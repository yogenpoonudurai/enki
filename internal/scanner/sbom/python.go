package sbom

import (
	"bufio"
	"encoding/json"
	"regexp"
	"strings"
)

var reqLine = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][A-Za-z0-9_.+\-]*)`)
var pyprojectDep = regexp.MustCompile(`(?m)^\s*"([A-Za-z0-9][A-Za-z0-9_.\-]*)(?:\[[^\]]*\])?\s*==\s*([0-9][^"\s,]+)"`)
var poetryDep = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*=\s*"[\^~>=<]*\s*([0-9][^"]*)"`)

func parseRequirements(data []byte) []Pkg {
	var out []Pkg
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, ";"); i >= 0 {
			line = line[:i]
		}
		m := reqLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := strings.ToLower(m[1]) + "@" + m[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Pkg{Name: m[1], Version: m[2], Ecosystem: "PyPI", Direct: true})
	}
	return out
}

func parsePyproject(data []byte) []Pkg {
	var out []Pkg
	content := string(data)
	for _, m := range pyprojectDep.FindAllStringSubmatch(content, -1) {
		out = append(out, Pkg{Name: m[1], Version: m[2], Ecosystem: "PyPI", Direct: true})
	}
	// Poetry dependency tables pin with plain versions (^, ~ and ranges are
	// skipped because they are not exact).
	if idx := strings.Index(content, "[tool.poetry.dependencies]"); idx >= 0 {
		section := content[idx:]
		if end := strings.Index(section, "\n["); end >= 0 {
			section = section[:end]
		}
		for _, m := range poetryDep.FindAllStringSubmatch(section, -1) {
			name := m[1]
			if strings.EqualFold(name, "python") {
				continue
			}
			ver := strings.TrimSpace(m[2])
			if !isExactVersion(ver) {
				continue
			}
			out = append(out, Pkg{Name: name, Version: ver, Ecosystem: "PyPI", Direct: true})
		}
	}
	return out
}

func isExactVersion(v string) bool {
	if v == "" || strings.ContainsAny(v, "^~*<>=! ") {
		return false
	}
	return v[0] >= '0' && v[0] <= '9'
}

// parseTOMLPackages handles poetry.lock, pdm.lock, and uv.lock block formats.
// When registryOnly is set (uv.lock), editable/git/path/url sources are
// skipped and counted.
func parseTOMLPackages(data []byte, registryOnly bool) ([]Pkg, int) {
	var out []Pkg
	skipped := 0
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)

	inBlock := false
	var name, version, source string
	flush := func() {
		if !inBlock {
			name, version, source = "", "", ""
			return
		}
		registry := strings.Contains(source, "registry")
		switch {
		case name == "" || version == "":
			if name != "" {
				skipped++
			}
		case registryOnly && (!registry || strings.Contains(source, "editable") ||
			strings.Contains(source, "git") || strings.Contains(source, "path") || strings.Contains(source, "url")):
			skipped++
		default:
			out = append(out, Pkg{Name: name, Version: version, Ecosystem: "PyPI"})
		}
		name, version, source = "", "", ""
	}

	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		switch {
		case t == "[[package]]":
			flush()
			inBlock = true
		case strings.HasPrefix(t, "name = "):
			if inBlock {
				name = unquoteTOML(strings.TrimPrefix(t, "name = "))
			}
		case strings.HasPrefix(t, "version = "):
			if inBlock {
				version = unquoteTOML(strings.TrimPrefix(t, "version = "))
			}
		case strings.HasPrefix(t, "source = "):
			if inBlock {
				source = t
			}
		}
	}
	flush()
	return out, skipped
}

func unquoteTOML(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`)
}

type pipfileDep struct {
	Version string `json:"version"`
}

func parsePipfileLock(data []byte) ([]Pkg, error) {
	var lock struct {
		Default map[string]pipfileDep `json:"default"`
		Develop map[string]pipfileDep `json:"develop"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []Pkg
	add := func(deps map[string]pipfileDep, dev bool) {
		for name, dep := range deps {
			v := strings.TrimPrefix(strings.TrimSpace(dep.Version), "==")
			if !semverish.MatchString(strings.TrimPrefix(v, "v")) {
				continue
			}
			out = append(out, Pkg{Name: name, Version: strings.TrimPrefix(v, "v"), Ecosystem: "PyPI", Dev: dev})
		}
	}
	add(lock.Default, false)
	add(lock.Develop, true)
	return out, nil
}
