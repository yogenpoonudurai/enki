package sbom

import (
	"bufio"
	"strings"
)

type goRequire struct {
	name     string
	version  string
	indirect bool
}

// parseGoMod parses require/replace/exclude directives. Direct is derived
// from the absence of a "// indirect" marker; go.sum is never used to guess
// selected versions.
func parseGoMod(data []byte) ([]Pkg, int) {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var reqs []goRequire
	excluded := map[string]bool{}
	replaces := map[string]Pkg{}
	skipped := 0

	mode := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		switch {
		case line == "require (":
			mode = "require"
			continue
		case line == "replace (":
			mode = "replace"
			continue
		case line == "exclude (":
			mode = "exclude"
			continue
		case line == ")":
			mode = ""
			continue
		case strings.HasPrefix(line, "require "):
			addGoRequire(strings.TrimPrefix(line, "require "), &reqs)
			continue
		case strings.HasPrefix(line, "replace "):
			addGoReplace(strings.TrimPrefix(line, "replace "), replaces, &skipped)
			continue
		case strings.HasPrefix(line, "exclude "):
			addGoExclude(strings.TrimPrefix(line, "exclude "), excluded)
			continue
		}
		line = strings.TrimSuffix(line, ")")
		switch mode {
		case "require":
			addGoRequire(line, &reqs)
		case "replace":
			addGoReplace(line, replaces, &skipped)
		case "exclude":
			addGoExclude(line, excluded)
		}
	}

	var out []Pkg
	for _, r := range reqs {
		if excluded[r.name+"@"+r.version] {
			continue
		}
		name, ver := r.name, r.version
		if rep, ok := replaces[name+"@"+ver]; ok {
			name, ver = rep.Name, rep.Version
		} else if rep, ok := replaces[name]; ok {
			name, ver = rep.Name, rep.Version
		}
		if name == "" || ver == "" {
			skipped++
			continue
		}
		out = append(out, Pkg{Name: name, Version: ver, Ecosystem: "Go", Direct: !r.indirect})
	}
	return out, skipped
}

func addGoRequire(line string, reqs *[]goRequire) {
	indirect := strings.Contains(line, "// indirect")
	if i := strings.Index(line, "//"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	*reqs = append(*reqs, goRequire{name: fields[0], version: fields[1], indirect: indirect})
}

func addGoExclude(line string, excluded map[string]bool) {
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		excluded[fields[0]+"@"+fields[1]] = true
	}
}

func addGoReplace(line string, replaces map[string]Pkg, skipped *int) {
	parts := strings.SplitN(line, "=>", 2)
	if len(parts) != 2 {
		return
	}
	oldFields := strings.Fields(parts[0])
	newFields := strings.Fields(parts[1])
	if len(oldFields) == 0 || len(newFields) == 0 {
		return
	}
	if len(newFields) < 2 {
		*skipped = *skipped + 1 // local path replacement: no registry version to query
		return
	}
	rep := Pkg{Name: newFields[0], Version: newFields[1]}
	if len(oldFields) >= 2 {
		replaces[oldFields[0]+"@"+oldFields[1]] = rep
	} else {
		replaces[oldFields[0]] = rep
	}
}
