package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yogenpoonudurai/enki/internal/scanner"
)

var semverish = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$`)

const maxNodeModulesPackages = 5000

type npmLockPkg struct {
	Version     string `json:"version"`
	Name        string `json:"name"`
	Dev         bool   `json:"dev"`
	Optional    bool   `json:"optional"`
	DevOptional bool   `json:"devOptional"`
	Link        bool   `json:"link"`
	InBundle    bool   `json:"inBundle"`
}

type npmLockDep struct {
	Version      string                `json:"version"`
	Dev          bool                  `json:"dev"`
	Optional     bool                  `json:"optional"`
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

// parseNpmLock handles package-lock.json v1 (recursive dependencies) and
// v2/v3 (packages map). Alias entries expose the real package in `name`.
func parseNpmLock(data []byte) ([]Pkg, int, error) {
	var lock struct {
		LockfileVersion int                   `json:"lockfileVersion"`
		Packages        map[string]npmLockPkg `json:"packages"`
		Dependencies    map[string]npmLockDep `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, 0, err
	}

	var out []Pkg
	skipped := 0
	add := func(name, version string, dev, optional, direct bool) {
		v := strings.TrimPrefix(strings.TrimSpace(version), "v")
		if name == "" || !semverish.MatchString(v) {
			skipped++
			return
		}
		out = append(out, Pkg{
			Name: name, Version: v, Ecosystem: "npm",
			Dev: dev, Optional: optional, Direct: direct,
		})
	}

	for key, entry := range lock.Packages {
		if key == "" || entry.Link || entry.InBundle {
			continue
		}
		name := entry.Name
		if name == "" {
			name = nameFromNodeModulesKey(key)
		}
		direct := strings.Count(key, "node_modules/") == 1
		add(name, entry.Version, entry.Dev || entry.DevOptional, entry.Optional || entry.DevOptional, direct)
	}
	if len(lock.Packages) == 0 {
		var walk func(deps map[string]npmLockDep, top bool)
		walk = func(deps map[string]npmLockDep, top bool) {
			for name, dep := range deps {
				add(name, dep.Version, dep.Dev, dep.Optional, top)
				if len(dep.Dependencies) > 0 {
					walk(dep.Dependencies, false)
				}
			}
		}
		walk(lock.Dependencies, true)
	}
	return out, skipped, nil
}

func nameFromNodeModulesKey(key string) string {
	if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
		return key[i+len("node_modules/"):]
	}
	return key
}

type npmManifest struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func parsePackageJSON(data []byte) []Pkg {
	var m npmManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	var out []Pkg
	add := func(deps map[string]string, dev bool) {
		for name, ver := range deps {
			v := strings.TrimPrefix(strings.TrimSpace(ver), "v")
			if !semverish.MatchString(v) {
				continue
			}
			out = append(out, Pkg{Name: name, Version: v, Ecosystem: "npm", Direct: true, Dev: dev})
		}
	}
	add(m.Dependencies, false)
	add(m.DevDependencies, true)
	return out
}

// parseYarnLock dispatches between classic (v1) and Berry lockfiles.
func parseYarnLock(data []byte) ([]Pkg, int, error) {
	if bytes.Contains(data, []byte("__metadata:")) {
		return parseYarnBerry(data)
	}
	return parseYarnV1(data)
}

// parseYarnV1 parses the classic flat text format. v1 has no dev markers.
func parseYarnV1(data []byte) ([]Pkg, int, error) {
	lines := strings.Split(string(data), "\n")
	var out []Pkg
	skipped := 0

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		header := strings.TrimSpace(line)
		if !strings.HasSuffix(header, ":") {
			continue
		}
		name := descriptorName(firstDescriptor(strings.TrimSuffix(header, ":")))
		version := ""
		j := i + 1
		for ; j < len(lines); j++ {
			next := lines[j]
			if next != "" && !strings.HasPrefix(next, " ") && !strings.HasPrefix(next, "\t") {
				break
			}
			t := strings.TrimSpace(next)
			switch {
			case strings.HasPrefix(t, "version "):
				version = strings.Trim(strings.TrimPrefix(t, "version "), `"`)
			case strings.HasPrefix(t, "version:"):
				version = strings.Trim(strings.TrimPrefix(t, "version:"), `" `)
			}
		}
		i = j - 1

		v := strings.TrimPrefix(version, "v")
		if name == "" || !semverish.MatchString(v) {
			skipped++
			continue
		}
		out = append(out, Pkg{Name: name, Version: v, Ecosystem: "npm"})
	}
	return out, skipped, nil
}

func firstDescriptor(header string) string {
	var cur strings.Builder
	inQuote := false
	for _, r := range header {
		switch r {
		case '"':
			inQuote = !inQuote
		case ',':
			if inQuote {
				cur.WriteRune(r)
				continue
			}
			return strings.TrimSpace(cur.String())
		default:
			cur.WriteRune(r)
		}
	}
	return strings.TrimSpace(cur.String())
}

// descriptorName resolves yarn/npm descriptors, including aliases
// (foo@npm:bar@^1.0.0) and scoped names.
func descriptorName(d string) string {
	d = strings.TrimSpace(strings.Trim(d, `"`))
	if d == "" {
		return ""
	}
	if i := strings.Index(d, "@npm:"); i > 0 {
		return descriptorName(d[i+len("@npm:"):])
	}
	for _, prefix := range []string{"file:", "link:", "git:", "git+", "http:", "https:", "workspace:"} {
		if strings.HasPrefix(d, prefix) {
			return ""
		}
	}
	start := 0
	if strings.HasPrefix(d, "@") {
		start = 1
	}
	if i := strings.LastIndex(d[start:], "@"); i >= 0 {
		return d[:start+i]
	}
	return d
}

// parseYarnBerry parses the YAML-based Berry lockfile (v2+).
func parseYarnBerry(data []byte) ([]Pkg, int, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, 0, err
	}
	var out []Pkg
	skipped := 0
	for key, raw := range doc {
		if key == "__metadata" {
			continue
		}
		entry, ok := raw.(map[string]any)
		if !ok {
			skipped++
			continue
		}
		if lt, _ := entry["linkType"].(string); lt == "soft" {
			continue
		}
		res, _ := entry["resolution"].(string)
		name, ver, ok := parseBerryResolution(res)
		if !ok {
			name = descriptorName(strings.Trim(key, `"`))
			if v, vok := entry["version"].(string); vok {
				v = strings.TrimPrefix(v, "v")
				ok = name != "" && semverish.MatchString(v)
				ver = v
			}
		}
		if !ok || name == "" {
			skipped++
			continue
		}
		out = append(out, Pkg{Name: name, Version: ver, Ecosystem: "npm"})
	}
	return out, skipped, nil
}

func parseBerryResolution(res string) (string, string, bool) {
	res = strings.Trim(res, `"`)
	if res == "" || strings.Contains(res, "@workspace:") || strings.Contains(res, "@patch:") {
		return "", "", false
	}
	if i := strings.Index(res, "#npm:"); i > 0 { // virtual: name@virtual:<hash>#npm:<ver>
		ver := strings.TrimPrefix(res[i+len("#npm:"):], "v")
		name := res[:i]
		if j := strings.Index(name, "@virtual:"); j > 0 {
			name = name[:j]
		}
		if semverish.MatchString(ver) {
			return name, ver, true
		}
		return "", "", false
	}
	if i := strings.Index(res, "@npm:"); i > 0 {
		ver := strings.TrimPrefix(res[i+len("@npm:"):], "v")
		if semverish.MatchString(ver) {
			return res[:i], ver, true
		}
	}
	return "", "", false
}

// parsePnpmLock parses pnpm lockfiles across v5/v6/v9 key grammars and unions
// all YAML documents (pnpm >= 12 emits a boot document plus the project one).
func parsePnpmLock(data []byte) ([]Pkg, int, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	seen := map[string]bool{}
	var out []Pkg
	skipped := 0

	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		for _, section := range []string{"packages", "snapshots"} {
			entries, ok := doc[section].(map[string]any)
			if !ok {
				continue
			}
			for key, raw := range entries {
				name, ver, ok := parsePnpmKey(key)
				if !ok {
					skipped++
					continue
				}
				k := name + "@" + ver
				if seen[k] {
					continue
				}
				seen[k] = true
				dev, optional := false, false
				if entry, ok := raw.(map[string]any); ok {
					dev, _ = entry["dev"].(bool)
					optional, _ = entry["optional"].(bool)
				}
				out = append(out, Pkg{Name: name, Version: ver, Ecosystem: "npm", Dev: dev, Optional: optional})
			}
		}
	}
	return out, skipped, nil
}

func parsePnpmKey(key string) (string, string, bool) {
	k := strings.TrimPrefix(key, "/")
	if i := strings.Index(k, "("); i > 0 {
		k = k[:i]
	}
	if k == "" {
		return "", "", false
	}
	// v6/v9: name@version (name may be scoped, starting with @)
	for i := len(k) - 1; i > 0; i-- {
		if k[i] == '@' {
			name, ver := k[:i], strings.TrimPrefix(k[i+1:], "v")
			if semverish.MatchString(ver) {
				return name, ver, true
			}
			break
		}
	}
	// v5: /name/version
	if i := strings.LastIndex(k, "/"); i > 0 {
		name, ver := k[:i], strings.TrimPrefix(k[i+1:], "v")
		if semverish.MatchString(ver) {
			return name, ver, true
		}
	}
	return "", "", false
}

func parseNodeModules(root string) []Pkg {
	nm := filepath.Join(root, "node_modules")
	entries, err := os.ReadDir(nm)
	if err != nil {
		return nil
	}
	var out []Pkg
	addDir := func(dir string) {
		if len(out) >= maxNodeModulesPackages {
			return
		}
		data, err := os.ReadFile(filepath.Join(dir, "package.json"))
		if err != nil {
			return
		}
		var m struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(data, &m) != nil {
			return
		}
		v := strings.TrimPrefix(m.Version, "v")
		if m.Name == "" || !semverish.MatchString(v) {
			return
		}
		out = append(out, Pkg{Name: m.Name, Version: v, Ecosystem: "npm"})
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == ".bin" {
			continue
		}
		if strings.HasPrefix(e.Name(), "@") {
			subs, err := os.ReadDir(filepath.Join(nm, e.Name()))
			if err != nil {
				continue
			}
			for _, s := range subs {
				if s.IsDir() {
					addDir(filepath.Join(nm, e.Name(), s.Name()))
				}
			}
			continue
		}
		addDir(filepath.Join(nm, e.Name()))
	}
	return out
}

func globalNpm(ctx context.Context) ([]Pkg, []scanner.CoverageGap) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "npm", "ls", "-g", "--json", "--depth=0")
	out, err := cmd.Output()
	if err != nil {
		return nil, []scanner.CoverageGap{{
			Module: moduleName,
			Reason: "npm global inventory failed (npm missing or not configured): " + err.Error(),
		}}
	}
	var doc struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, []scanner.CoverageGap{{Module: moduleName, Reason: "cannot parse npm global inventory"}}
	}
	var pkgs []Pkg
	for name, dep := range doc.Dependencies {
		v := strings.TrimPrefix(dep.Version, "v")
		if !semverish.MatchString(v) {
			continue
		}
		pkgs = append(pkgs, Pkg{Name: name, Version: v, Ecosystem: "npm", Direct: true})
	}
	return pkgs, nil
}
