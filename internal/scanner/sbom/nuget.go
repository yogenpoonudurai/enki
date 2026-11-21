package sbom

import (
	"encoding/json"
	"regexp"
	"strings"
)

var nugetVersion = regexp.MustCompile(`^\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.\-]+)?$`)

type nugetDep struct {
	Type     string `json:"type"`
	Resolved string `json:"resolved"`
}

// parseNuGetLock reads packages.lock.json across target frameworks.
func parseNuGetLock(data []byte) ([]Pkg, error) {
	var lock struct {
		Version      int                            `json:"version"`
		Dependencies map[string]map[string]nugetDep `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Pkg
	for _, tfm := range lock.Dependencies {
		for name, dep := range tfm {
			if dep.Type == "Project" || dep.Resolved == "" {
				continue
			}
			key := name + "@" + dep.Resolved
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Pkg{
				Name: name, Version: dep.Resolved, Ecosystem: "NuGet",
				Direct: dep.Type == "Direct",
			})
		}
	}
	return out, nil
}

// parseProjectAssets is the fallback when RestorePackagesWithLockFile is off.
func parseProjectAssets(data []byte) ([]Pkg, error) {
	var assets struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
	}
	if err := json.Unmarshal(data, &assets); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Pkg
	for key, lib := range assets.Libraries {
		if lib.Type == "project" {
			continue
		}
		i := strings.LastIndex(key, "/")
		if i <= 0 {
			continue
		}
		name, ver := key[:i], key[i+1:]
		if !nugetVersion.MatchString(ver) {
			continue
		}
		if seen[name+"@"+ver] {
			continue
		}
		seen[name+"@"+ver] = true
		out = append(out, Pkg{Name: name, Version: ver, Ecosystem: "NuGet"})
	}
	return out, nil
}
