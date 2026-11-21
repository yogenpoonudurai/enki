package sbom

import (
	"fmt"
	"strconv"
	"strings"
)

// compareVersions compares dotted versions (with optional v prefix,
// prerelease, and build metadata). Returns -1, 0, or 1.
func compareVersions(a, b string) int {
	ac, apre := splitVersion(a)
	bc, bpre := splitVersion(b)
	for i := 0; i < len(ac) || i < len(bc); i++ {
		var x, y int
		if i < len(ac) {
			x = ac[i]
		}
		if i < len(bc) {
			y = bc[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1 // release > prerelease
	case bpre == "":
		return -1
	case apre < bpre:
		return -1
	default:
		return 1
	}
}

func splitVersion(v string) ([]int, string) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.Index(v, "+"); i >= 0 {
		v = v[:i]
	}
	pre := ""
	if i := strings.Index(v, "-"); i >= 0 {
		pre = v[i+1:]
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			n = 0
		}
		nums = append(nums, n)
	}
	return nums, pre
}

// maxFixedVersion picks the highest version-like fixed entry (commit hashes
// are filtered out).
func maxFixedVersion(fixed []string) string {
	best := ""
	for _, f := range printableFixed(fixed) {
		if best == "" || compareVersions(f, best) > 0 {
			best = f
		}
	}
	return best
}

func packageVersionKey(p Pkg) string {
	return p.Ecosystem + "|" + strings.ToLower(p.Name) + "@" + p.Version
}

// upgradeCommand returns the package-manager command that upgrades pkg to at
// least fixed. It is guidance: enki never executes it.
func upgradeCommand(p Pkg, fixed string) (manager, command string, ok bool) {
	switch {
	case p.Ecosystem == "PyPI":
		return "pip", fmt.Sprintf(`python3 -m pip install --upgrade "%s>=%s"`, p.Name, fixed), true
	case p.Ecosystem == "npm":
		return "npm", fmt.Sprintf("npm install %s@%s", p.Name, fixed), true
	case p.Ecosystem == "Go":
		return "go", fmt.Sprintf("go get %s@%s", p.Name, fixed), true
	case p.Ecosystem == "crates.io":
		return "cargo", fmt.Sprintf("cargo update -p %s --precise %s", p.Name, fixed), true
	case p.Ecosystem == "NuGet":
		return "dotnet", fmt.Sprintf("dotnet add package %s --version %s", p.Name, fixed), true
	case strings.HasPrefix(p.Ecosystem, "Debian:"), strings.HasPrefix(p.Ecosystem, "Ubuntu:"):
		return "apt-get", fmt.Sprintf("sudo apt-get install --only-upgrade %s", p.Name), true
	case strings.HasPrefix(p.Ecosystem, "Alpine:"):
		return "apk", fmt.Sprintf("sudo apk upgrade %s", p.Name), true
	case strings.HasPrefix(p.Ecosystem, "Rocky Linux:"), strings.HasPrefix(p.Ecosystem, "AlmaLinux:"):
		return "dnf", fmt.Sprintf("sudo dnf upgrade %s", p.Name), true
	}
	return "", "", false
}
