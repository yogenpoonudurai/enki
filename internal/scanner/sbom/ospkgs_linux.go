//go:build linux

package sbom

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/yogenpoonudurai/enki/internal/scanner"
)

const maxOSPackages = 10000

// inventoryOSPackages enumerates the distro package database and maps it to
// an OSV ecosystem when supported. Unsupported distros return the inventory
// with an explicit coverage gap (never silently "clean").
func inventoryOSPackages(ctx context.Context) ([]Pkg, []scanner.CoverageGap) {
	release, _ := os.ReadFile("/etc/os-release")
	rel := parseOSRelease(release)
	eco, supported := osvEcosystem(rel["ID"], rel["VERSION_ID"])

	var gaps []scanner.CoverageGap
	var pkgs []Pkg

	switch {
	case exists("dpkg-query"):
		out, err := runInventoryCmd(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\n")
		if err != nil {
			gaps = append(gaps, osGap("dpkg inventory failed: "+err.Error()))
		} else {
			pkgs = parseDpkgOutput(out)
		}
	case exists("rpm"):
		out, err := runInventoryCmd(ctx, "rpm", "-qa", "--qf", "%{NAME} %{EVR}\n")
		if err != nil {
			gaps = append(gaps, osGap("rpm inventory failed: "+err.Error()))
		} else {
			pkgs = parseRpmOutput(out)
		}
	case fileExists("/lib/apk/db/installed"):
		data, err := os.ReadFile("/lib/apk/db/installed")
		if err != nil {
			gaps = append(gaps, osGap("apk database unreadable: "+err.Error()))
		} else {
			pkgs = parseApkInstalled(data)
		}
	default:
		gaps = append(gaps, osGap("no supported OS package manager (dpkg/rpm/apk) found; OS package coverage skipped"))
		return nil, gaps
	}

	if len(pkgs) == 0 {
		return nil, gaps
	}
	if !supported {
		for i := range pkgs {
			pkgs[i].Ecosystem = "OS"
		}
		gaps = append(gaps, osGap(fmt.Sprintf(
			"OSV has no vulnerability data for %q %q; %d OS packages are inventory-only",
			rel["ID"], rel["VERSION_ID"], len(pkgs))))
		return pkgs, gaps
	}
	for i := range pkgs {
		pkgs[i].Ecosystem = eco
	}
	if len(pkgs) > maxOSPackages {
		gaps = append(gaps, osGap(fmt.Sprintf("OS package inventory truncated at %d entries", maxOSPackages)))
		pkgs = pkgs[:maxOSPackages]
	}
	return pkgs, gaps
}

func osGap(reason string) scanner.CoverageGap {
	return scanner.CoverageGap{Module: moduleName, Reason: reason}
}

func runInventoryCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

func exists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func parseOSRelease(data []byte) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		m[kv[0]] = strings.Trim(kv[1], `"'`)
	}
	return m
}

// osvEcosystem maps a distro to an OSV ecosystem identifier, verified against
// ecosystems.txt. RHEL uses stream-scoped identifiers and is deferred.
func osvEcosystem(id, version string) (string, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	v := strings.TrimSpace(version)
	switch id {
	case "debian":
		major := leadingNumber(v)
		if major == "" {
			return "", false
		}
		return "Debian:" + major, true
	case "ubuntu":
		if v == "" {
			return "", false
		}
		switch v {
		case "18.04", "20.04", "22.04", "24.04", "26.04":
			return "Ubuntu:" + v + ":LTS", true
		}
		return "Ubuntu:" + v, true
	case "alpine":
		mm := majorMinor(v)
		if mm == "" {
			return "", false
		}
		return "Alpine:v" + mm, true
	case "rocky":
		major := leadingNumber(v)
		if major == "" {
			return "", false
		}
		return "Rocky Linux:" + major, true
	case "almalinux":
		major := leadingNumber(v)
		if major == "" {
			return "", false
		}
		return "AlmaLinux:" + major, true
	}
	return "", false
}

func leadingNumber(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
			continue
		}
		break
	}
	return b.String()
}

func majorMinor(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

// parseDpkgOutput parses `dpkg-query -W` output with source package fields.
// OSV Debian/Ubuntu advisories are source-package based and expect the epoch
// included in the version verbatim.
func parseDpkgOutput(data []byte) []Pkg {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	seen := map[string]bool{}
	var out []Pkg
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 2 {
			continue
		}
		name, ver := fields[0], fields[1]
		if len(fields) >= 4 {
			if fields[2] != "" {
				name = fields[2]
			}
			if fields[3] != "" {
				ver = fields[3]
			}
		}
		if name == "" || ver == "" {
			continue
		}
		key := name + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Pkg{Name: name, Version: ver})
	}
	return out
}

func parseRpmOutput(data []byte) []Pkg {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	seen := map[string]bool{}
	var out []Pkg
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "gpg-pubkey") {
			continue
		}
		key := fields[0] + "@" + fields[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Pkg{Name: fields[0], Version: fields[1]})
	}
	return out
}

// parseApkInstalled reads /lib/apk/db/installed directly, which is stable
// across apk-tools CLI output changes. OSV Alpine packages are origin-based.
func parseApkInstalled(data []byte) []Pkg {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	seen := map[string]bool{}
	var out []Pkg
	var pname, pver, origin string
	flush := func() {
		name := origin
		if name == "" {
			name = pname
		}
		if name != "" && pver != "" {
			key := name + "@" + pver
			if !seen[key] {
				seen[key] = true
				out = append(out, Pkg{Name: name, Version: pver})
			}
		}
		pname, pver, origin = "", "", ""
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "P:"):
			pname = strings.TrimPrefix(line, "P:")
		case strings.HasPrefix(line, "V:"):
			pver = strings.TrimPrefix(line, "V:")
		case strings.HasPrefix(line, "o:"):
			origin = strings.TrimPrefix(line, "o:")
		case line == "":
			flush()
		}
	}
	flush()
	return out
}
