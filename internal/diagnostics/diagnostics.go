// Package diagnostics collects local system facts that shape what remediation
// advice is valid on this machine (OS, service manager, available firewall and
// package tools, privileges, container limitations). It never runs privileged
// commands or reads user content.
package diagnostics

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/platform"
)

// Report is the capability/limitation context for this machine.
type Report struct {
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	Distro          string   `json:"distro,omitempty"`
	DistroVersion   string   `json:"distro_version,omitempty"`
	Kernel          string   `json:"kernel,omitempty"`
	Elevated        bool     `json:"elevated"`
	Container       bool     `json:"container,omitempty"`
	Shell           string   `json:"shell,omitempty"`
	ServiceManager  string   `json:"service_manager,omitempty"`
	Firewalls       []string `json:"firewall_tools,omitempty"`
	PackageManagers []string `json:"package_managers,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	Limitations     []string `json:"limitations,omitempty"`
}

// Collect gathers local diagnostics. Cheap, local, and side-effect free.
func Collect() Report {
	r := Report{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Elevated: platform.Elevated(),
		Shell:    shell(),
	}
	r.Distro, r.DistroVersion = distro()
	r.Kernel = kernel()
	r.Container = inContainer()
	r.ServiceManager = serviceManager()
	r.Firewalls = lookPaths([]string{"ufw", "nft", "iptables", "pfctl", "firewall-cmd", "netsh"})
	r.PackageManagers = lookPaths([]string{
		"apt-get", "dpkg-query", "dnf", "yum", "apk", "pacman", "brew", "winget", "choco",
	})

	r.Capabilities = []string{
		"local file remediation with backups and byte-identical undo (permissions, comment-preserving JSONC edits)",
		"deterministic scans (offline except OSV advisory lookups)",
	}
	if r.ServiceManager != "" && r.ServiceManager != "unknown" {
		r.Capabilities = append(r.Capabilities,
			"service manager "+r.ServiceManager+" (bind changes take effect after restarting the service)")
	}
	if len(r.Firewalls) > 0 {
		r.Capabilities = append(r.Capabilities,
			"firewall CLI available: "+strings.Join(r.Firewalls, ", "))
	}
	if len(r.PackageManagers) > 0 {
		r.Capabilities = append(r.Capabilities,
			"package manager available: "+strings.Join(r.PackageManagers, ", "))
	}

	if !r.Elevated {
		r.Limitations = append(r.Limitations,
			"not running elevated: firewall, service, and other system changes require sudo/administrator")
	}
	if r.Container {
		r.Limitations = append(r.Limitations,
			"running in a container network namespace: host or other-container listeners are not visible")
	}
	if len(r.Firewalls) == 0 {
		r.Limitations = append(r.Limitations,
			"no supported firewall CLI detected: prefer rebinding services to loopback")
	}
	if len(r.PackageManagers) == 0 {
		r.Limitations = append(r.Limitations,
			"no supported package manager detected: OS package vulnerabilities may be unknown")
	}
	r.Limitations = append(r.Limitations,
		"probing is loopback-only unless --probe-remote is explicitly authorized",
		"AI may only rank and explain; execution requires the deterministic fix engine or the operator",
	)
	return r
}

func shell() string {
	if sh := os.Getenv("SHELL"); sh != "" {
		return filepath.Base(sh)
	}
	if comspec := os.Getenv("COMSPEC"); comspec != "" {
		return filepath.Base(comspec)
	}
	return ""
}

func distro() (string, string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	values := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) == 2 {
			values[kv[0]] = strings.Trim(kv[1], `"'`)
		}
	}
	return values["ID"], values["VERSION_ID"]
}

func kernel() string {
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "kubepods") || strings.Contains(s, "containerd") {
			return true
		}
	}
	return false
}

func serviceManager() string {
	switch runtime.GOOS {
	case "darwin":
		return "launchd"
	case "windows":
		return "windows-service"
	case "linux":
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			return "systemd"
		}
		if _, err := exec.LookPath("rc-service"); err == nil {
			return "openrc"
		}
	}
	return "unknown"
}

func lookPaths(names []string) []string {
	var found []string
	for _, name := range names {
		if _, err := exec.LookPath(name); err == nil {
			found = append(found, name)
		}
	}
	return found
}
