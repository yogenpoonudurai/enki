// Package mcp audits Model Context Protocol server configuration for supply
// chain and exposure risks (unpinned packages, plaintext remotes, inline
// secrets, broad filesystem access).
package mcp

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/collector"
	"github.com/yogenpoonudurai/enki/internal/configutil"
	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/scanner"
	"github.com/yogenpoonudurai/enki/internal/secretlib"
)

const moduleName = "mcp"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }

func (m *Module) Description() string {
	return "Audits MCP server configs (Claude, Cursor, VS Code, Windsurf, Zed)"
}

type serverDef struct {
	Name    string
	Command string
	Args    []string
	Env     map[string]string
	URL     string
	Headers map[string]string
}

func (m *Module) Run(sc *scanner.Context) ([]finding.Finding, []scanner.CoverageGap, error) {
	var out []finding.Finding
	var gaps []scanner.CoverageGap

	for _, cf := range sc.Configs {
		defs, err := serversFrom(cf)
		if err != nil {
			if looksLikeMCP(cf.Data) {
				gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Reason: fmt.Sprintf("cannot parse %s: %v", cf.Path, err)})
			}
			continue
		}
		if len(defs) == 0 {
			continue
		}
		sort.SliceStable(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })

		for _, srv := range defs {
			out = append(out, checkServer(sc, cf, srv)...)
		}
		if cf.Mode.Perm()&0o004 != 0 {
			f := finding.New("MCP-006", moduleName,
				"MCP config is world-readable",
				"The configuration exposes MCP server commands, arguments, and possibly environment secrets to every local user.",
				finding.SeverityMedium, finding.ConfidenceHigh,
				finding.Location{Path: cf.Path})
			f.Evidence = fmt.Sprintf("file mode %04o", cf.Mode.Perm())
			f.Remediation = chmodRemediation(cf.Path, "Restrict the config file to the owning user")
			f.Tags = []string{"mcp", "permissions"}
			out = append(out, f)
		}
	}

	finding.Sort(out)
	return out, gaps, nil
}

func looksLikeMCP(data []byte) bool {
	s := string(data)
	return strings.Contains(s, "mcpServers") || strings.Contains(s, "context_servers") || strings.Contains(s, `"servers"`)
}

func serversFrom(cf collector.ConfigFile) ([]serverDef, error) {
	root, err := configutil.ToMap(cf.Data)
	if err != nil {
		return nil, err
	}
	var defs []serverDef
	for _, key := range []string{"mcpServers", "servers", "context_servers"} {
		servers, ok := root[key].(map[string]any)
		if !ok {
			continue
		}
		for name, raw := range servers {
			rm, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			defs = append(defs, extractServer(name, rm))
		}
	}
	return defs, nil
}

func extractServer(name string, rm map[string]any) serverDef {
	d := serverDef{Name: name}
	switch c := rm["command"].(type) {
	case string:
		d.Command = c
	case map[string]any:
		// Zed-style nested command object.
		if p, ok := c["path"].(string); ok {
			d.Command = p
		}
		if args, ok := c["args"]; ok {
			d.Args = configutil.Strings(args)
		}
		if env, ok := c["env"]; ok {
			d.Env = configutil.StringMap(env)
		}
	}
	if args, ok := rm["args"]; ok {
		d.Args = append(d.Args, configutil.Strings(args)...)
	}
	if env, ok := rm["env"]; ok && d.Env == nil {
		d.Env = configutil.StringMap(env)
	}
	if u, ok := rm["url"].(string); ok {
		d.URL = u
	}
	if u, ok := rm["serverUrl"].(string); ok && d.URL == "" {
		d.URL = u
	}
	if h, ok := rm["headers"]; ok {
		d.Headers = configutil.StringMap(h)
	}
	return d
}

func checkServer(sc *scanner.Context, cf collector.ConfigFile, srv serverDef) []finding.Finding {
	var out []finding.Finding
	loc := finding.Location{Path: cf.Path}

	if pkg, unpinned := unpinnedPackage(srv.Command, srv.Args); unpinned {
		f := finding.New("MCP-001", moduleName,
			fmt.Sprintf("Unpinned MCP server package %q", pkg),
			"The server is launched with a floating package specifier, so every start may execute a different (possibly compromised) release. Supply-chain attacks on MCP servers are a known vector.",
			finding.SeverityHigh, finding.ConfidenceHigh, loc)
		f.Evidence = fmt.Sprintf("server %q: %s %s", srv.Name, filepath.Base(srv.Command), strings.Join(srv.Args, " "))
		f.Remediation = &finding.Remediation{
			Class:    finding.ActionModerate,
			Summary:  fmt.Sprintf("Pin %q to an exact version", pkg),
			Guidance: "Add an explicit version (for example package@1.2.3 or package==1.2.3) and review upgrades deliberately.",
		}
		f.Tags = []string{"mcp", "supply-chain"}
		out = append(out, f)
	}

	if srv.URL != "" {
		if u, err := url.Parse(srv.URL); err == nil && strings.EqualFold(u.Scheme, "http") && !isLoopbackHost(u.Hostname()) {
			f := finding.New("MCP-002", moduleName,
				"Remote MCP server uses plaintext HTTP",
				"Messages between the agent and the remote MCP server are unencrypted and can be modified in transit.",
				finding.SeverityMedium, finding.ConfidenceHigh, loc)
			f.Evidence = fmt.Sprintf("server %q: %s", srv.Name, srv.URL)
			f.Remediation = &finding.Remediation{
				Class:    finding.ActionModerate,
				Summary:  "Use HTTPS for the remote MCP endpoint",
				Guidance: "Point the server URL at https:// or route it through a TLS-terminating gateway.",
			}
			f.Tags = []string{"mcp", "transport"}
			out = append(out, f)
		}
	}

	for name, val := range srv.Env {
		hit := secretlib.ScanValue(val)
		if hit == nil && secretlib.IsSecretEnvName(name) && len(strings.TrimSpace(val)) >= 16 {
			hit = &secretlib.Match{ID: "inline", Name: "Inline credential", Value: strings.TrimSpace(val)}
		}
		if hit == nil {
			continue
		}
		f := finding.New("MCP-003", moduleName,
			fmt.Sprintf("MCP server %q embeds a credential", srv.Name),
			"Secrets pasted into MCP configuration are readable by every process of the user and often leak into backups, dotfile repos, and screenshots.",
			finding.SeverityHigh, finding.ConfidenceHigh, loc)
		f.Evidence = fmt.Sprintf("env %s = %s (fingerprint %s)", name, finding.RedactSecret(hit.Value), finding.SecretFingerprint(hit.Value))
		f.Remediation = &finding.Remediation{
			Class:    finding.ActionModerate,
			Summary:  fmt.Sprintf("Move %s out of the MCP config and rotate it", name),
			Guidance: "Reference a secret manager or a shell-injected environment variable instead, then rotate the exposed credential.",
		}
		f.Tags = []string{"mcp", "secret"}
		out = append(out, f)
	}
	for name, val := range srv.Headers {
		if hit := secretlib.ScanValue(val); hit != nil {
			f := finding.New("MCP-003", moduleName,
				fmt.Sprintf("MCP server %q embeds a credential in headers", srv.Name),
				"Authorization headers stored in MCP configuration expose credentials to other local processes and backups.",
				finding.SeverityHigh, finding.ConfidenceHigh, loc)
			f.Evidence = fmt.Sprintf("header %s: %s (fingerprint %s)", name, finding.RedactSecret(hit.Value), finding.SecretFingerprint(hit.Value))
			f.Remediation = &finding.Remediation{
				Class:    finding.ActionModerate,
				Summary:  fmt.Sprintf("Move the %s header value out of the config and rotate it", name),
				Guidance: "Keep credentials in the OS keychain or a secret manager and inject them at runtime.",
			}
			f.Tags = []string{"mcp", "secret"}
			out = append(out, f)
		}
	}

	for _, arg := range srv.Args {
		if broadRoot(arg, sc.HomeDir) {
			f := finding.New("MCP-004", moduleName,
				fmt.Sprintf("MCP server %q has broad filesystem access", srv.Name),
				"The server is granted a filesystem root (or the home directory). A compromised or prompt-injected server can read or modify nearly everything the user can.",
				finding.SeverityMedium, finding.ConfidenceMedium, loc)
			f.Evidence = fmt.Sprintf("server %q argument: %s", srv.Name, arg)
			f.Remediation = &finding.Remediation{
				Class:    finding.ActionModerate,
				Summary:  "Scope the MCP server to a dedicated project directory",
				Guidance: "Replace the root/home argument with the smallest directory the server actually needs.",
			}
			f.Tags = []string{"mcp", "least-privilege"}
			out = append(out, f)
			break
		}
	}

	if isExecLike(srv.Name) {
		f := finding.New("MCP-005", moduleName,
			fmt.Sprintf("MCP server %q exposes command execution", srv.Name),
			"An agent tool that runs shell commands turns prompt injection into code execution on the host.",
			finding.SeverityInfo, finding.ConfidenceMedium, loc)
		f.Evidence = fmt.Sprintf("server name %q suggests shell/exec functionality", srv.Name)
		f.Remediation = &finding.Remediation{
			Class:    finding.ActionModerate,
			Summary:  "Review the server's command execution scope",
			Guidance: "Prefer narrower tools. If shell access is required, restrict the working directory and require approval for each call.",
		}
		f.Tags = []string{"mcp", "rce"}
		out = append(out, f)
	}

	return out
}

// unpinnedPackage inspects npx/uvx style launchers and returns the package
// specifier when it floats without an exact version.
func unpinnedPackage(command string, args []string) (string, bool) {
	base := strings.ToLower(filepath.Base(command))
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".cmd")

	switch base {
	case "npx", "pnpx", "bunx":
		pkg := npxPackage(args)
		if pkg == "" || hasPinnedVersion(pkg) {
			return "", false
		}
		return pkg, true
	case "uvx":
		return uvxPinCheck(args)
	}
	return "", false
}

// npxValueFlags consume the following argument as their value. Without this,
// a registry URL or cache path is mistaken for the package to execute.
var npxValueFlags = map[string]bool{
	"-p": true, "--package": true,
	"-c": true, "--call": true,
	"-w": true, "--workspace": true,
	"--registry":     true,
	"--cache":        true,
	"--prefix":       true,
	"--userconfig":   true,
	"--tag":          true,
	"--node-options": true,
}

// npxPackage finds the executed package: --package wins, otherwise the first
// positional argument. Boolean flags such as -y must not consume a value.
func npxPackage(args []string) string {
	var pkg string
	endOfOptions := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if endOfOptions {
			if pkg == "" {
				pkg = a
			}
			continue
		}
		switch {
		case a == "--":
			endOfOptions = true
		case npxValueFlags[a]:
			i++ // value is not the package
		case strings.HasPrefix(a, "--package="):
			pkg = strings.TrimPrefix(a, "--package=")
		case strings.HasPrefix(a, "-"):
			// -y/--yes and other boolean flags do not consume a value
		default:
			if pkg == "" {
				pkg = a
			}
		}
	}
	return pkg
}

var uvxValueFlags = map[string]bool{
	"-p": true, "--python": true,
	"-w": true, "--with": true,
	"-f": true, "--find-links": true,
	"-c": true, "--constraints": true,
	"-C": true, "--config-setting": true,
	"--index-url":         true,
	"--extra-index-url":   true,
	"--index":             true,
	"--default-index":     true,
	"--overrides":         true,
	"--refresh-package":   true,
	"--reinstall-package": true,
	"--link-mode":         true,
	"--cache-dir":         true,
	"--python-platform":   true,
	"--python-version":    true,
	"--resolution":        true,
	"--prerelease":        true,
	"--exclude-newer":     true,
	"--config-file":       true,
	"--directory":         true,
	"--no-binary":         true,
	"--only-binary":       true,
}

// uvxPinCheck resolves `uvx [flags] package` or `uvx --from package command`.
func uvxPinCheck(args []string) (string, bool) {
	endOfOptions := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if endOfOptions {
			return uvPinCheck(a)
		}
		switch {
		case a == "--":
			endOfOptions = true
		case a == "--from" && i+1 < len(args):
			return uvPinCheck(args[i+1])
		case strings.HasPrefix(a, "--from="):
			return uvPinCheck(strings.TrimPrefix(a, "--from="))
		case uvxValueFlags[a]:
			i++ // value-consuming flag
		case strings.HasPrefix(a, "-"):
			continue
		default:
			return uvPinCheck(a)
		}
	}
	return "", false
}

func uvPinCheck(spec string) (string, bool) {
	if strings.Contains(spec, "==") || hasPinnedVersion(spec) {
		return "", false
	}
	return spec, true
}

func hasPinnedVersion(spec string) bool {
	rest := spec
	if strings.HasPrefix(rest, "@") {
		if i := strings.Index(rest[1:], "/"); i >= 0 {
			rest = rest[i+1:]
		}
	}
	i := strings.LastIndex(rest, "@")
	if i <= 0 {
		return false
	}
	ver := strings.ToLower(strings.TrimSpace(rest[i+1:]))
	switch ver {
	case "", "latest", "next", "beta", "canary", "rc":
		return false
	}
	return true
}

func broadRoot(arg, home string) bool {
	a := strings.TrimSpace(arg)
	if a == "" {
		return false
	}
	if a == "/" || a == "~" || a == "%USERPROFILE%" || a == "$HOME" {
		return true
	}
	if home != "" && strings.EqualFold(filepath.Clean(a), filepath.Clean(home)) {
		return true
	}
	if len(a) == 3 && a[1] == ':' && (a[2] == '\\' || a[2] == '/') {
		return true // C:\ style drive root
	}
	return false
}

func isExecLike(name string) bool {
	l := strings.ToLower(name)
	for _, marker := range []string{"shell", "exec", "terminal", "bash", "powershell", "cmd", "command"} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]"
}

func chmodRemediation(path, summary string) *finding.Remediation {
	return &finding.Remediation{
		Class:   finding.ActionSafe,
		Summary: summary,
		Action:  "chmod_private",
		Params:  map[string]string{"path": path, "mode": "0600"},
	}
}
