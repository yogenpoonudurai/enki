// Package agentcfg audits AI coding agent settings for permission sprawl:
// bypass modes, unrestricted shell grants, auto-approval, and access to
// sensitive credential paths.
package agentcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/configutil"
	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

const moduleName = "agent-permissions"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }

func (m *Module) Description() string {
	return "Audits agent permission modes and allow-lists (Claude Code, Cursor, VS Code)"
}

func (m *Module) Run(sc *scanner.Context) ([]finding.Finding, []scanner.CoverageGap, error) {
	var out []finding.Finding
	for _, cf := range sc.Configs {
		root, err := configutil.ToMap(cf.Data)
		if err != nil {
			continue
		}
		out = append(out, checkConfig(cf.Path, root)...)
	}
	if sc.Scope.IncludesHost() {
		out = append(out, checkShellProfiles(sc.HomeDir)...)
	}
	finding.Sort(out)
	return out, nil, nil
}

func checkConfig(path string, root map[string]any) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	add := func(ruleID, title, desc, evidence string, sev finding.Severity, conf finding.Confidence, rm *finding.Remediation) {
		key := ruleID + "|" + path
		if seen[key] {
			return
		}
		seen[key] = true
		f := finding.New(ruleID, moduleName, title, desc, sev, conf, finding.Location{Path: path})
		f.Evidence = evidence
		f.Remediation = rm
		out = append(out, f)
	}

	configutil.Walk(root, func(parent []string, key string, val any) {
		lk := strings.ToLower(key)

		switch lk {
		case "defaultmode":
			if s, ok := val.(string); ok && strings.EqualFold(s, "bypassPermissions") {
				keyPath := joinKeyPath(parent, key)
				add("AGT-001",
					"Agent runs with bypassPermissions",
					"Every tool call is auto-approved without review. A prompt injection or malicious MCP server gains immediate, unattended access to the host.",
					keyPath+" = bypassPermissions", finding.SeverityHigh, finding.ConfidenceHigh,
					removeKeyRemediation(path, keyPath, "Disable bypassPermissions and restore explicit approvals"))
			}
		case "dangerouslyskipperpermissions", "dangerously-skip-permissions", "dangerouslyskip":
			if b, ok := val.(bool); ok && b {
				keyPath := joinKeyPath(parent, key)
				add("AGT-001",
					"Agent runs with dangerouslySkipPermissions",
					"The agent skips all permission prompts, so tool calls execute without human review.",
					keyPath+" = true", finding.SeverityHigh, finding.ConfidenceHigh,
					removeKeyRemediation(path, keyPath, "Remove dangerouslySkipPermissions"))
			}
		case "allow", "allowedtools", "allowed_tools", "alwaysallow":
			for _, entry := range configutil.Strings(val) {
				if isUnrestrictedShell(entry) {
					add("AGT-002",
						"Agent allow-list grants unrestricted shell",
						"The allow-list contains an unscoped shell tool. Any injected instruction can run arbitrary commands without approval.",
						fmt.Sprintf("%s entry %q", lk, entry), finding.SeverityMedium, finding.ConfidenceHigh,
						&finding.Remediation{
							Class:    finding.ActionModerate,
							Summary:  fmt.Sprintf("Scope the %q allow-list entry", entry),
							Guidance: "Replace the wildcard with narrow, reviewed command patterns or remove the entry.",
						})
				}
				if touchesSensitivePath(entry) {
					add("AGT-004",
						"Agent may modify sensitive credential paths",
						"The allow-list grants access to SSH keys, cloud credentials, or GPG material. A compromised agent can exfiltrate or overwrite them.",
						fmt.Sprintf("%s entry %q", lk, entry), finding.SeverityHigh, finding.ConfidenceMedium,
						&finding.Remediation{
							Class:    finding.ActionModerate,
							Summary:  fmt.Sprintf("Remove access to %q from the allow-list", entry),
							Guidance: "Agents should never need ~/.ssh, ~/.aws, or ~/.gnupg. Remove the grant and rotate any keys the agent could have read.",
						})
				}
			}
		}

		if strings.Contains(lk, "autorun") || strings.Contains(lk, "auto_run") || strings.Contains(lk, "autoapprove") {
			if b, ok := val.(bool); ok && b {
				add("AGT-003",
					"Agent auto-approves tool actions",
					"Auto-run/auto-approve is enabled, so edits and commands execute without confirmation.",
					lk+" = true", finding.SeverityMedium, finding.ConfidenceMedium,
					&finding.Remediation{
						Class:    finding.ActionModerate,
						Summary:  "Disable auto-approval",
						Guidance: "Turn off auto-run/auto-approve in the editor settings and review tool calls manually.",
					})
			}
		}
	})

	return out
}

func checkShellProfiles(home string) []finding.Finding {
	files := []string{".zshrc", ".bashrc", ".profile", ".zprofile", ".config/fish/config.fish"}
	var out []finding.Finding
	for _, rel := range files {
		p := filepath.Join(home, rel)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if !strings.Contains(string(data), "--dangerously-skip-permissions") {
			continue
		}
		f := finding.New("AGT-001", moduleName,
			"Shell profile launches Claude Code with --dangerously-skip-permissions",
			"The flag is applied to every launch from this shell, permanently disabling permission prompts.",
			finding.SeverityHigh, finding.ConfidenceHigh, finding.Location{Path: p})
		f.Evidence = "shell profile contains --dangerously-skip-permissions"
		f.Remediation = &finding.Remediation{
			Class:    finding.ActionModerate,
			Summary:  "Remove the flag from the shell profile",
			Guidance: "Delete the alias/export containing --dangerously-skip-permissions and relaunch the shell.",
		}
		out = append(out, f)
	}
	return out
}

func removeKeyRemediation(path, keyPath, summary string) *finding.Remediation {
	return &finding.Remediation{
		Class:    finding.ActionModerate,
		Summary:  summary,
		Action:   "remove_json_key",
		Params:   map[string]string{"path": path, "key_path": keyPath},
		Guidance: "A timestamped backup is written before the edit.",
	}
}

func joinKeyPath(parent []string, key string) string {
	parts := append(append([]string{}, parent...), key)
	return strings.Join(parts, ".")
}

func isUnrestrictedShell(entry string) bool {
	e := strings.ToLower(strings.TrimSpace(entry))
	switch e {
	case "bash", "bash(*)", "bash(:*)", "shell", "shell(*)", "zsh", "zsh(*)",
		"sh", "sh(*)", "powershell", "powershell(*)", "pwsh", "pwsh(*)",
		"cmd", "cmd(*)":
		return true
	}
	return false
}

func touchesSensitivePath(entry string) bool {
	e := strings.ToLower(entry)
	for _, marker := range []string{".ssh", ".aws", ".gnupg", ".config/gcloud", "id_rsa", "id_ed25519"} {
		if strings.Contains(e, marker) {
			return true
		}
	}
	return false
}
