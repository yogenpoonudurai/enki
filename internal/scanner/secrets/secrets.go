// Package secrets sweeps AI-relevant files for provider credentials, shell
// history leaks, plaintext token files, and permissive file modes.
package secrets

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/scanner"
	"github.com/yogenpoonudurai/enki/internal/secretlib"
)

const moduleName = "secrets"

const maxFileSize = 2 << 20

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }

func (m *Module) Description() string {
	return "Finds AI provider credentials in configs, .env files, shell history, and token stores"
}

type target struct {
	path string
	kind string // config, env, history, credential, hf-token
}

func (m *Module) Run(sc *scanner.Context) ([]finding.Finding, []scanner.CoverageGap, error) {
	var out []finding.Finding
	gitCache := map[string]bool{}
	for _, t := range buildTargets(sc) {
		out = append(out, scanTarget(sc, t, gitCache)...)
	}
	finding.Sort(out)
	return out, nil, nil
}

func buildTargets(sc *scanner.Context) []target {
	seen := map[string]bool{}
	var out []target
	add := func(p, kind string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, target{path: p, kind: kind})
	}

	for _, cf := range sc.Configs {
		add(cf.Path, "config")
	}
	add(filepath.Join(sc.HomeDir, ".codex", "auth.json"), "config")
	add(filepath.Join(sc.HomeDir, ".continue", "config.json"), "config")
	add(filepath.Join(sc.HomeDir, ".aider.conf.yml"), "config")

	for _, name := range []string{".env", ".env.local", ".env.development", ".env.production"} {
		add(filepath.Join(sc.WorkingDir, name), "env")
	}
	add(filepath.Join(sc.HomeDir, ".env"), "env")

	add(filepath.Join(sc.HomeDir, ".zsh_history"), "history")
	add(filepath.Join(sc.HomeDir, ".bash_history"), "history")
	add(filepath.Join(sc.HomeDir, ".local", "share", "fish", "fish_history"), "history")

	add(filepath.Join(sc.HomeDir, ".netrc"), "credential")
	add(filepath.Join(sc.HomeDir, ".git-credentials"), "credential")
	add(filepath.Join(sc.HomeDir, ".cache", "huggingface", "token"), "hf-token")
	return out
}

func scanTarget(sc *scanner.Context, t target, gitCache map[string]bool) []finding.Finding {
	info, err := os.Stat(t.path)
	if err != nil || info.IsDir() || info.Size() > maxFileSize {
		return nil
	}
	data, err := os.ReadFile(t.path)
	if err != nil {
		return nil
	}
	content := string(data)
	mode := info.Mode().Perm()
	permissive := mode&0o077 != 0

	if t.kind == "hf-token" {
		trimmed := strings.TrimSpace(content)
		hit := secretlib.ScanValue(trimmed)
		if hit == nil || !strings.HasPrefix(trimmed, "hf_") {
			return nil
		}
		f := finding.New("SEC-004", moduleName,
			"Hugging Face token stored in plaintext",
			"The Hugging Face CLI token file holds a live credential. Malware or another user with file access can read it.",
			finding.SeverityMedium, finding.ConfidenceHigh, finding.Location{Path: t.path})
		f.Evidence = fmt.Sprintf("Hugging Face token (fingerprint %s, value %s) · file mode %04o",
			finding.SecretFingerprint(trimmed), finding.RedactSecret(trimmed), mode)
		f.Remediation = rotateRemediation(t.path, permissive)
		f.Tags = []string{"secret", "token-file"}
		return []finding.Finding{f}
	}

	var matches []secretlib.Match
	if t.kind == "history" {
		matches = secretlib.Scan(content)
	} else {
		matches = secretlib.ScanAll(content)
	}

	var out []finding.Finding
	seen := map[string]bool{}
	placeholder := false
	for _, match := range matches {
		if t.kind == "credential" && !isAIProvider(match.ID) {
			continue
		}
		key := match.ID + "|" + match.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		placeholder = true

		line := lineOf(content, match.Index)
		fp := finding.SecretFingerprint(match.Value)
		redacted := finding.RedactSecret(match.Value)

		switch t.kind {
		case "history":
			sev := finding.SeverityMedium
			if permissive {
				sev = finding.SeverityHigh
			}
			f := finding.New("SEC-002", moduleName,
				fmt.Sprintf("%s in shell history", match.Name),
				"Exported credentials persist in shell history files, which are commonly synced to dotfile repositories, backups, and other machines.",
				sev, finding.ConfidenceHigh, finding.Location{Path: t.path, Line: line})
			f.Evidence = fmt.Sprintf("%s (fingerprint %s, value %s) · file mode %04o", match.Name, fp, redacted, mode)
			f.Remediation = &finding.Remediation{
				Class:    finding.ActionModerate,
				Summary:  "Remove the history line and rotate the credential",
				Guidance: "Delete the offending line (or rebuild the history file) and rotate the key at the provider.",
			}
			f.Tags = []string{"secret", "history"}
			out = append(out, f)
		default:
			sev := finding.SeverityHigh
			conf := finding.ConfidenceHigh
			tracked := gitTracked(sc, t.path, gitCache)
			if tracked {
				sev = finding.SeverityCritical
			}
			f := finding.New("SEC-001", moduleName,
				fmt.Sprintf("%s in %s", match.Name, filepath.Base(t.path)),
				"A provider credential is stored in a plaintext file. Treat it as compromised: it may already be exposed to backups, other users, or version control.",
				sev, conf, finding.Location{Path: t.path, Line: line})
			evidence := fmt.Sprintf("%s (fingerprint %s, value %s) · file mode %04o", match.Name, fp, redacted, mode)
			if tracked {
				evidence += " · tracked by git"
			}
			f.Evidence = evidence
			f.Remediation = rotateRemediation(t.path, permissive)
			if tracked {
				f.Remediation.Guidance += " The file is tracked by git; rewrite history before pushing and rotate the key immediately."
			}
			f.Tags = []string{"secret", "plaintext"}
			out = append(out, f)
		}
	}

	if placeholder && permissive && t.kind != "history" {
		f := finding.New("SEC-003", moduleName,
			"Credential file is readable by other users",
			"Group/other permissions expose the secret-bearing file to every local account.",
			finding.SeverityMedium, finding.ConfidenceHigh, finding.Location{Path: t.path})
		f.Evidence = fmt.Sprintf("file mode %04o", mode)
		f.Remediation = &finding.Remediation{
			Class:   finding.ActionSafe,
			Summary: "Restrict the file to the owning user",
			Action:  "chmod_private",
			Params:  map[string]string{"path": t.path, "mode": "0600"},
		}
		f.Tags = []string{"secret", "permissions"}
		out = append(out, f)
	}
	return out
}

func rotateRemediation(path string, permissive bool) *finding.Remediation {
	if permissive {
		return &finding.Remediation{
			Class:    finding.ActionSafe,
			Summary:  "Restrict file permissions (then rotate the credential)",
			Action:   "chmod_private",
			Params:   map[string]string{"path": path, "mode": "0600"},
			Guidance: "Revoke and re-issue the key at the provider after restricting the file, then inject it at runtime from an environment variable or OS keychain.",
		}
	}
	return &finding.Remediation{
		Class:    finding.ActionModerate,
		Summary:  "Rotate the credential and move it to a secret manager",
		Guidance: "Revoke and re-issue the key at the provider, then inject it at runtime from an environment variable or OS keychain.",
		Params:   map[string]string{"path": path},
	}
}

func isAIProvider(id string) bool {
	switch id {
	case "openai", "anthropic", "huggingface", "google":
		return true
	}
	return false
}

func gitTracked(sc *scanner.Context, path string, cache map[string]bool) bool {
	if v, ok := cache[path]; ok {
		return v
	}
	tracked := false
	rel, err := filepath.Rel(sc.WorkingDir, path)
	if err == nil && !strings.HasPrefix(rel, "..") {
		if _, err := os.Stat(filepath.Join(sc.WorkingDir, ".git")); err == nil {
			cmd := exec.CommandContext(sc.Ctx, "git", "-C", sc.WorkingDir, "ls-files", "--error-unmatch", "--", rel)
			tracked = cmd.Run() == nil
		}
	}
	cache[path] = tracked
	return tracked
}

func lineOf(content string, idx int) int {
	if idx < 0 || idx > len(content) {
		return 0
	}
	return strings.Count(content[:idx], "\n") + 1
}
