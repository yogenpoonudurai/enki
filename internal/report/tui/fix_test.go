package tui

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/fingerprint"
	"github.com/yogenpoonudurai/enki/internal/report"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

func fixTestModel(t *testing.T) (*Model, string, string) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("OPENAI_API_KEY=sk-test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(envPath, 0o644); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(dir, "settings.json")
	original := "{\n  \"permissions\": {\n    \"defaultMode\": \"bypassPermissions\"\n  }\n}\n"
	if err := os.WriteFile(settings, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	envSHA, envSize, err := fingerprint.Capture(envPath)
	if err != nil {
		t.Fatal(err)
	}
	settingsSHA, settingsSize, err := fingerprint.Capture(settings)
	if err != nil {
		t.Fatal(err)
	}

	rep := &report.Report{
		Tool: report.Tool{Name: "enki", Version: "test", SchemaVersion: "1"},
		Scan: report.Scan{ID: "fixture", Host: "unit", OS: "linux", Arch: "amd64", User: "tester"},
		Summary: report.Summary{
			Score: 40, Verdict: "AT RISK", Total: 3,
			Counts: map[string]int{"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0},
		},
		Modules: []report.ModuleInfo{{Name: "secrets"}},
		Findings: []finding.Finding{
			{
				ID: "f1", RuleID: "SEC-001", Module: "secrets", Title: "key", Severity: finding.SeverityHigh,
				Location: finding.Location{Path: envPath},
				Remediation: &finding.Remediation{
					Class: finding.ActionSafe, Summary: "chmod 600", Action: "chmod_private",
					Params: map[string]string{
						"path": envPath, "mode": "0600",
						fingerprint.ParamSHA256: envSHA,
						fingerprint.ParamSize:   strconv.FormatInt(envSize, 10),
					},
				},
			},
			{
				ID: "f2", RuleID: "AGT-001", Module: "agent-permissions", Title: "bypass", Severity: finding.SeverityHigh,
				Location: finding.Location{Path: settings},
				Remediation: &finding.Remediation{
					Class: finding.ActionModerate, Summary: "remove bypass", Action: "remove_json_key",
					Params: map[string]string{
						"path": settings, "key_path": "permissions.defaultMode",
						fingerprint.ParamSHA256: settingsSHA,
						fingerprint.ParamSize:   strconv.FormatInt(settingsSize, 10),
					},
				},
			},
			{
				ID: "f3", RuleID: "MCP-001", Module: "mcp", Title: "unpinned", Severity: finding.SeverityMedium,
				Remediation: &finding.Remediation{
					Class: finding.ActionModerate, Summary: "pin the package",
				},
			},
		},
	}

	m := New("test", func(context.Context, func(scanner.Progress)) (*report.Report, error) {
		return nil, nil
	})
	m.width, m.height = 100, 40
	m.Update(resultMsg{rep: rep})
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	return m, envPath, settings
}

func fixIndex(m *Model, ruleID string) int {
	for i, a := range m.fixPlan {
		if a.RuleID == ruleID {
			return i
		}
	}
	return -1
}

func pressRune(m *Model, r rune) {
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
}

func TestFixPanelAppliesSafeAction(t *testing.T) {
	m, envPath, _ := fixTestModel(t)

	idx := fixIndex(m, "SEC-001")
	if idx < 0 {
		t.Fatal("safe action missing from plan")
	}
	pressRune(m, rune('1'+idx))

	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
	if !strings.Contains(m.View(), "applied") {
		t.Fatal("application feedback missing")
	}
}

func TestFixPanelConfirmsModerateAction(t *testing.T) {
	m, _, settings := fixTestModel(t)
	idx := fixIndex(m, "AGT-001")
	if idx < 0 {
		t.Fatal("moderate action missing")
	}
	pressRune(m, rune('1'+idx))

	view := m.View()
	if !strings.Contains(view, "Apply [") || !strings.Contains(view, "[y] yes") {
		t.Fatalf("confirmation prompt missing:\n%s", view)
	}
	data, _ := os.ReadFile(settings)
	if !strings.Contains(string(data), "defaultMode") {
		t.Fatal("file changed before confirmation")
	}

	pressRune(m, 'y')
	data, _ = os.ReadFile(settings)
	if strings.Contains(string(data), "defaultMode") {
		t.Fatalf("moderate edit not applied:\n%s", data)
	}

	pressRune(m, 'u')
	restored, _ := os.ReadFile(settings)
	if !strings.Contains(string(restored), "defaultMode") {
		t.Fatalf("undo did not restore the edit:\n%s", restored)
	}
}

func TestFixPanelManualActionExplains(t *testing.T) {
	m, _, _ := fixTestModel(t)
	idx := fixIndex(m, "MCP-001")
	if idx < 0 {
		t.Fatal("manual action missing")
	}
	pressRune(m, rune('1'+idx))
	view := m.View()
	if !strings.Contains(view, "manual action") {
		t.Fatalf("manual guidance missing:\n%s", view)
	}
	if !strings.Contains(view, "GUIDANCE") {
		t.Fatalf("guidance badge missing:\n%s", view)
	}
}

func TestFixPanelApplySafeAll(t *testing.T) {
	m, envPath, settings := fixTestModel(t)
	pressRune(m, 'a')

	info, _ := os.Stat(envPath)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("safe action not applied by a: %04o", info.Mode().Perm())
	}
	data, _ := os.ReadFile(settings)
	if !strings.Contains(string(data), "defaultMode") {
		t.Fatal("apply-safe-all must not apply moderate actions")
	}
}
