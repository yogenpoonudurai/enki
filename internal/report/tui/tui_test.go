package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/report"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

func sampleReport() *report.Report {
	return &report.Report{
		Tool: report.Tool{Name: "enki", Version: "test", SchemaVersion: "1"},
		Scan: report.Scan{ID: "enki-test", Host: "unit", OS: "linux", Arch: "amd64", User: "tester"},
		Summary: report.Summary{
			Score: 70, Verdict: "ATTENTION", Total: 1,
			Counts: map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
		},
		Modules: []report.ModuleInfo{{Name: "mcp", Findings: 1}},
		Findings: []finding.Finding{{
			ID: "AGT-001-x", RuleID: "AGT-001", Module: "agent-permissions",
			Title: "Agent runs with bypassPermissions", Description: "Agent is bypassing approvals.",
			Severity: finding.SeverityHigh, Confidence: finding.ConfidenceHigh,
			Location: finding.Location{Path: "/tmp/settings.json"},
			Evidence: "permissions.defaultMode = bypassPermissions",
			Remediation: &finding.Remediation{
				Class: finding.ActionModerate, Summary: "Disable bypassPermissions",
				Action: "remove_json_key", Params: map[string]string{"path": "/tmp/settings.json", "key_path": "permissions.defaultMode"},
			},
		}},
	}
}

func TestDashboardRendersProgressAndResults(t *testing.T) {
	m := New("test", func(context.Context, func(scanner.Progress)) (*report.Report, error) {
		return nil, nil
	})
	m.width, m.height = 100, 40

	m.Update(progressMsg(scanner.Progress{Module: "mcp", State: scanner.StateRunning}))
	m.Update(progressMsg(scanner.Progress{Module: "mcp", State: scanner.StateDone}))
	m.Update(resultMsg{rep: sampleReport()})

	view := m.View()
	for _, want := range []string{"MODULES", "mcp", "FINDINGS", "POSTURE", "70/100", "AGT-001", "Agent runs with bypassPermissions"} {
		if !strings.Contains(view, want) {
			t.Errorf("dashboard missing %q\n%s", want, view)
		}
	}

	// Toggle the fix panel.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	fixView := m.View()
	if !strings.Contains(fixView, "FIX PLAN") {
		t.Fatalf("fix panel not rendered:\n%s", fixView)
	}

	// Detail pane via enter.
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	detail := m.View()
	if !strings.Contains(detail, "evidence:") {
		t.Fatalf("detail pane not rendered:\n%s", detail)
	}
}

func TestDashboardEmptyFindings(t *testing.T) {
	m := New("test", func(context.Context, func(scanner.Progress)) (*report.Report, error) {
		return nil, nil
	})
	rep := sampleReport()
	rep.Findings = nil
	rep.Summary = report.Summary{Score: 100, Verdict: "GOOD", Counts: map[string]int{}}
	m.Update(resultMsg{rep: rep})
	if !strings.Contains(m.View(), "no findings") {
		t.Fatal("empty state not rendered")
	}
}

func TestFullArtHeaderOnLargeTerminal(t *testing.T) {
	m := New("test", func(context.Context, func(scanner.Progress)) (*report.Report, error) {
		return nil, nil
	})
	m.width, m.height = report.SmallLogoWidth()+20, len(report.SmallLogoLines())+30

	view := m.View()
	if !strings.Contains(view, report.SmallLogoLines()[0]) {
		t.Fatal("compact artwork not used as the dashboard header")
	}
	if !strings.Contains(view, "ENKI") || !strings.Contains(view, "AI Security Posture") {
		t.Fatal("branded title line missing from the dashboard")
	}
	if !strings.Contains(view, "MODULES") {
		t.Fatal("dashboard content missing")
	}
	if strings.Contains(view, report.BannerLines[0]) {
		t.Fatal("wordmark should be replaced by the artwork")
	}
	if strings.Contains(view, report.LogoLines()[0]) {
		t.Fatal("the full-size artwork must not be used in the dashboard")
	}
}

func TestCompactHeaderOnSmallTerminal(t *testing.T) {
	m := New("test", func(context.Context, func(scanner.Progress)) (*report.Report, error) {
		return nil, nil
	})
	m.width, m.height = report.SmallLogoWidth()+10, 20
	view := m.View()
	if !strings.Contains(view, report.BannerLines[0]) {
		t.Fatal("wordmark should be used when the artwork does not fit")
	}
	if strings.Contains(view, report.SmallLogoLines()[0]) {
		t.Fatal("artwork must not overflow a short terminal")
	}
}

func TestCompactHeaderOnTypicalTerminal(t *testing.T) {
	m := New("test", func(context.Context, func(scanner.Progress)) (*report.Report, error) {
		return nil, nil
	})
	// 80x30 is a common terminal size; the artwork must be visible.
	m.width, m.height = 80, 30
	if !strings.Contains(m.View(), report.SmallLogoLines()[0]) {
		t.Fatal("artwork hidden on a typical 80x30 terminal")
	}
}
