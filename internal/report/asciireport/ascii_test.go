package asciireport

import (
	"strings"
	"testing"
	"time"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/report"
)

func sample() *report.Report {
	return &report.Report{
		Tool: report.Tool{Name: "enki", Version: "test", SchemaVersion: "1", RulePack: "builtin-1"},
		Scan: report.Scan{
			ID: "enki-test", StartedAt: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC),
			Host: "unit", OS: "linux", Arch: "amd64", User: "tester",
		},
		Summary: report.Summary{
			Score: 60, Verdict: "AT RISK", Total: 1,
			Counts: map[string]int{"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
		},
		Modules: []report.ModuleInfo{{Name: "endpoint-exposure", Findings: 1, DurationMS: 12}},
		Findings: []finding.Finding{{
			ID: "AEP-001-x", RuleID: "AEP-001", Module: "endpoint-exposure",
			Title: "Ollama exposed on 0.0.0.0:11434", Description: "desc",
			Severity: finding.SeverityCritical, Confidence: finding.ConfidenceHigh,
			Location: finding.Location{Addr: "0.0.0.0:11434"},
			Evidence: "GET /api/tags → 200",
			Remediation: &finding.Remediation{
				Class: finding.ActionRisky, Summary: "bind to loopback", Command: "sudo ufw deny 11434/tcp",
			},
		}},
	}
}

func TestRenderContainsSections(t *testing.T) {
	out := Render(sample(), false)
	for _, want := range []string{
		"ENKI · AI SECURITY POSTURE REPORT", "POSTURE SCORE", "60 / 100",
		"VERDICT", "AEP-001", "Ollama exposed", "sudo ufw deny 11434/tcp", "MODULES",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("plain report contains ANSI escapes")
	}
}

func TestRenderColor(t *testing.T) {
	if !strings.Contains(Render(sample(), true), "\x1b[") {
		t.Fatal("colored report has no ANSI escapes")
	}
}

func TestNoFindings(t *testing.T) {
	rep := sample()
	rep.Findings = nil
	rep.Summary = report.Summary{Score: 100, Verdict: "GOOD", Counts: map[string]int{}}
	out := Render(rep, false)
	if !strings.Contains(out, "100 / 100") {
		t.Fatalf("missing score: %s", out)
	}
}
