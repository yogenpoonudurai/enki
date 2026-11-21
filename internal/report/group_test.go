package report

import (
	"strings"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
)

func sbomFinding(pkg, advisory string, sev finding.Severity) finding.Finding {
	return finding.Finding{
		ID: "id-" + pkg + advisory, RuleID: "SBOM-001", Module: "sbom",
		Title: pkg + " advisory " + advisory, Severity: sev,
		Location: finding.Location{Path: "/p/package-lock.json"},
		Tags:     []string{"sbom", "cve", "pkg:" + pkg, "advisory:" + advisory},
	}
}

func TestCollapseSBOM(t *testing.T) {
	fs := []finding.Finding{
		sbomFinding("lodash@4.17.20", "GHSA-1", finding.SeverityHigh),
		sbomFinding("lodash@4.17.20", "GHSA-2", finding.SeverityMedium),
		{RuleID: "SEC-001", Module: "secrets", Title: "key", Severity: finding.SeverityHigh, Tags: []string{"secret"}},
	}
	out := CollapseSBOM(fs)
	if len(out) != 2 {
		t.Fatalf("groups = %d, want 2: %+v", len(out), out)
	}
	found := false
	for _, f := range out {
		if f.RuleID == "SBOM-001" {
			found = true
			if !strings.Contains(f.Title, "lodash@4.17.20") || !strings.Contains(f.Title, "2 advisories") {
				t.Fatalf("group title = %q", f.Title)
			}
			if f.Severity != finding.SeverityHigh {
				t.Fatalf("group severity = %s", f.Severity)
			}
			if !strings.Contains(f.Evidence, "top: GHSA-") {
				t.Fatalf("group evidence = %q", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatal("grouped finding missing")
	}
}

func TestCollapseSBOMKeepsSingle(t *testing.T) {
	out := CollapseSBOM([]finding.Finding{sbomFinding("x@1.0.0", "A-1", finding.SeverityLow)})
	if len(out) != 1 || out[0].Title != "x@1.0.0 advisory A-1" {
		t.Fatalf("single advisory should pass through: %+v", out)
	}
}
