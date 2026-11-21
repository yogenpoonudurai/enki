package sarif

import (
	"testing"
	"time"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/report"
)

func TestBuild(t *testing.T) {
	rep := &report.Report{
		Tool: report.Tool{Name: "enki", Version: "test"},
		Scan: report.Scan{StartedAt: time.Now()},
		Findings: []finding.Finding{
			{ID: "A1", RuleID: "AEP-001", Module: "endpoint-exposure", Title: "exposed", Description: "d", Severity: finding.SeverityCritical, Confidence: finding.ConfidenceHigh, Location: finding.Location{Addr: "0.0.0.0:11434"}},
			{ID: "A2", RuleID: "AEP-001", Module: "endpoint-exposure", Title: "exposed2", Description: "d", Severity: finding.SeverityHigh, Location: finding.Location{Addr: "0.0.0.0:11434"}},
			{ID: "S1", RuleID: "SEC-001", Module: "secrets", Title: "key", Description: "d", Severity: finding.SeverityMedium, Location: finding.Location{Path: "/tmp/.env", Line: 3}},
		},
	}
	doc := Build(rep)
	if doc.Version != "2.1.0" {
		t.Fatalf("version = %s", doc.Version)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 3 {
		t.Fatalf("results = %+v", doc.Runs)
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != 2 {
		t.Fatalf("rules should be deduplicated, got %d", len(doc.Runs[0].Tool.Driver.Rules))
	}
	if doc.Runs[0].Results[0].Level != "error" || doc.Runs[0].Results[2].Level != "warning" {
		t.Fatalf("levels = %s / %s", doc.Runs[0].Results[0].Level, doc.Runs[0].Results[2].Level)
	}
	if doc.Runs[0].Results[2].Locations[0].PhysicalLocation.Region.StartLine != 3 {
		t.Fatal("line number not propagated")
	}
	if doc.Runs[0].Results[0].PartialFingerprints["enkiFinding/v1"] != "A1" {
		t.Fatal("fingerprint missing")
	}
}
