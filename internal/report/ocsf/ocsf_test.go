package ocsf

import (
	"testing"
	"time"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/report"
)

func TestBuildMapping(t *testing.T) {
	rep := &report.Report{
		Tool: report.Tool{Name: "enki", Version: "test"},
		Scan: report.Scan{StartedAt: time.Now()},
		Findings: []finding.Finding{
			{ID: "A1", RuleID: "AEP-001", Title: "exposed", Description: "d", Severity: finding.SeverityCritical, Confidence: finding.ConfidenceHigh, Location: finding.Location{Addr: "0.0.0.0:11434"}},
			{ID: "S1", RuleID: "SEC-001", Title: "key", Severity: finding.SeverityLow, Confidence: finding.ConfidenceLow, Location: finding.Location{Path: "/tmp/.env"}},
		},
	}
	events := Build(rep)
	if len(events) != 2 {
		t.Fatalf("events = %d", len(events))
	}
	if events[0].ClassUID != 2004 || events[0].CategoryUID != 2 || events[0].TypeUID != 200401 {
		t.Fatalf("class mapping = %+v", events[0])
	}
	if events[0].SeverityID != 5 || events[1].SeverityID != 2 {
		t.Fatalf("severity ids = %d / %d", events[0].SeverityID, events[1].SeverityID)
	}
	if events[0].ConfidenceID != 3 || events[1].ConfidenceID != 1 {
		t.Fatalf("confidence ids = %d / %d", events[0].ConfidenceID, events[1].ConfidenceID)
	}
	if events[0].Resources[0].Type != "Network Endpoint" || events[1].Resources[0].Type != "File" {
		t.Fatalf("resource types = %+v", events)
	}
}
