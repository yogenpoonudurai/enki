package sbom

import (
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
)

func TestCVSSV3BaseScore(t *testing.T) {
	cases := []struct {
		vector string
		score  float64
		sev    finding.Severity
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, finding.SeverityCritical},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, finding.SeverityMedium},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8, finding.SeverityHigh},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, finding.SeverityCritical},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8, finding.SeverityHigh},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, finding.SeverityCritical},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 0, ""},
	}
	for _, tc := range cases {
		score, ok := cvssV3BaseScore(tc.vector)
		if tc.sev == "" {
			if ok {
				t.Errorf("%s: expected unsupported vector, got score %.1f", tc.vector, score)
			}
			continue
		}
		if !ok || score != tc.score {
			t.Errorf("%s: got %.1f (ok=%v), want %.1f", tc.vector, score, ok, tc.score)
		}
		if sev, _, ok := severityFromVector(tc.vector); !ok || sev != tc.sev {
			t.Errorf("%s: severity %s, want %s", tc.vector, sev, tc.sev)
		}
	}
}

func TestSeverityFromScore(t *testing.T) {
	cases := map[float64]finding.Severity{
		0:   finding.SeverityInfo,
		1.2: finding.SeverityLow,
		5.0: finding.SeverityMedium,
		8.0: finding.SeverityHigh,
		9.8: finding.SeverityCritical,
	}
	for score, want := range cases {
		if got := severityFromScore(score); got != want {
			t.Errorf("score %.1f → %s, want %s", score, got, want)
		}
	}
}

func TestConvertVulnPrefersCVSSOverGHSA(t *testing.T) {
	raw := &osvVuln{
		ID:               "GHSA-test",
		DatabaseSpecific: map[string]any{"severity": "MODERATE"},
		Severity: []osvSeverity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
	}
	adv := convertVuln(raw)
	if adv.Severity != finding.SeverityCritical || adv.CVSS != 9.8 {
		t.Fatalf("got %s / %.1f, want CRITICAL / 9.8", adv.Severity, adv.CVSS)
	}
}

func TestConvertVulnFallsBackToGHSA(t *testing.T) {
	raw := &osvVuln{
		ID:               "GHSA-test",
		DatabaseSpecific: map[string]any{"severity": "MODERATE"},
	}
	if adv := convertVuln(raw); adv.Severity != finding.SeverityMedium {
		t.Fatalf("got %s, want MEDIUM", adv.Severity)
	}
}
