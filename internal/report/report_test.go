package report

import (
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
)

func TestScorePerModuleCap(t *testing.T) {
	var fs []finding.Finding
	for i := 0; i < 10; i++ {
		fs = append(fs, finding.Finding{Module: "sbom", Severity: finding.SeverityCritical})
	}
	score, counts := Score(fs)
	// 10 criticals in one module cap at a 40 penalty: 10000/(100+40) ≈ 71.
	if score != 71 {
		t.Fatalf("score = %d, want 71", score)
	}
	if counts["CRITICAL"] != 10 {
		t.Fatalf("counts = %+v", counts)
	}
}

func TestScoreMultipleModules(t *testing.T) {
	fs := []finding.Finding{
		{Module: "a", Severity: finding.SeverityHigh},
		{Module: "b", Severity: finding.SeverityMedium},
		{Module: "c", Severity: finding.SeverityLow},
	}
	score, _ := Score(fs)
	// 15 total penalty: 10000/(100+15) ≈ 87.
	if score != 87 {
		t.Fatalf("score = %d, want 87", score)
	}
}

func TestScoreNeverCollapsesToZero(t *testing.T) {
	var fs []finding.Finding
	for _, module := range []string{"a", "b", "c", "d", "e", "f"} {
		for i := 0; i < 20; i++ {
			fs = append(fs, finding.Finding{Module: module, Severity: finding.SeverityCritical})
		}
	}
	score, _ := Score(fs)
	if score <= 0 || score >= 50 {
		t.Fatalf("score = %d, want a compressed but actionable value", score)
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		counts map[string]int
		want   string
	}{
		{map[string]int{"CRITICAL": 1}, "AT RISK"},
		{map[string]int{"HIGH": 1}, "ATTENTION"},
		{map[string]int{"MEDIUM": 1}, "REVIEW"},
		{map[string]int{}, "GOOD"},
	}
	for _, tc := range cases {
		if got := Verdict(tc.counts); got != tc.want {
			t.Errorf("Verdict(%v) = %s, want %s", tc.counts, got, tc.want)
		}
	}
}
