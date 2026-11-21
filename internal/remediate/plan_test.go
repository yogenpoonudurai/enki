package remediate

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/fingerprint"
	"github.com/yogenpoonudurai/enki/internal/report"
)

func TestDisplayClass(t *testing.T) {
	if got := DisplayClass(Action{Class: "moderate", Auto: false}); got != "GUIDANCE" {
		t.Fatalf("guidance label = %q", got)
	}
	if got := DisplayClass(Action{Class: "safe", Auto: true}); got != "SAFE" {
		t.Fatalf("safe label = %q", got)
	}
	if got := DisplayClass(Action{Class: "moderate", Auto: true}); got != "MODERATE" {
		t.Fatalf("moderate label = %q", got)
	}
}

func TestBuildPlanCarriesFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sha, size, err := fingerprint.Capture(path)
	if err != nil {
		t.Fatal(err)
	}
	rm := &finding.Remediation{
		Class:   finding.ActionSafe,
		Action:  "chmod_private",
		Summary: "restrict",
		Params: map[string]string{
			"path":                  path,
			"mode":                  "0600",
			fingerprint.ParamSHA256: sha,
			fingerprint.ParamSize:   strconv.FormatInt(size, 10),
		},
	}
	rep := &report.Report{Findings: []finding.Finding{{
		ID: "SEC-003-abc", RuleID: "SEC-003", Remediation: rm,
	}}}
	plan := BuildPlan(rep)
	if len(plan) != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	if plan[0].ExpectedSHA256 == "" || plan[0].ExpectedSize != int64(len("A=1\n")) {
		t.Fatalf("fingerprint not carried into action: %+v", plan[0])
	}
	if plan[0].ExpectedSHA256 != rm.Params[fingerprint.ParamSHA256] {
		t.Fatal("action fingerprint differs from remediation params")
	}
}
