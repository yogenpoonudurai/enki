package report

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/fingerprint"
	"github.com/yogenpoonudurai/enki/internal/scanner"
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
		if got := Verdict(tc.counts, nil); got != tc.want {
			t.Errorf("Verdict(%v) = %s, want %s", tc.counts, got, tc.want)
		}
	}
}

func TestVerdictWithCoverage(t *testing.T) {
	permission := []scanner.CoverageGap{{Module: "listeners", Kind: scanner.GapPermission}}
	if got := Verdict(map[string]int{}, permission); got != "GOOD (partial)" {
		t.Fatalf("gapped clean verdict = %q, want GOOD (partial)", got)
	}
	network := []scanner.CoverageGap{{Module: "sbom", Kind: scanner.GapNetwork}}
	if got := Verdict(map[string]int{}, network); got != "GOOD (partial)" {
		t.Fatalf("network-gap verdict = %q, want GOOD (partial)", got)
	}
	notApplicable := []scanner.CoverageGap{{Module: "listeners", Kind: scanner.GapNotApplicable}}
	if got := Verdict(map[string]int{}, notApplicable); got != "GOOD" {
		t.Fatalf("not-applicable verdict = %q, want GOOD", got)
	}
	if got := Verdict(map[string]int{"HIGH": 1}, permission); got != "ATTENTION" {
		t.Fatalf("finding verdict = %q, want ATTENTION", got)
	}
}

func TestBuildAttachesTargetFingerprints(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("OPENAI_API_KEY=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := finding.New("SEC-003", "secrets", "perms", "desc", finding.SeverityMedium, finding.ConfidenceHigh, finding.Location{Path: path})
	f.Remediation = &finding.Remediation{
		Class: finding.ActionSafe, Action: "chmod_private", Summary: "restrict",
		Params: map[string]string{"path": path, "mode": "0600"},
	}
	rep := Build("test", "builtin-1", &scanner.Context{}, []*scanner.ModuleResult{{Module: "secrets", Findings: []finding.Finding{f}}}, time.Now(), "test-id")
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %d", len(rep.Findings))
	}
	params := rep.Findings[0].Remediation.Params
	if params[fingerprint.ParamSHA256] == "" {
		t.Fatal("report did not attach a target fingerprint")
	}
	if params[fingerprint.ParamSize] != strconv.Itoa(len("OPENAI_API_KEY=x\n")) {
		t.Fatalf("size = %q", params[fingerprint.ParamSize])
	}
}

func TestBuildAttachesRuleMetadata(t *testing.T) {
	f := finding.New("MCP-001", "mcp", "unpinned", "desc", finding.SeverityMedium, finding.ConfidenceHigh, finding.Location{Path: "/x/.mcp.json"})
	rep := Build("test", "builtin-1", &scanner.Context{}, []*scanner.ModuleResult{{Module: "mcp", Findings: []finding.Finding{f}}}, time.Now(), "test-id")
	got := rep.Findings[0]
	if got.Category != finding.CategoryUnsafeConfig {
		t.Fatalf("category = %q", got.Category)
	}
	if got.Basis != finding.BasisConditional {
		t.Fatalf("basis = %q", got.Basis)
	}
}
