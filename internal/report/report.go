// Package report assembles scan results into enki's stable report model.
package report

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"time"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

const SchemaVersion = "1"

type Tool struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	SchemaVersion string `json:"schema_version"`
	RulePack      string `json:"rule_pack"`
}

type Scan struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
	Host       string    `json:"host"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	User       string    `json:"user"`
	Elevated   bool      `json:"elevated"`
	WorkDir    string    `json:"workdir"`
}

type Summary struct {
	Score   int            `json:"score"`
	Verdict string         `json:"verdict"`
	Total   int            `json:"total"`
	Counts  map[string]int `json:"counts"`
}

type ModuleInfo struct {
	Name       string `json:"name"`
	Findings   int    `json:"findings"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

type Report struct {
	Tool     Tool                  `json:"tool"`
	Scan     Scan                  `json:"scan"`
	Summary  Summary               `json:"summary"`
	Modules  []ModuleInfo          `json:"modules"`
	Findings []finding.Finding     `json:"findings"`
	Coverage []scanner.CoverageGap `json:"coverage,omitempty"`
}

// Build assembles a Report from module results.
func Build(ver, rulePack string, sc *scanner.Context, results []*scanner.ModuleResult, started time.Time, scanID string) *Report {
	if scanID == "" {
		scanID = newScanID()
	}
	rep := &Report{
		Tool: Tool{Name: "enki", Version: ver, SchemaVersion: SchemaVersion, RulePack: rulePack},
		Scan: Scan{
			ID:         scanID,
			StartedAt:  started.UTC(),
			DurationMS: time.Since(started).Milliseconds(),
			Host:       sc.Hostname,
			OS:         sc.OS,
			Arch:       sc.Arch,
			User:       sc.Username,
			Elevated:   sc.Elevated,
			WorkDir:    sc.WorkingDir,
		},
		Findings: []finding.Finding{},
		Modules:  []ModuleInfo{},
	}
	rep.Coverage = append(rep.Coverage, sc.Gaps...)
	for _, res := range results {
		mi := ModuleInfo{Name: res.Module, Findings: len(res.Findings), DurationMS: res.Duration.Milliseconds()}
		if res.Err != nil {
			mi.Error = res.Err.Error()
		}
		rep.Modules = append(rep.Modules, mi)
		rep.Findings = append(rep.Findings, res.Findings...)
		rep.Coverage = append(rep.Coverage, res.Gaps...)
	}
	finding.Sort(rep.Findings)
	rep.Summary.Score, rep.Summary.Counts = Score(rep.Findings)
	rep.Summary.Total = len(rep.Findings)
	rep.Summary.Verdict = Verdict(rep.Summary.Counts)
	return rep
}

var severityPenalty = map[finding.Severity]int{
	finding.SeverityCritical: 20,
	finding.SeverityHigh:     10,
	finding.SeverityMedium:   4,
	finding.SeverityLow:      1,
	finding.SeverityInfo:     0,
}

// modulePenaltyCap keeps a single noisy module from zeroing the score.
const modulePenaltyCap = 40

// Score computes a 0-100 posture score. Penalties are weighted by severity
// and capped per module (so one noisy module cannot dominate), then compressed
// with diminishing returns so large-but-routine finding sets stay actionable
// instead of collapsing to zero.
func Score(fs []finding.Finding) (int, map[string]int) {
	counts := map[string]int{
		string(finding.SeverityCritical): 0,
		string(finding.SeverityHigh):     0,
		string(finding.SeverityMedium):   0,
		string(finding.SeverityLow):      0,
		string(finding.SeverityInfo):     0,
	}
	perModule := map[string]int{}
	for _, f := range fs {
		counts[string(f.Severity)]++
		perModule[f.Module] += severityPenalty[f.Severity]
	}
	total := 0
	for _, p := range perModule {
		if p > modulePenaltyCap {
			p = modulePenaltyCap
		}
		total += p
	}
	score := int(math.Round(10000 / float64(100+total)))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, counts
}

func Verdict(counts map[string]int) string {
	switch {
	case counts[string(finding.SeverityCritical)] > 0:
		return "AT RISK"
	case counts[string(finding.SeverityHigh)] > 0:
		return "ATTENTION"
	case counts[string(finding.SeverityMedium)] > 0:
		return "REVIEW"
	default:
		return "GOOD"
	}
}

func newScanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return "enki-" + hex.EncodeToString(b[:])
}
