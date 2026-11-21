// Package report assembles scan results into enki's stable report model.
package report

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"strconv"
	"time"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/fingerprint"
	"github.com/yogenpoonudurai/enki/internal/rules"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

const SchemaVersion = "2"

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
	Scope      string    `json:"scope"`
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
	Gaps       int    `json:"gaps,omitempty"`
	Skipped    bool   `json:"skipped,omitempty"`
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
			Scope:      scopeName(sc.Scope),
		},
		Findings: []finding.Finding{},
		Modules:  []ModuleInfo{},
	}
	rep.Coverage = append(rep.Coverage, sc.Gaps...)
	for _, res := range results {
		mi := ModuleInfo{
			Name:       res.Module,
			Findings:   len(res.Findings),
			DurationMS: res.Duration.Milliseconds(),
			Gaps:       len(res.Gaps),
			Skipped:    res.Skipped,
		}
		if res.Err != nil {
			mi.Error = res.Err.Error()
		}
		rep.Modules = append(rep.Modules, mi)
		rep.Findings = append(rep.Findings, res.Findings...)
		rep.Coverage = append(rep.Coverage, res.Gaps...)
	}
	attachTargetFingerprints(rep.Findings)
	attachRuleMetadata(rep.Findings)
	finding.Sort(rep.Findings)
	rep.Summary.Score, rep.Summary.Counts = Score(rep.Findings)
	rep.Summary.Total = len(rep.Findings)
	rep.Summary.Verdict = Verdict(rep.Summary.Counts, rep.Coverage)
	return rep
}

func scopeName(s scanner.Scope) string {
	if s == "" {
		return string(scanner.ScopeFull)
	}
	return string(s)
}

// attachTargetFingerprints records the content identity of every file that a
// machine remediation would modify, so a stale report cannot overwrite a file
// that changed after the scan.
func attachTargetFingerprints(fs []finding.Finding) {
	for i := range fs {
		rm := fs[i].Remediation
		if rm == nil || rm.Params == nil {
			continue
		}
		switch rm.Action {
		case "chmod_private", "remove_json_key":
		default:
			continue
		}
		path := rm.Params["path"]
		if path == "" {
			continue
		}
		sha, size, err := fingerprint.Capture(path)
		if err != nil {
			continue
		}
		rm.Params[fingerprint.ParamSHA256] = sha
		rm.Params[fingerprint.ParamSize] = strconv.FormatInt(size, 10)
	}
}

// attachRuleMetadata fills category and evidence basis from the rule catalog,
// so every finding states what kind of risk it represents and how directly the
// evidence proves it.
func attachRuleMetadata(fs []finding.Finding) {
	index := make(map[string]rules.Rule, len(rules.Catalog))
	for _, r := range rules.Catalog {
		index[r.ID] = r
	}
	for i := range fs {
		r, ok := index[fs[i].RuleID]
		if !ok {
			continue
		}
		if fs[i].Category == "" {
			fs[i].Category = r.Category
		}
		if fs[i].Basis == "" {
			fs[i].Basis = r.Basis
		}
	}
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

func Verdict(counts map[string]int, coverage []scanner.CoverageGap) string {
	base := "GOOD"
	switch {
	case counts[string(finding.SeverityCritical)] > 0:
		base = "AT RISK"
	case counts[string(finding.SeverityHigh)] > 0:
		base = "ATTENTION"
	case counts[string(finding.SeverityMedium)] > 0:
		base = "REVIEW"
	}
	if base != "GOOD" {
		return base
	}
	for _, g := range coverage {
		if g.Kind != scanner.GapNotApplicable {
			return "GOOD (partial)"
		}
	}
	return "GOOD"
}

func newScanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return "enki-" + hex.EncodeToString(b[:])
}
