//go:build realworld

package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/rules"
)

type rwStat struct {
	PosCases int `json:"pos_cases"`
	NegCases int `json:"neg_cases"`
	TP       int `json:"tp"`
	FP       int `json:"fp"`
	FN       int `json:"fn"`
}

type rwBaseline struct {
	Categories map[string]map[string]rwStat `json:"categories"`
}

func TestRealWorldBenchmark(t *testing.T) {
	controlled := loadManifest(t, filepath.Join("testdata", "cases.json"))
	for i := range controlled.Cases {
		c := &controlled.Cases[i]
		c.Category = "controlled"
		c.Evaluate = []string{c.Rule}
		if c.Type == "positive" {
			c.Labels = []labelSpec{{RuleID: c.Rule, Count: 1}}
		} else {
			c.Labels = nil
		}
	}
	public := loadManifest(t, filepath.Join("testdata", "realworld.json"))

	all := append(append([]benchCase{}, controlled.Cases...), public.Cases...)
	stats := map[string]map[string]*rwStat{
		"controlled": {},
		"public":     {},
		"combined":   {},
	}

	var failures []string
	for _, c := range all {
		if c.Name == "" || c.Module == "" || c.Category == "" {
			failures = append(failures, "case with empty name/module/category")
			continue
		}
		if len(c.Evaluate) == 0 {
			failures = append(failures, c.Name+": no evaluate rules")
			continue
		}
		expected := map[string]int{}
		for _, l := range c.Labels {
			if l.RuleID == "" {
				failures = append(failures, c.Name+": label with empty rule")
				continue
			}
			n := l.Count
			if n <= 0 {
				n = 1
			}
			expected[l.RuleID] += n
		}
		for id := range expected {
			if !contains(c.Evaluate, id) {
				failures = append(failures, fmt.Sprintf("%s: label %s not in evaluate list", c.Name, id))
			}
		}

		got, err := runCase(t, c)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", c.Name, err))
			continue
		}
		seen := map[string]bool{}
		for _, ruleID := range c.Evaluate {
			if seen[ruleID] {
				continue
			}
			seen[ruleID] = true
			exp := expected[ruleID]
			act := got[ruleID]
			tp := minInt(exp, act)
			fp := maxInt(0, act-exp)
			fn := maxInt(0, exp-act)
			for _, category := range []string{c.Category, "combined"} {
				s := stats[category][ruleID]
				if s == nil {
					s = &rwStat{}
					stats[category][ruleID] = s
				}
				if exp > 0 {
					s.PosCases++
				} else {
					s.NegCases++
				}
				s.TP += tp
				s.FP += fp
				s.FN += fn
			}
		}
	}
	if len(failures) > 0 {
		for _, f := range failures {
			t.Errorf("%s", f)
		}
		t.Fatalf("%d real-world benchmark failure(s)", len(failures))
	}

	got := rwBaseline{Categories: map[string]map[string]rwStat{}}
	for category, byRule := range stats {
		got.Categories[category] = map[string]rwStat{}
		for id, s := range byRule {
			got.Categories[category][id] = *s
		}
	}

	baselinePath := filepath.Join("testdata", "realworld-baseline.json")
	docPath := filepath.Join("..", "..", "docs", "benchmark-real-world.md")
	if *update {
		writeJSON(t, baselinePath, got)
		writeRealWorldDocs(t, docPath, controlled, public, got)
		t.Logf("updated %s and %s", baselinePath, docPath)
		return
	}

	raw, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("read baseline: %v (run make bench-real-world-update)", err)
	}
	var want rwBaseline
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("parse baseline: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("real-world benchmark baseline drift; run make bench-real-world-update\n got: %+v\nwant: %+v", got, want)
	}
}

func loadManifest(t *testing.T, path string) manifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func pct(num, den int) string {
	if den == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(num)/float64(den))
}

func f1(s rwStat) string {
	den := 2*s.TP + s.FP + s.FN
	if den == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f%%", 100*2*float64(s.TP)/float64(den))
}

func shortCommit(commit string) string {
	if len(commit) > 8 {
		return commit[:8]
	}
	return commit
}

func writeRealWorldDocs(t *testing.T, path string, controlled, public manifest, b rwBaseline) {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("# Real-world detection benchmark\n\n")
	sb.WriteString("Generated from `internal/bench/testdata/realworld.json` plus the controlled fixtures in `internal/bench/testdata/cases.json`. Do not edit by hand; run `make bench-real-world-update`.\n\n> **Preliminary:** this is a curated, non-random corpus. Use per-rule numbers as directional evidence, not ecosystem-wide accuracy.\n\n")

	sb.WriteString("## Method\n\n")
	sb.WriteString("- **Public-source cases** are pinned files from public repositories, fetched at a specific commit and verified by SHA256. They are not redistributed in this repository.\n")
	sb.WriteString("- **Controlled cases** are the controlled offline fixtures. Endpoint, secret-positive, and host cases are controlled so the benchmark never handles live credentials or exposed services.\n")
	sb.WriteString("- **SBOM cases** use real npm registry lockfiles; advisory data for lodash 4.17.20 is pinned in the harness so results are reproducible.\n")
	sb.WriteString("- Each label is an expected finding count for a rule in a case. TP = min(expected, actual), FP = extra actual findings, FN = missing expected findings. Only rules listed in the case's `evaluate` list are scored.\n")
	sb.WriteString("- Metrics are per-rule case precision and recall. They are **not** a random sample of the ecosystem and do not do location-level matching.\n\n")

	sb.WriteString("## Corpus\n\n")
	sb.WriteString(fmt.Sprintf("- Controlled cases: **%d** across %d rules\n", len(controlled.Cases), len(rules.Catalog)))
	sb.WriteString(fmt.Sprintf("- Public-source cases: **%d**\n", len(public.Cases)))
	sb.WriteString("- Public sources (pinned commit, SHA256 verified at runtime):\n\n")
	sb.WriteString("| Case | Source | Path | Evaluated rules | Notes |\n|---|---|---|---|---|\n")
	sources := append([]benchCase{}, public.Cases...)
	sort.Slice(sources, func(i, j int) bool { return sources[i].Name < sources[j].Name })
	for _, c := range sources {
		if c.Source == nil {
			continue
		}
		src := c.Source
		source := src.Repo
		if source != "" {
			source = fmt.Sprintf("[%s](https://github.com/%s)@`%s`", src.Repo, src.Repo, shortCommit(src.Commit))
		} else {
			source = "npm registry (generated lockfile)"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | `%s` | %s | %s |\n", c.Name, source, src.Path, strings.Join(c.Evaluate, ", "), c.Notes))
	}

	sb.WriteString("\n## Per-rule results (controlled + public)\n\n")
	sb.WriteString("| Rule | Module | Public pos/neg | Controlled pos/neg | TP | FP | FN | Precision | Recall | F1 |\n|---|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	moduleByRule := map[string]string{}
	for _, r := range rules.Catalog {
		moduleByRule[r.ID] = r.Module
	}
	for _, r := range rules.Catalog {
		s := b.Categories["combined"][r.ID]
		pub := b.Categories["public"][r.ID]
		ctl := b.Categories["controlled"][r.ID]
		sb.WriteString(fmt.Sprintf("| %s | %s | %d/%d | %d/%d | %d | %d | %d | %s | %s | %s |\n",
			r.ID, moduleByRule[r.ID], pub.PosCases, pub.NegCases, ctl.PosCases, ctl.NegCases,
			s.TP, s.FP, s.FN, pct(s.TP, s.TP+s.FP), pct(s.TP, s.TP+s.FN), f1(s)))
	}

	sb.WriteString("\n## Public-source results only\n\n")
	sb.WriteString("| Rule | Pos/neg cases | TP | FP | FN | Precision | Recall | F1 |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range rules.Catalog {
		s := b.Categories["public"][r.ID]
		if s.PosCases+s.NegCases == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("| %s | %d/%d | %d | %d | %d | %s | %s | %s |\n",
			r.ID, s.PosCases, s.NegCases, s.TP, s.FP, s.FN, pct(s.TP, s.TP+s.FP), pct(s.TP, s.TP+s.FN), f1(s)))
	}

	sb.WriteString("\nA separate blind, held-out review with live OSV data is published in [benchmark-heldout.md](benchmark-heldout.md).\n")

	sb.WriteString("\n## Findings from this corpus\n\n")
	sb.WriteString("- The IBM public MCP config exposed an MCP-003 false positive on placeholder values such as `YOUR_API_KEY` and `<APIKEY>`. The detector now ignores placeholder-shaped values, and `mcp-003-negative-long-placeholder` is a regression fixture. The results above reflect the fixed detector.\n")
	sb.WriteString("- The public cases add real repository evidence for MCP-001/002, AGT-001/002, MDL-002/003, SEC-001/003 negatives, and SBOM-001; other rules remain controlled.\n")

	sb.WriteString("\n## Limitations\n\n")
	sb.WriteString("- The corpus is curated, not a random sample; results are not a claim about ecosystem-wide prevalence.\n")
	sb.WriteString("- Scoring is count-based per case; it does not yet verify exact line/location matching.\n")
	sb.WriteString("- Public-source cases cover MCP, agent permissions, model code, secret-file negatives, and SBOM. Host exposure, secret positives, and some config rules remain controlled.\n")
	sb.WriteString("- SBOM results use a pinned advisory fixture, not live OSV data; rerun against live OSV separately for current advisory coverage.\n")
	sb.WriteString("- Public files can change upstream; the harness pins commits and verifies SHA256, and fails rather than silently using different content.\n\n")

	sb.WriteString("## Reproduce\n\n")
	sb.WriteString("```bash\n")
	sb.WriteString("make bench-real-world\n")
	sb.WriteString("make bench-real-world-update   # refresh baseline + this document\n")
	sb.WriteString("```\n\n")
	sb.WriteString("Baseline: `internal/bench/testdata/realworld-baseline.json`.\n")

	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
