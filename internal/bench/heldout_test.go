//go:build realworld

package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yogenpoonudurai/enki/internal/rules"
)

type heldoutMismatch struct {
	Case, Rule, Source string
	Expected, Actual   int
}

func TestHeldOutBenchmark(t *testing.T) {
	if !*liveOSV {
		t.Fatal("held-out benchmark requires -live-osv")
	}
	m := loadManifest(t, filepath.Join("testdata", "heldout.json"))
	if len(m.Cases) < 100 {
		t.Fatalf("held-out corpus has %d cases, need at least 100", len(m.Cases))
	}

	stats := map[string]*rwStat{}
	var failures []string
	var mismatches []heldoutMismatch
	for _, c := range m.Cases {
		if c.Name == "" || c.Module == "" || len(c.Evaluate) == 0 {
			failures = append(failures, "case with empty name/module/evaluate")
			continue
		}
		expected := map[string]int{}
		presence := map[string]bool{}
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
			if l.Presence {
				presence[l.RuleID] = true
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
			if presence[ruleID] {
				exp = boolInt(exp > 0)
				act = boolInt(act > 0)
			}
			tp := minInt(exp, act)
			fp := maxInt(0, act-exp)
			fn := maxInt(0, exp-act)
			s := stats[ruleID]
			if s == nil {
				s = &rwStat{}
				stats[ruleID] = s
			}
			if exp > 0 {
				s.PosCases++
			} else {
				s.NegCases++
			}
			s.TP += tp
			s.FP += fp
			s.FN += fn
			if exp != act {
				source := c.Source.LocalPath
				if c.Source.Repo != "" {
					source = c.Source.Repo + "@" + shortCommit(c.Source.Commit) + ":" + c.Source.Path
				}
				mismatches = append(mismatches, heldoutMismatch{Case: c.Name, Rule: ruleID, Source: source, Expected: exp, Actual: act})
			}
		}
	}
	if len(failures) > 0 {
		for _, f := range failures {
			t.Errorf("%s", f)
		}
		t.Fatalf("%d held-out benchmark failure(s)", len(failures))
	}

	got := rwBaseline{Categories: map[string]map[string]rwStat{"heldout": {}}}
	for id, s := range stats {
		got.Categories["heldout"][id] = *s
	}

	baselinePath := filepath.Join("testdata", "heldout-baseline.json")
	docPath := filepath.Join("..", "..", "docs", "benchmark-heldout.md")
	if *update {
		writeJSON(t, baselinePath, got)
		writeHeldOutDocs(t, docPath, m, got, mismatches, time.Now().UTC().Format("2006-01-02"))
		t.Logf("updated %s and %s", baselinePath, docPath)
		return
	}

	raw, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("read held-out baseline: %v (run make bench-heldout-update)", err)
	}
	var want rwBaseline
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("parse held-out baseline: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("held-out baseline drift; live OSV data may have changed; run make bench-heldout-update\n got: %+v\nwant: %+v", got, want)
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func writeHeldOutDocs(t *testing.T, path string, m manifest, b rwBaseline, mismatches []heldoutMismatch, generated string) {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("# Held-out real-world detection benchmark (live OSV)\n\n")
	sb.WriteString(fmt.Sprintf("Generated on **%s** from `internal/bench/testdata/heldout.json` with live OSV advisory data. Do not edit by hand; run `make bench-heldout-update`.\n\n", generated))
	sb.WriteString("> **Held out:** these cases were sourced and labeled after detector tuning and were not used to change detection rules. Results are published as measured, including any false positives and false negatives.\n\n")

	sb.WriteString("## Method\n\n")
	sb.WriteString("- The corpus contains at least 100 public-source cases from pinned public repositories plus public npm registry lockfiles. Source integrity uses 16-hex SHA256 prefixes to avoid secret-scanner false positives; upstream commits are pinned.\n")
	sb.WriteString("- Labels are produced by an independent corpus builder, not by enki's detectors. MCP/agent/model/env labels use explicit ground-truth parsers; SBOM labels use live OSV queries.\n")
	sb.WriteString("- Public files are fetched at pinned commits and verified by a pinned SHA256 prefix; they are not redistributed.\n")
	sb.WriteString("- Secret-like files and positive secret cases are excluded from the public corpus to avoid handling live credentials; secret detection remains covered by controlled fixtures.\n")
	sb.WriteString("- Scoring is per-rule case precision/recall. SBOM-001 uses presence (any advisory vs none); other rules use expected/actual finding counts.\n\n")

	sb.WriteString("## Corpus composition\n\n")
	byModule := map[string]int{}
	for _, c := range m.Cases {
		byModule[c.Module]++
	}
	sb.WriteString("| Module | Cases |\n|---|---:|\n")
	for _, module := range ruleModules() {
		if byModule[module] > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", module, byModule[module]))
		}
	}
	sb.WriteString(fmt.Sprintf("\nTotal held-out cases: **%d**. Source manifest: `internal/bench/testdata/heldout.json`.\n\n", len(m.Cases)))

	sb.WriteString("## Per-rule results\n\n")
	sb.WriteString("| Rule | Module | Pos/neg | TP | FP | FN | Precision | Recall | F1 |\n|---|---|---:|---:|---:|---:|---:|---:|---:|\n")
	moduleByRule := map[string]string{}
	for _, r := range rules.Catalog {
		moduleByRule[r.ID] = r.Module
	}
	for _, r := range rules.Catalog {
		s := b.Categories["heldout"][r.ID]
		sb.WriteString(fmt.Sprintf("| %s | %s | %d/%d | %d | %d | %d | %s | %s | %s |\n",
			r.ID, moduleByRule[r.ID], s.PosCases, s.NegCases, s.TP, s.FP, s.FN,
			pct(s.TP, s.TP+s.FP), pct(s.TP, s.TP+s.FN), f1(s)))
	}

	sb.WriteString("\n## Label corrections during the held-out build\n\n")
	sb.WriteString("- `uv run` was initially treated as an unpinned `uvx` launch; the rule scope is npx/uvx, so that label was removed.\n")
	sb.WriteString("- AGT and MDL findings are emitted once per config/file; labels now use the same finding granularity (for example, multiple Bash entries or torch.load calls count as one finding).\n")
	sb.WriteString("- These corrections were made only in the independent corpus labeler. No detector code was changed based on held-out results.\n")
	sb.WriteString("- The corpus is disjoint from the development public cases, including the lodash SBOM pairs used there.\n")

	sb.WriteString("\n## Case-level mismatches\n\n")
	if len(mismatches) == 0 {
		sb.WriteString("No expected/actual count mismatches in this run.\n")
	} else {
		sb.WriteString("| Case | Rule | Source | Expected | Actual |\n|---|---|---|---:|---:|\n")
		for _, x := range mismatches {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %d |\n", x.Case, x.Rule, x.Source, x.Expected, x.Actual))
		}
	}

	sb.WriteString("\n## Limitations\n\n")
	sb.WriteString("- The corpus is selected from public search results and may not be representative of the ecosystem; it is a held-out set, not a random sample.\n")
	sb.WriteString("- Labels are produced by independent parsers and OSV; parser ambiguities and upstream updates can create label noise.\n")
	sb.WriteString("- Scoring is count-based for most rules and presence-based for SBOM; exact location matching is not implemented.\n")
	sb.WriteString("- Host exposure and positive secret cases remain controlled; this report does not measure runtime exposure in the wild.\n")
	sb.WriteString("- Live OSV results are a snapshot and can change as advisories are published or withdrawn.\n\n")

	sb.WriteString("## Reproduce\n\n")
	sb.WriteString("```bash\n")
	sb.WriteString("make bench-heldout\n")
	sb.WriteString("make bench-heldout-update\n")
	sb.WriteString("```\n\n")
	sb.WriteString("Baseline: `internal/bench/testdata/heldout-baseline.json`.\n")

	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func ruleModules() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rules.Catalog {
		if !seen[r.Module] {
			seen[r.Module] = true
			out = append(out, r.Module)
		}
	}
	return out
}
