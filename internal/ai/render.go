package ai

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/report"
)

type findingMeta struct {
	severity    string
	title       string
	remediation string
	guidance    string
	fix         string
}

// WriteHuman renders a customer-facing triage plan: ranked findings, numbered
// fix steps, and an explicit verified/unverified action label.
func WriteHuman(w io.Writer, result *TriageResult, rep *report.Report) {
	model := result.Cost.Model
	if model == "" {
		model = "unknown model"
	}
	fmt.Fprintf(w, "enki triage · %s\n", model)
	fmt.Fprintf(w, "%s · score %d · %d finding(s) reviewed\n\n",
		rep.Summary.Verdict, rep.Summary.Score, result.FindingsSent)

	if result.Summary != "" {
		fmt.Fprintln(w, result.Summary)
		fmt.Fprintln(w)
	}

	meta := make(map[string]findingMeta, len(rep.Findings))
	for _, f := range rep.Findings {
		m := findingMeta{severity: string(f.Severity), title: f.Title}
		if f.Remediation != nil {
			m.remediation = f.Remediation.Summary
			m.guidance = f.Remediation.Guidance
			m.fix = remediationCommand(f.Remediation)
		}
		meta[f.ID] = m
	}

	if len(result.Top) == 0 {
		fmt.Fprintln(w, "No prioritized items were returned. Review the full report before making changes.")
		fmt.Fprintln(w)
	}

	for i, item := range result.Top {
		m := meta[item.FindingID]
		severity := strings.ToUpper(m.severity)
		if severity == "" {
			severity = "INFO"
		}
		title := m.title
		if title == "" {
			title = item.RuleID
		}
		fmt.Fprintf(w, "%d. [%s] %s — %s\n", i+1, severity, item.RuleID, title)
		if item.Why != "" {
			fmt.Fprintf(w, "   Why: %s\n", item.Why)
		}
		if m.fix != "" {
			fmt.Fprintf(w, "   enki fix (authoritative): %s\n", m.fix)
		} else if m.remediation != "" {
			fmt.Fprintf(w, "   enki remediation (authoritative): %s\n", m.remediation)
		}
		if m.guidance != "" {
			fmt.Fprintf(w, "   enki guidance: %s\n", m.guidance)
		}
		if len(item.FixSteps) == 0 {
			fmt.Fprintln(w, "   AI-suggested steps: none returned — use the remediation above or review this finding manually.")
		} else {
			fmt.Fprintln(w, "   AI-suggested steps (verify before running):")
			for j, step := range item.FixSteps {
				fmt.Fprintf(w, "     %d. %s\n", j+1, step)
			}
		}
		fmt.Fprintf(w, "   Action: %s\n\n", actionLabel(item))
	}

	if result.Omitted > 0 {
		var parts []string
		for rule, count := range result.OmittedRules {
			parts = append(parts, fmt.Sprintf("%s ×%d", rule, count))
		}
		sort.Strings(parts)
		if len(parts) > 0 {
			fmt.Fprintf(w, "Note: %d finding(s) were not reviewed (%s).\n",
				result.Omitted, strings.Join(parts, ", "))
		} else {
			fmt.Fprintf(w, "Note: %d finding(s) were not reviewed.\n", result.Omitted)
		}
	}

	switch {
	case result.Cost.Hosted && result.Cost.USD > 0:
		fmt.Fprintf(w, "Cost: ~$%.4f (BYOK, %d in / %d out, %s)\n",
			result.Cost.USD, result.Cost.InputTokens, result.Cost.OutputTokens, model)
	case result.Cost.Hosted:
		fmt.Fprintf(w, "Cost: included in your hosted plan (%d in / %d out)\n",
			result.Cost.InputTokens, result.Cost.OutputTokens)
	case result.Cost.Metered:
		fmt.Fprintf(w, "Cost: ~$%.4f (%d in / %d out, %s)\n",
			result.Cost.USD, result.Cost.InputTokens, result.Cost.OutputTokens, model)
	default:
		fmt.Fprintf(w, "Cost: none · self-hosted/unmetered (%d in / %d out)\n",
			result.Cost.InputTokens, result.Cost.OutputTokens)
	}
	fmt.Fprintln(w, "AI advice only — verify each command before running it. enki never executes model output.")
}

func remediationCommand(rm *finding.Remediation) string {
	switch rm.Action {
	case "chmod_private":
		path := rm.Params["path"]
		if path == "" {
			return ""
		}
		mode := rm.Params["mode"]
		if mode == "" {
			mode = "0600"
		}
		return fmt.Sprintf("chmod %s %s", mode, shellQuote(path))
	case "remove_json_key":
		path, key := rm.Params["path"], rm.Params["key_path"]
		if path == "" || key == "" {
			return ""
		}
		return fmt.Sprintf("remove key %q from %s", key, shellQuote(path))
	}
	return ""
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func actionLabel(item TriageItem) string {
	switch {
	case item.RecommendedAction == "":
		return "manual review (no model action proposed)"
	case item.ActionVerified && item.RecommendedAction == "manual":
		return "manual review (verified)"
	case item.ActionVerified:
		return item.RecommendedAction + " (verified enki action)"
	default:
		return item.RecommendedAction + " — NOT VERIFIED; use the fix steps above manually, enki will not run it"
	}
}
