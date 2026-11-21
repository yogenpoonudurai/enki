// Package remediate plans and applies guarded, reversible fixes for findings.
// Safe actions (chmod) apply directly; moderate actions (config edits) require
// explicit approval; risky actions are surfaced as commands for the operator.
package remediate

import (
	"fmt"
	"sort"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/report"
)

// Action is a single machine-executable remediation derived from a finding.
type Action struct {
	FindingID string              `json:"finding_id"`
	RuleID    string              `json:"rule_id"`
	Class     finding.ActionClass `json:"class"`
	Kind      string              `json:"kind"` // chmod_private | remove_json_key | "" (manual)
	Summary   string              `json:"summary"`
	Path      string              `json:"path,omitempty"`
	KeyPath   string              `json:"key_path,omitempty"`
	Mode      string              `json:"mode,omitempty"`
	Command   string              `json:"command,omitempty"`
	Guidance  string              `json:"guidance,omitempty"`
	Auto      bool                `json:"auto"`
}

// Result reports the outcome of applying one action.
type Result struct {
	Action  Action `json:"action"`
	Applied bool   `json:"applied"`
	Skipped bool   `json:"skipped"`
	Reason  string `json:"reason,omitempty"`
	Backup  string `json:"backup,omitempty"`
}

// BuildPlan extracts and deduplicates remediation actions from a report.
func BuildPlan(rep *report.Report) []Action {
	seen := map[string]bool{}
	var actions []Action
	for _, f := range rep.Findings {
		rm := f.Remediation
		if rm == nil {
			continue
		}
		a := Action{
			FindingID: f.ID,
			RuleID:    f.RuleID,
			Class:     rm.Class,
			Kind:      rm.Action,
			Summary:   rm.Summary,
			Path:      rm.Params["path"],
			KeyPath:   rm.Params["key_path"],
			Mode:      rm.Params["mode"],
			Command:   rm.Command,
			Guidance:  rm.Guidance,
		}
		switch a.Kind {
		case "chmod_private", "remove_json_key":
			a.Auto = true
		}
		if a.Mode == "" {
			a.Mode = "0600"
		}
		key := a.Kind + "|" + a.Path + "|" + a.KeyPath + "|" + a.Command
		if seen[key] {
			continue
		}
		seen[key] = true
		actions = append(actions, a)
	}
	sort.SliceStable(actions, func(i, j int) bool {
		if classRank(actions[i].Class) != classRank(actions[j].Class) {
			return classRank(actions[i].Class) < classRank(actions[j].Class)
		}
		return actions[i].Path < actions[j].Path
	})
	return actions
}

func classRank(c finding.ActionClass) int {
	switch c {
	case finding.ActionSafe:
		return 0
	case finding.ActionModerate:
		return 1
	default:
		return 2
	}
}

// DisplayClass is the label shown in plans: GUIDANCE when enki cannot apply
// the action itself, otherwise the remediation class.
func DisplayClass(a Action) string {
	if !a.Auto {
		return "GUIDANCE"
	}
	return upper(string(a.Class))
}

// Describe renders a one-line plan entry, e.g.
// "[1] SAFE     chmod 0600 ~/.env                              SEC-001".
func Describe(i int, a Action) string {
	class := DisplayClass(a)
	target := a.Summary
	if a.Kind == "chmod_private" && a.Path != "" {
		target = fmt.Sprintf("chmod %s %s", a.Mode, a.Path)
	} else if a.Kind == "remove_json_key" && a.Path != "" {
		target = fmt.Sprintf("remove %s from %s", a.KeyPath, a.Path)
	}
	return fmt.Sprintf("[%d] %-8s %s  ·  %s", i+1, class, target, a.RuleID)
}

func upper(s string) string {
	if s == "" {
		return ""
	}
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 32
		}
	}
	return string(b)
}
