// Package plain renders scan results as CI-friendly text (no cursor control).
package plain

import (
	"fmt"
	"io"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/report"
)

// Write renders the report as plain lines, optionally with ANSI colors.
func Write(w io.Writer, rep *report.Report, color bool) {
	fmt.Fprintf(w, "%s %s · %s\n", report.Bold(color, "enki"), rep.Tool.Version, report.Dim(color, "AI Security Posture"))
	fmt.Fprintf(w, "%s · %s/%s · %s · scope %s\n\n", rep.Scan.Host, rep.Scan.OS, rep.Scan.Arch, rep.Scan.User, scopeOrFull(rep.Scan.Scope))

	counts := rep.Summary.Counts
	fmt.Fprintf(w, "POSTURE %d/100 · %s · %s\n\n",
		rep.Summary.Score,
		report.Bold(color, rep.Summary.Verdict),
		fmt.Sprintf("%d critical, %d high, %d medium, %d low, %d info",
			counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"]))

	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
	} else {
		for _, f := range report.CollapseSBOM(rep.Findings) {
			sev := report.Paint(color, f.Severity, fmt.Sprintf("%-8s", f.Severity))
			loc := f.Location.String()
			if loc != "" {
				loc = "  " + report.Dim(color, loc)
			}
			fmt.Fprintf(w, "%s %-8s %s%s\n", sev, f.RuleID, f.Title, loc)
			if f.Evidence != "" {
				fmt.Fprintf(w, "         %s\n", report.Dim(color, f.Evidence))
			}
			if f.Remediation != nil {
				fmt.Fprintf(w, "         %s %s\n", report.Dim(color, "fix ("+string(f.Remediation.Class)+"):"), f.Remediation.Summary)
			}
		}
	}

	if len(rep.Coverage) > 0 {
		fmt.Fprintln(w, "\nCoverage gaps (results may be incomplete):")
		for _, g := range rep.Coverage {
			kind := g.Kind
			if kind == "" {
				kind = "unknown"
			}
			fmt.Fprintf(w, "  note [%s/%s] %s\n", g.Module, kind, g.Reason)
		}
	}

	for _, m := range rep.Modules {
		if m.Skipped {
			fmt.Fprintf(w, "\n  skipped [%s] not applicable in this scope\n", m.Name)
		}
		if m.Error != "" {
			fmt.Fprintf(w, "\n  error [%s] %s\n", m.Name, m.Error)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, report.Dim(color, "Review remediations with: enki fix"))
}

func scopeOrFull(scope string) string {
	if scope == "" {
		return "full"
	}
	return scope
}

// SeverityAtOrAbove reports whether any finding meets the threshold.
func SeverityAtOrAbove(rep *report.Report, threshold finding.Severity) bool {
	for _, f := range rep.Findings {
		if f.Severity.Order() >= threshold.Order() {
			return true
		}
	}
	return false
}
