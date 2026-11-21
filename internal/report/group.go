package report

import (
	"fmt"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/finding"
)

// CollapseSBOM groups SBOM-001 findings by package for human-readable
// rendering. JSON/SARIF/OCSF continue to carry one finding per advisory.
func CollapseSBOM(fs []finding.Finding) []finding.Finding {
	var out []finding.Finding
	groups := map[string][]finding.Finding{}
	var order []string
	for _, f := range fs {
		if f.RuleID != "SBOM-001" {
			out = append(out, f)
			continue
		}
		key := tagValue(f, "pkg:")
		if key == "" {
			out = append(out, f)
			continue
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], f)
	}
	for _, key := range order {
		group := groups[key]
		if len(group) == 1 {
			out = append(out, group[0])
			continue
		}
		out = append(out, collapseGroup(key, group))
	}
	finding.Sort(out)
	return out
}

func tagValue(f finding.Finding, prefix string) string {
	for _, t := range f.Tags {
		if strings.HasPrefix(t, prefix) {
			return strings.TrimPrefix(t, prefix)
		}
	}
	return ""
}

func collapseGroup(tag string, group []finding.Finding) finding.Finding {
	pkg := strings.TrimPrefix(tag, "pkg:")
	counts := map[finding.Severity]int{}
	maxSev := finding.SeverityInfo
	var top []string
	for _, f := range group {
		counts[f.Severity]++
		if f.Severity.Order() > maxSev.Order() {
			maxSev = f.Severity
		}
		if id := tagValue(f, "advisory:"); id != "" && len(top) < 3 {
			top = append(top, id)
		}
	}

	first := group[0]
	f := finding.New("SBOM-001", first.Module,
		fmt.Sprintf("%s — %d advisories", pkg, len(group)),
		fmt.Sprintf("%d known advisories affect %s. Each advisory is reported individually in JSON/SARIF output.", len(group), pkg),
		maxSev, finding.ConfidenceHigh, first.Location)
	f.Evidence = fmt.Sprintf("%d critical, %d high, %d medium, %d low, %d info",
		counts[finding.SeverityCritical], counts[finding.SeverityHigh], counts[finding.SeverityMedium],
		counts[finding.SeverityLow], counts[finding.SeverityInfo])
	if len(top) > 0 {
		f.Evidence += " · top: " + strings.Join(top, ", ")
	}
	f.Tags = append([]string{"sbom", "grouped"}, first.Tags...)
	f.Remediation = first.Remediation
	return f
}
