package report

import "github.com/yogenpoonudurai/enki/internal/finding"

// ANSI SGR color codes for severities; empty when color is disabled.
func sevColor(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "\x1b[38;2;255;71;87m"
	case finding.SeverityHigh:
		return "\x1b[38;2;255;159;67m"
	case finding.SeverityMedium:
		return "\x1b[38;2;255;217;61m"
	case finding.SeverityLow:
		return "\x1b[38;2;77;171;247m"
	default:
		return "\x1b[38;2;173;181;189m"
	}
}

const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
)

// Paint wraps s in the severity color when color is enabled.
func Paint(color bool, s finding.Severity, text string) string {
	if !color {
		return text
	}
	return sevColor(s) + text + ansiReset
}

// Bold and Dim return styled text when color is enabled.
func Bold(color bool, s string) string {
	if !color {
		return s
	}
	return ansiBold + s + ansiReset
}

func Dim(color bool, s string) string {
	if !color {
		return s
	}
	return ansiDim + s + ansiReset
}

// GradientLines applies an amber→red truecolor gradient to banner lines.
func GradientLines(color bool, lines []string) []string {
	grad := []string{
		"\x1b[38;2;255;179;71m",
		"\x1b[38;2;255;159;67m",
		"\x1b[38;2;255;127;80m",
		"\x1b[38;2;255;71;87m",
		"\x1b[38;2;230;57;70m",
	}
	if !color {
		return lines
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		c := grad[len(grad)-1]
		if i < len(grad) {
			c = grad[i]
		}
		out[i] = c + l + ansiReset
	}
	return out
}
