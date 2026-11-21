package report

import (
	_ "embed"
	"fmt"
	"strings"
	"unicode/utf8"
)

//go:embed logo.txt
var logoRaw string

//go:embed logo_small.txt
var logoSmallRaw string

var (
	logoLines      = splitArt(logoRaw)
	logoSmallLines = splitArt(logoSmallRaw)
)

func splitArt(raw string) []string {
	return strings.Split(strings.TrimRight(raw, "\n"), "\n")
}

// LogoLines returns the full-size enki artwork (enki banner).
func LogoLines() []string { return logoLines }

// LogoWidth returns the width of the widest full-size artwork line.
func LogoWidth() int { return artWidth(logoLines) }

// SmallLogoLines returns the downsampled artwork used in the TUI dashboard.
func SmallLogoLines() []string { return logoSmallLines }

// SmallLogoWidth returns the width of the widest compact artwork line.
func SmallLogoWidth() int { return artWidth(logoSmallLines) }

// LogoGradient renders the full-size artwork with a vertical amber→red
// gradient when color is enabled.
func LogoGradient(color bool) []string { return artGradient(logoLines, color) }

// SmallLogoGradient renders the compact artwork with the same gradient.
func SmallLogoGradient(color bool) []string { return artGradient(logoSmallLines, color) }

func artWidth(lines []string) int {
	w := 0
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > w {
			w = n
		}
	}
	return w
}

func artGradient(lines []string, color bool) []string {
	if !color {
		return lines
	}
	const (
		startR, startG, startB = 255, 179, 71
		endR, endG, endB       = 230, 57, 70
	)
	out := make([]string, len(lines))
	denom := len(lines) - 1
	for i, line := range lines {
		t := 0.0
		if denom > 0 {
			t = float64(i) / float64(denom)
		}
		r := startR + int(float64(endR-startR)*t)
		g := startG + int(float64(endG-startG)*t)
		b := startB + int(float64(endB-startB)*t)
		out[i] = fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", r, g, b, line)
	}
	return out
}
