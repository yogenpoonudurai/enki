package report

import (
	"strings"
	"testing"
)

func TestLogoArtLoaded(t *testing.T) {
	lines := LogoLines()
	if len(lines) < 40 {
		t.Fatalf("artwork has %d lines, expected the full piece", len(lines))
	}
	if w := LogoWidth(); w < 80 {
		t.Fatalf("artwork width = %d, expected > 80", w)
	}
	if strings.TrimSpace(lines[0]) == "" {
		t.Fatal("first artwork line is empty")
	}
}

func TestLogoGradient(t *testing.T) {
	plain := LogoGradient(false)
	if plain[0] != LogoLines()[0] {
		t.Fatal("plain artwork should be unchanged")
	}
	colored := LogoGradient(true)
	if !strings.Contains(colored[0], "\x1b[38;2;") {
		t.Fatal("colored artwork missing truecolor escapes")
	}
	if !strings.Contains(colored[len(colored)-1], "\x1b[38;2;230;57;70m") {
		t.Fatal("gradient did not reach the terminal red")
	}
}

func TestSmallLogo(t *testing.T) {
	lines := SmallLogoLines()
	if len(lines) == 0 {
		t.Fatal("compact artwork missing")
	}
	if len(lines) >= len(LogoLines()) {
		t.Fatalf("compact artwork (%d lines) should be smaller than full (%d)", len(lines), len(LogoLines()))
	}
	if SmallLogoWidth() > LogoWidth() {
		t.Fatal("compact artwork must not be wider than the full artwork")
	}
	// Braille cells are two dots wide and four tall; a visually square logo
	// therefore needs roughly two cells of width per cell of height.
	if w, h := SmallLogoWidth(), len(lines); w < 2*h-4 || w > 2*h+4 {
		t.Fatalf("compact artwork is not square: %dx%d cells", w, h)
	}
	if !strings.Contains(SmallLogoGradient(true)[0], "\x1b[38;2;") {
		t.Fatal("compact artwork gradient missing")
	}
}
