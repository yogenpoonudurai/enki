package platform

import (
	"os"

	"golang.org/x/term"
)

// Interactive reports whether enki should use the rich TUI. It is false in
// CI, when NO_COLOR is set, under TERM=dumb, or when stdio is not a terminal.
func Interactive() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("CI") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stdin.Fd()))
}

// ColorEnabled reports whether ANSI color should be emitted on stdout.
func ColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" || !term.IsTerminal(int(os.Stdout.Fd())) {
		return false
	}
	return true
}
