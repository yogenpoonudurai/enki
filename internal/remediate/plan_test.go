package remediate

import "testing"

func TestDisplayClass(t *testing.T) {
	if got := DisplayClass(Action{Class: "moderate", Auto: false}); got != "GUIDANCE" {
		t.Fatalf("guidance label = %q", got)
	}
	if got := DisplayClass(Action{Class: "safe", Auto: true}); got != "SAFE" {
		t.Fatalf("safe label = %q", got)
	}
	if got := DisplayClass(Action{Class: "moderate", Auto: true}); got != "MODERATE" {
		t.Fatalf("moderate label = %q", got)
	}
}
