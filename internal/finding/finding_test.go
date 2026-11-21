package finding

import (
	"strings"
	"testing"
)

func TestSeverityOrder(t *testing.T) {
	order := []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for i := 1; i < len(order); i++ {
		if order[i].Order() <= order[i-1].Order() {
			t.Fatalf("%s should rank above %s", order[i], order[i-1])
		}
	}
	if _, ok := ParseSeverity("bogus"); ok {
		t.Fatal("bogus severity accepted")
	}
	if s, ok := ParseSeverity("crit"); !ok || s != SeverityCritical {
		t.Fatalf("crit = %s, %v", s, ok)
	}
}

func TestRedactSecret(t *testing.T) {
	if got := RedactSecret("sk-proj-1234567890abcdef"); got != "sk-p…cdef" {
		t.Fatalf("redact = %q", got)
	}
	if got := RedactSecret("short"); got != "****" {
		t.Fatalf("short redact = %q", got)
	}
}

func TestSecretFingerprintStable(t *testing.T) {
	a := SecretFingerprint("same-value")
	b := SecretFingerprint("same-value")
	if a != b || len(a) != 8 {
		t.Fatalf("fingerprints = %q, %q", a, b)
	}
	if strings.Contains(a, "same") {
		t.Fatal("fingerprint leaks plaintext")
	}
}

func TestInstanceIDsAreUniqueAndStable(t *testing.T) {
	a := New("AEP-001", "m", "t", "d", SeverityHigh, ConfidenceHigh, Location{Addr: "1.2.3.4:1"})
	b := New("AEP-001", "m", "t", "d", SeverityHigh, ConfidenceHigh, Location{Addr: "1.2.3.4:1"})
	c := New("AEP-001", "m", "t", "d", SeverityHigh, ConfidenceHigh, Location{Addr: "1.2.3.4:2"})
	if a.ID != b.ID {
		t.Fatal("identical findings should share an ID")
	}
	if a.ID == c.ID {
		t.Fatal("different locations must produce different IDs")
	}
	d := New("SEC-001", "m", "t", "d", SeverityHigh, ConfidenceHigh, Location{Path: "/x", Line: 1})
	e := New("SEC-001", "m", "t", "d", SeverityHigh, ConfidenceHigh, Location{Path: "/x", Line: 2})
	if d.ID == e.ID {
		t.Fatal("same-rule findings on different lines must produce different IDs")
	}
}

func TestSort(t *testing.T) {
	fs := []Finding{
		{RuleID: "B", Severity: SeverityLow},
		{RuleID: "A", Severity: SeverityCritical},
		{RuleID: "C", Severity: SeverityMedium},
	}
	Sort(fs)
	if fs[0].Severity != SeverityCritical || fs[2].Severity != SeverityLow {
		t.Fatalf("sort order = %+v", fs)
	}
}
