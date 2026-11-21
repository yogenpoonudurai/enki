package scanner

import "testing"

func TestParseScope(t *testing.T) {
	for _, want := range []Scope{ScopeProject, ScopeHost, ScopeFull} {
		got, ok := ParseScope(string(want))
		if !ok || got != want {
			t.Fatalf("ParseScope(%q) = %q, %v", want, got, ok)
		}
	}
	if _, ok := ParseScope("everything"); ok {
		t.Fatal("invalid scope accepted")
	}
}

func TestScopeIncludes(t *testing.T) {
	if ScopeProject.IncludesHost() {
		t.Fatal("project scope must not include host surfaces")
	}
	if ScopeHost.IncludesProject() {
		t.Fatal("host scope must not include project surfaces")
	}
	if !ScopeFull.IncludesHost() || !ScopeFull.IncludesProject() {
		t.Fatal("full scope must include both surfaces")
	}
}
