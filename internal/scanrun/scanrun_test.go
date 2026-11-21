package scanrun

import (
	"testing"

	"github.com/yogenpoonudurai/enki/internal/scanner"
)

func TestScopeGaps(t *testing.T) {
	project := scopeGaps(scanner.ScopeProject)
	if len(project) == 0 {
		t.Fatal("project scope must report unchecked host surfaces")
	}
	for _, g := range project {
		if g.Kind != scanner.GapNotApplicable || g.Scope != "host" {
			t.Fatalf("project gap = %+v, want not-applicable host gap", g)
		}
	}
	host := scopeGaps(scanner.ScopeHost)
	if len(host) == 0 {
		t.Fatal("host scope must report unchecked project surfaces")
	}
	for _, g := range host {
		if g.Kind != scanner.GapNotApplicable || g.Scope != "project" {
			t.Fatalf("host gap = %+v, want not-applicable project gap", g)
		}
	}
	if got := scopeGaps(scanner.ScopeFull); len(got) != 0 {
		t.Fatalf("full scope gaps = %+v, want none", got)
	}
}

func TestSBOBOptionsByScope(t *testing.T) {
	project := sbomOptions(Options{Scope: scanner.ScopeProject, OSPackages: true, Paths: []string{"/repo"}})
	if project.OSPackages {
		t.Fatal("project scope must not inventory OS packages")
	}

	host := sbomOptions(Options{Scope: scanner.ScopeHost, OSPackages: true, Paths: []string{"/repo"}})
	if !host.NoProject || host.Roots != nil {
		t.Fatalf("host sbom options = %+v, want NoProject and no roots", host)
	}
	if !host.OSPackages {
		t.Fatal("host scope should keep OS package inventory")
	}

	full := sbomOptions(Options{Scope: scanner.ScopeFull, OSPackages: true, Paths: []string{"/repo"}})
	if full.NoProject {
		t.Fatal("full scope must include project manifests")
	}
}

func TestOptionsNormalizeToAIAndFull(t *testing.T) {
	o := Options{}.normalized()
	if o.Deps != "ai" {
		t.Fatalf("default deps = %q, want ai", o.Deps)
	}
	if o.Scope != scanner.ScopeFull {
		t.Fatalf("default scope = %q, want full", o.Scope)
	}
}
