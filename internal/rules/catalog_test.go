package rules

import (
	"strings"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
)

var modules = []string{"endpoint-exposure", "mcp", "secrets", "agent-permissions", "model-artifacts", "sbom"}

func TestCatalogValid(t *testing.T) {
	if problems := Validate(modules); len(problems) != 0 {
		t.Fatalf("catalog problems: %v", problems)
	}
}

func TestCatalogRejectsUnknownMetadata(t *testing.T) {
	orig := Catalog
	defer func() { Catalog = orig }()
	Catalog = append(append([]Rule{}, orig...), Rule{
		ID: "TST-001", Module: "mcp", Severity: "LOW", Title: "test",
		Category: finding.Category("mystery"), Basis: finding.Basis("vibes"),
	})
	problems := Validate(modules)
	if len(problems) != 2 {
		t.Fatalf("problems = %v", problems)
	}
	joined := strings.Join(problems, "; ")
	if !strings.Contains(joined, "invalid category") || !strings.Contains(joined, "invalid basis") {
		t.Fatalf("problems = %v", problems)
	}
}
