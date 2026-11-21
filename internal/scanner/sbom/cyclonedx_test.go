package sbom

import (
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
)

func TestBuildCycloneDX(t *testing.T) {
	pkgs := []Pkg{
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Source: "/p/package-lock.json"},
		{Name: "openssl", Version: "1:3.0.11-1~deb12u2", Ecosystem: "Debian:12", Source: "dpkg"},
		{Name: "@scope/pkg", Version: "2.0.0", Ecosystem: "npm", Dev: true},
	}
	vulns := map[string][]*Advisory{
		PkgRef(pkgs[0]): {{
			ID: "GHSA-1", Summary: "proto pollution", Severity: finding.SeverityHigh, CVSS: 8.8,
			Aliases: []string{"CVE-2020-1234"},
		}},
		PkgRef(pkgs[1]): {{
			ID: "DSA-1", Severity: finding.SeverityMedium,
		}},
	}
	bom := BuildCycloneDX(pkgs, "test", vulns)

	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" || bom.Version != 1 {
		t.Fatalf("bom header = %+v", bom)
	}
	if len(bom.Components) != 3 {
		t.Fatalf("components = %d", len(bom.Components))
	}
	byName := map[string]CdxComponent{}
	for _, c := range bom.Components {
		byName[c.Name] = c
	}
	if byName["lodash"].Purl != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("lodash purl = %q", byName["lodash"].Purl)
	}
	if byName["openssl"].Type != "operating-system" {
		t.Fatalf("openssl type = %q", byName["openssl"].Type)
	}
	if byName["@scope/pkg"].Scope != "optional" {
		t.Fatalf("dev package scope = %q", byName["@scope/pkg"].Scope)
	}
	if len(bom.Vulnerabilities) != 2 {
		t.Fatalf("vulnerabilities = %d", len(bom.Vulnerabilities))
	}
	for _, v := range bom.Vulnerabilities {
		if len(v.Affects) != 1 {
			t.Fatalf("vuln %s affects = %+v", v.ID, v.Affects)
		}
	}
	if bom.SerialNumber == "" {
		t.Fatal("missing serial number")
	}
}

func TestBuildCycloneDXWithoutVulns(t *testing.T) {
	bom := BuildCycloneDX([]Pkg{{Name: "x", Version: "1.0.0", Ecosystem: "PyPI"}}, "test", nil)
	if len(bom.Vulnerabilities) != 0 {
		t.Fatalf("unexpected vulnerabilities: %+v", bom.Vulnerabilities)
	}
}
