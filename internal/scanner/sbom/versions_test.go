package sbom

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.6.0", "2.2.0", 1},
		{"2.2.0", "2.6.0", -1},
		{"2.6.0", "2.6.0", 0},
		{"v2.6.0", "2.6.0", 0},
		{"2.10.0", "2.9.1", 1},
		{"2.7.1", "2.7.1-rc1", 1},
		{"1.0", "1.0.0", 0},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestMaxFixedVersion(t *testing.T) {
	got := maxFixedVersion([]string{"2.2.0", "2.6.0", "deadbeefcafe", "2.10.0"})
	if got != "2.10.0" {
		t.Fatalf("maxFixedVersion = %q", got)
	}
	if maxFixedVersion([]string{"deadbeef"}) != "" {
		t.Fatal("commit hashes must be ignored")
	}
}

func TestUpgradeCommandPerEcosystem(t *testing.T) {
	cases := []struct {
		pkg     Pkg
		fixed   string
		manager string
		needle  string
	}{
		{Pkg{Name: "torch", Version: "2.0.1", Ecosystem: "PyPI"}, "2.6.0", "pip", ">=2.6.0"},
		{Pkg{Name: "lodash", Version: "4.17.20", Ecosystem: "npm"}, "4.17.21", "npm", "lodash@4.17.21"},
		{Pkg{Name: "github.com/x/y", Version: "v1.0.0", Ecosystem: "Go"}, "v1.2.3", "go", "go get"},
		{Pkg{Name: "serde", Version: "1.0.0", Ecosystem: "crates.io"}, "1.0.1", "cargo", "--precise"},
		{Pkg{Name: "Serilog", Version: "2.0.0", Ecosystem: "NuGet"}, "2.12.0", "dotnet", "dotnet add package"},
		{Pkg{Name: "openssl", Version: "1:3.0", Ecosystem: "Debian:12"}, "1:3.0.11-1~deb12u2", "apt-get", "apt-get"},
	}
	for _, tc := range cases {
		manager, cmd, ok := upgradeCommand(tc.pkg, tc.fixed)
		if !ok || manager != tc.manager || !strings.Contains(cmd, tc.needle) {
			t.Errorf("%s: manager=%q cmd=%q ok=%v", tc.pkg.Ecosystem, manager, cmd, ok)
		}
	}
	if _, _, ok := upgradeCommand(Pkg{Ecosystem: "OS"}, "1.0"); ok {
		t.Fatal("unsupported ecosystem should not get a command")
	}
}

func TestFindingCarriesUpgradeCommand(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("torch==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fakeClient{
		ids: map[string][]string{"torch@2.0.1": {"GHSA-1", "GHSA-2"}},
		adv: map[string]*Advisory{
			"GHSA-1": {ID: "GHSA-1", Severity: finding.SeverityHigh, Fixed: []string{"2.2.0"}},
			"GHSA-2": {ID: "GHSA-2", Severity: finding.SeverityMedium, Fixed: []string{"2.6.0"}},
		},
	}
	opts := DefaultOptions()
	opts.OSPackages = false
	sc := &scanner.Context{Ctx: context.Background(), WorkingDir: dir}
	fs, _, err := NewWithClient(opts, fake).Run(sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("findings = %d", len(fs))
	}
	for _, f := range fs {
		rm := f.Remediation
		if rm == nil || rm.Class != finding.ActionRisky {
			t.Fatalf("remediation = %+v", rm)
		}
		if !strings.Contains(rm.Summary, "2.6.0") {
			t.Fatalf("summary should use the highest fixed version: %q", rm.Summary)
		}
		if !strings.Contains(rm.Command, "pip install") || !strings.Contains(rm.Command, "2.6.0") {
			t.Fatalf("command = %q", rm.Command)
		}
		if rm.Params["manager"] != "pip" || rm.Params["fixed"] != "2.6.0" {
			t.Fatalf("params = %+v", rm.Params)
		}
	}
}
