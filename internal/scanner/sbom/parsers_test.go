package sbom

import (
	"os"
	"path/filepath"
	"testing"
)

func pkgMap(ps []Pkg) map[string]string {
	m := map[string]string{}
	for _, p := range ps {
		m[p.Name] = p.Version
	}
	return m
}

func TestNpmLockV3(t *testing.T) {
	data := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "version": "1.0.0"},
	    "node_modules/lodash": {"version": "4.17.20"},
	    "node_modules/dev-tool": {"version": "1.2.3", "dev": true},
	    "node_modules/alias": {"version": "6.0.0", "name": "real-pkg"},
	    "node_modules/linked": {"version": "1.0.0", "link": true},
	    "node_modules/git-dep": {"version": "git+https://example.com/x.git"}
	  }
	}`)
	ps, skipped, err := parseNpmLock(data)
	if err != nil {
		t.Fatal(err)
	}
	got := pkgMap(ps)
	if got["lodash"] != "4.17.20" || got["real-pkg"] != "6.0.0" {
		t.Fatalf("packages = %+v", got)
	}
	if _, ok := got["alias"]; ok {
		t.Fatal("alias should resolve to the real package name")
	}
	if _, ok := got["linked"]; ok {
		t.Fatal("link entries must be skipped")
	}
	if skipped != 1 { // git version
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	for _, p := range ps {
		if p.Name == "dev-tool" && !p.Dev {
			t.Fatal("dev flag lost")
		}
		if p.Name == "lodash" && !p.Direct {
			t.Fatal("top-level package should be direct")
		}
	}
}

func TestNpmLockV1(t *testing.T) {
	data := []byte(`{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
	    "c": {"version": "3.0.0", "dev": true}
	  }
	}`)
	ps, _, err := parseNpmLock(data)
	if err != nil {
		t.Fatal(err)
	}
	got := pkgMap(ps)
	if got["a"] != "1.0.0" || got["b"] != "2.0.0" || got["c"] != "3.0.0" {
		t.Fatalf("packages = %+v", got)
	}
}

func TestYarnV1(t *testing.T) {
	data := []byte(`# yarn lockfile v1

"lodash@^4.17.0", "lodash@^4.17.20":
  version "4.17.20"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.20.tgz"

"alias@npm:real-pkg@^1.0.0":
  version "1.5.0"

"bad@file:../local":
  version "file:../local"
`)
	ps, skipped, err := parseYarnLock(data)
	if err != nil {
		t.Fatal(err)
	}
	got := pkgMap(ps)
	if got["lodash"] != "4.17.20" || got["real-pkg"] != "1.5.0" {
		t.Fatalf("packages = %+v", got)
	}
	if _, ok := got["alias"]; ok {
		t.Fatal("yarn alias should resolve to the real package")
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
}

func TestYarnBerry(t *testing.T) {
	data := []byte(`__metadata:
  version: 8
  cacheKey: 10c0

"lodash@npm:^4.17.20":
  version: 4.17.20
  resolution: "lodash@npm:4.17.20"
  linkType: hard

"pkg@virtual:abc123#npm:2.0.0":
  version: 2.0.0
  resolution: "pkg@virtual:abc123#npm:2.0.0"
  linkType: hard

"ws@workspace:.":
  version: 0.0.0-use.local
  resolution: "ws@workspace:."
  linkType: soft
`)
	ps, _, err := parseYarnLock(data)
	if err != nil {
		t.Fatal(err)
	}
	got := pkgMap(ps)
	if got["lodash"] != "4.17.20" || got["pkg"] != "2.0.0" {
		t.Fatalf("packages = %+v", got)
	}
	if len(ps) != 2 {
		t.Fatalf("expected 2 packages, got %+v", got)
	}
}

func TestPnpmMultiDocument(t *testing.T) {
	data := []byte(`lockfileVersion: '9.0'
packages:
  'lodash@4.17.20':
    resolution: {integrity: sha512-abc}
---
lockfileVersion: '9.0'
packages:
  '@scope/pkg@1.2.3(peer@1.0.0)':
    resolution: {integrity: sha512-def}
  'file:../local':
    resolution: {directory: ../local}
`)
	ps, skipped, err := parsePnpmLock(data)
	if err != nil {
		t.Fatal(err)
	}
	got := pkgMap(ps)
	if got["lodash"] != "4.17.20" || got["@scope/pkg"] != "1.2.3" {
		t.Fatalf("packages = %+v (skipped %d)", got, skipped)
	}
	if len(ps) != 2 {
		t.Fatalf("expected 2 packages, got %+v", got)
	}
}

func TestPnpmKeyVariants(t *testing.T) {
	cases := []struct {
		key, name, version string
		ok                 bool
	}{
		{"/lodash/4.17.20", "lodash", "4.17.20", true},
		{"/@scope/pkg/1.2.3", "@scope/pkg", "1.2.3", true},
		{"/lodash@4.17.20", "lodash", "4.17.20", true},
		{"lodash@4.17.20(react@18.0.0)", "lodash", "4.17.20", true},
		{"@scope/pkg@1.2.3", "@scope/pkg", "1.2.3", true},
		{"file:../local", "", "", false},
		{"link:../pkg", "", "", false},
	}
	for _, tc := range cases {
		name, ver, ok := parsePnpmKey(tc.key)
		if ok != tc.ok || name != tc.name || ver != tc.version {
			t.Errorf("parsePnpmKey(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.key, name, ver, ok, tc.name, tc.version, tc.ok)
		}
	}
}

func TestNodeModulesFallback(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("node_modules/lodash/package.json", `{"name":"lodash","version":"4.17.20"}`)
	write("node_modules/@scope/pkg/package.json", `{"name":"@scope/pkg","version":"2.0.0"}`)
	write("node_modules/broken/package.json", `not json`)

	ps := parseNodeModules(root)
	got := pkgMap(ps)
	if got["lodash"] != "4.17.20" || got["@scope/pkg"] != "2.0.0" {
		t.Fatalf("packages = %+v", got)
	}
}

func TestGoMod(t *testing.T) {
	data := []byte(`module example.com/app

go 1.22

require (
	golang.org/x/text v0.14.0
	github.com/foo/bar v1.2.3 // indirect
	github.com/old/pkg v0.1.0
)

require github.com/single/dep v1.0.0

replace github.com/old/pkg => github.com/new/pkg v0.2.0

exclude github.com/foo/bar v1.2.3
`)
	ps, skipped := parseGoMod(data)
	got := pkgMap(ps)
	if got["golang.org/x/text"] != "v0.14.0" || got["github.com/single/dep"] != "v1.0.0" {
		t.Fatalf("packages = %+v", got)
	}
	if got["github.com/new/pkg"] != "v0.2.0" {
		t.Fatalf("replace not applied: %+v", got)
	}
	if _, ok := got["github.com/foo/bar"]; ok {
		t.Fatal("excluded module still present")
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d", skipped)
	}
	for _, p := range ps {
		if p.Name == "github.com/foo/bar" {
			t.Fatal("excluded module present")
		}
		if p.Name == "github.com/new/pkg" && !p.Direct {
			t.Fatal("replaced direct requirement lost its direct flag")
		}
	}
}

func TestCargoLock(t *testing.T) {
	data := []byte(`[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "local-workspace"
version = "0.1.0"

[[package]]
name = "tokio"
version = "1.35.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
	ps := parseCargoLock(data)
	got := pkgMap(ps)
	if got["serde"] != "1.0.193" || got["tokio"] != "1.35.0" {
		t.Fatalf("packages = %+v", got)
	}
	if _, ok := got["local-workspace"]; ok {
		t.Fatal("workspace member should be skipped")
	}
}

func TestNuGetLock(t *testing.T) {
	data := []byte(`{
	  "version": 1,
	  "dependencies": {
	    "net8.0": {
	      "Serilog": {"type": "Direct", "resolved": "2.12.0"},
	      "Microsoft.Extensions.Logging": {"type": "Transitive", "resolved": "8.0.0"},
	      "MyApp": {"type": "Project", "resolved": "1.0.0"}
	    }
	  }
	}`)
	ps, err := parseNuGetLock(data)
	if err != nil {
		t.Fatal(err)
	}
	got := pkgMap(ps)
	if got["Serilog"] != "2.12.0" || got["Microsoft.Extensions.Logging"] != "8.0.0" {
		t.Fatalf("packages = %+v", got)
	}
	if len(ps) != 2 {
		t.Fatalf("project references must be skipped, got %+v", got)
	}
	for _, p := range ps {
		if p.Name == "Serilog" && !p.Direct {
			t.Fatal("direct flag lost for NuGet")
		}
	}
}

func TestProjectAssetsFallback(t *testing.T) {
	data := []byte(`{
	  "libraries": {
	    "Serilog/2.12.0": {"type": "package"},
	    "MyApp/1.0.0": {"type": "project"},
	    "invalidkey": {"type": "package"}
	  }
	}`)
	ps, err := parseProjectAssets(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Name != "Serilog" || ps[0].Version != "2.12.0" {
		t.Fatalf("packages = %+v", ps)
	}
}
