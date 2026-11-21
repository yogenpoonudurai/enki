package sbom

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

func TestParseRequirements(t *testing.T) {
	data := []byte("torch==2.0.1\nlangchain>=1.0  # unpinned\n-r other.txt\nrequests==2.31.0\ntorch==2.0.1\n")
	got := parseRequirements(data)
	if len(got) != 2 {
		t.Fatalf("parsed %d packages, want 2: %+v", len(got), got)
	}
	if got[0].Name != "torch" || got[0].Version != "2.0.1" || got[0].Ecosystem != "PyPI" {
		t.Fatalf("first package = %+v", got[0])
	}
}

func TestParsePackageLock(t *testing.T) {
	data := []byte(`{
	  "packages": {
	    "": {"version": "1.0.0"},
	    "node_modules/openai": {"version": "4.1.0"},
	    "node_modules/a/node_modules/@anthropic-ai/sdk": {"version": "0.20.0"}
	  }
	}`)
	got, _, err := parseNpmLock(data)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, p := range got {
		names[p.Name] = p.Version
	}
	if names["openai"] != "4.1.0" || names["@anthropic-ai/sdk"] != "0.20.0" {
		t.Fatalf("parsed = %+v", names)
	}
}

func TestParsePoetryLock(t *testing.T) {
	data := []byte(`[[package]]
name = "torch"
version = "2.1.0"
description = "x"

[[package]]
name = "requests"
version = "2.31.0"
`)
	got, _ := parseTOMLPackages(data, false)
	if len(got) != 2 || got[0].Name != "torch" {
		t.Fatalf("parsed = %+v", got)
	}
}

func TestAIPackageFilter(t *testing.T) {
	if !isAIPackage("PyPI", "torch") {
		t.Fatal("torch should be selected")
	}
	if !isAIPackage("PyPI", "Huggingface_Hub") {
		t.Fatal("normalization failed")
	}
	if !isAIPackage("npm", "@modelcontextprotocol/sdk") {
		t.Fatal("mcp sdk should be selected")
	}
	if isAIPackage("PyPI", "requests") {
		t.Fatal("requests should not be selected")
	}
}

type fakeClient struct {
	ids map[string][]string
	adv map[string]*Advisory
	err error
}

func (f *fakeClient) QueryBatch(_ context.Context, qs []Query) ([][]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := make([][]string, len(qs))
	for i, q := range qs {
		out[i] = f.ids[q.Name+"@"+q.Version]
	}
	return out, nil
}

func (f *fakeClient) Advisory(_ context.Context, id string) (*Advisory, error) {
	if a, ok := f.adv[id]; ok {
		return a, nil
	}
	return nil, errors.New("missing advisory")
}

func (f *fakeClient) Enrich(context.Context, []*Advisory) {}

func TestModuleDedupesAdvisorySources(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("torch==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fakeClient{
		ids: map[string][]string{"torch@2.0.1": {"GHSA-1", "PYSEC-1"}},
		adv: map[string]*Advisory{
			"GHSA-1": {
				ID: "GHSA-1", Summary: "torch RCE", Aliases: []string{"CVE-2024-1111"},
				Severity: finding.SeverityHigh, Fixed: []string{"2.1.0"}, KEV: true,
			},
			"PYSEC-1": {
				ID: "PYSEC-1", Aliases: []string{"CVE-2024-1111"},
				Severity: finding.SeverityMedium, Fixed: []string{"deadbeefcafe"},
			},
		},
	}
	sc := &scanner.Context{Ctx: context.Background(), WorkingDir: dir}
	opts := DefaultOptions()
	opts.OSPackages = false
	fs, gaps, err := NewWithClient(opts, fake).Run(sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v", gaps)
	}
	if len(fs) != 1 {
		t.Fatalf("expected 1 merged finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].Severity != finding.SeverityHigh {
		t.Fatalf("severity = %s, want HIGH", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Evidence, "CVE-2024-1111") {
		t.Fatalf("evidence missing CVE alias: %s", fs[0].Evidence)
	}
	if strings.Contains(fs[0].Evidence, "deadbeefcafe") {
		t.Fatalf("commit hash should be filtered from fixed versions: %s", fs[0].Evidence)
	}
}

func TestNetworkFailureIsGapNotClean(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("torch==2.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fakeClient{err: errors.New("network down")}
	sc := &scanner.Context{Ctx: context.Background(), WorkingDir: dir}
	opts := DefaultOptions()
	opts.OSPackages = false
	fs, gaps, err := NewWithClient(opts, fake).Run(sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("unexpected findings: %+v", fs)
	}
	if len(gaps) == 0 || !strings.Contains(gaps[0].Reason, "unknown") {
		t.Fatalf("expected an unknown-status gap, got %+v", gaps)
	}
}

func TestNoAIPackagesSkipsNetwork(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &fakeClient{err: errors.New("must not be called")}
	sc := &scanner.Context{Ctx: context.Background(), WorkingDir: dir}
	opts := DefaultOptions()
	opts.OSPackages = false
	opts.Deps = "ai"
	fs, _, err := NewWithClient(opts, fake).Run(sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("findings = %+v", fs)
	}
}
