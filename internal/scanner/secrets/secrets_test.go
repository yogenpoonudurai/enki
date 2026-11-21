package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

func testContext(t *testing.T) *scanner.Context {
	t.Helper()
	return &scanner.Context{
		Ctx:        context.Background(),
		HomeDir:    t.TempDir(),
		WorkingDir: t.TempDir(),
	}
}

func TestEnvFileSecrets(t *testing.T) {
	sc := testContext(t)
	envPath := filepath.Join(sc.WorkingDir, ".env")
	if err := os.WriteFile(envPath, []byte(
		"OPENAI_API_KEY=sk-test-abcdefghijklmnopqrstuvwxyz123456\n"+
			"HF_TOKEN=hf_testabcdefghijklmnopqrstuvwxyz0123456789\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(envPath, 0o644); err != nil {
		t.Fatal(err)
	}

	fs, _, err := New().Run(sc)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, f := range fs {
		counts[f.RuleID]++
		if strings.Contains(f.Evidence, "sk-test-abcdefghijklmnopqrstuvwxyz123456") {
			t.Fatalf("raw secret leaked in evidence: %s", f.Evidence)
		}
		if strings.Contains(f.Evidence, "hf_testabcdefghijklmnopqrstuvwxyz0123456789") {
			t.Fatalf("raw token leaked in evidence: %s", f.Evidence)
		}
	}
	if counts["SEC-001"] != 2 {
		t.Fatalf("SEC-001 count = %d, want 2", counts["SEC-001"])
	}
	if counts["SEC-003"] != 1 {
		t.Fatalf("SEC-003 count = %d, want 1", counts["SEC-003"])
	}

	for _, f := range fs {
		if f.RuleID == "SEC-003" {
			if f.Remediation == nil || f.Remediation.Action != "chmod_private" {
				t.Fatalf("SEC-003 remediation = %+v", f.Remediation)
			}
			if f.Remediation.Class != finding.ActionSafe {
				t.Fatalf("SEC-003 class = %s, want safe", f.Remediation.Class)
			}
		}
	}
}

func TestHistoryLeak(t *testing.T) {
	sc := testContext(t)
	hist := filepath.Join(sc.HomeDir, ".zsh_history")
	if err := os.WriteFile(hist, []byte("export ANTHROPIC_API_KEY=sk-ant-test-abcdefghijklmnopqrstuvwxyz\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fs, _, err := New().Run(sc)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		if f.RuleID == "SEC-002" {
			found = true
			if f.Severity != finding.SeverityMedium {
				t.Fatalf("history severity = %s, want MEDIUM for 0600 file", f.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("no SEC-002 finding: %+v", fs)
	}
}

func TestHFTokenFile(t *testing.T) {
	sc := testContext(t)
	dir := filepath.Join(sc.HomeDir, ".cache", "huggingface")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(dir, "token")
	if err := os.WriteFile(token, []byte("hf_testabcdefghijklmnopqrstuvwxyz0123456789\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fs, _, err := New().Run(sc)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		if f.RuleID == "SEC-004" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no SEC-004 finding: %+v", fs)
	}
}

func TestBuildTargetsScope(t *testing.T) {
	sc := &scanner.Context{HomeDir: "/home/u", WorkingDir: "/work"}
	sc.Scope = scanner.ScopeProject
	for _, target := range buildTargets(sc) {
		if target.path == "/home/u/.env" || target.path == "/home/u/.netrc" {
			t.Fatalf("project scope included host target %s", target.path)
		}
	}

	sc.Scope = scanner.ScopeHost
	for _, target := range buildTargets(sc) {
		if target.path == "/work/.env" {
			t.Fatal("host scope included project target /work/.env")
		}
	}
}
