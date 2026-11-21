package agentcfg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/configutil"
)

func TestBypassPermissionsAndGrants(t *testing.T) {
	root, err := configutil.ToMap([]byte(`{"permissions":{"defaultMode":"bypassPermissions","allow":["Bash(*)","Read(~/.ssh/**)","Read(./src/**)"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	fs := checkConfig("/tmp/settings.json", root)

	got := map[string]int{}
	for _, f := range fs {
		got[f.RuleID]++
	}
	for _, want := range []string{"AGT-001", "AGT-002", "AGT-004"} {
		if got[want] != 1 {
			t.Errorf("rule %s count = %d, want 1 (all: %v)", want, got[want], got)
		}
	}

	for _, f := range fs {
		if f.RuleID != "AGT-001" {
			continue
		}
		if f.Remediation == nil || f.Remediation.Action != "remove_json_key" {
			t.Fatalf("AGT-001 remediation = %+v", f.Remediation)
		}
		if f.Remediation.Params["key_path"] != "permissions.defaultMode" {
			t.Fatalf("key_path = %q", f.Remediation.Params["key_path"])
		}
	}
}

func TestCleanSettings(t *testing.T) {
	root, err := configutil.ToMap([]byte(`{"permissions":{"defaultMode":"default","allow":["Read(./src/**)"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if fs := checkConfig("/tmp/settings.json", root); len(fs) != 0 {
		t.Fatalf("unexpected findings: %+v", fs)
	}
}

func TestAutoRunDetection(t *testing.T) {
	root, err := configutil.ToMap([]byte(`{"cursor.general.autoRun":true,"chat.tools.autoApprove":false}`))
	if err != nil {
		t.Fatal(err)
	}
	fs := checkConfig("/tmp/settings.json", root)
	if len(fs) != 1 || fs[0].RuleID != "AGT-003" {
		t.Fatalf("auto-run findings = %+v", fs)
	}
}

func TestShellProfileFlag(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(profile, []byte("alias claude='claude --dangerously-skip-permissions'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := checkShellProfiles(home)
	if len(fs) != 1 || fs[0].RuleID != "AGT-001" {
		t.Fatalf("shell profile findings = %+v", fs)
	}
}
