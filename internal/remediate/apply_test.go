package remediate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
)

func isolatedState(t *testing.T) {
	t.Helper()
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
}

func writeTemp(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestChmodThenUndo(t *testing.T) {
	isolatedState(t)
	path := writeTemp(t, ".env", "OPENAI_API_KEY=sk-proj-abc\n", 0o644)

	a := Action{Kind: "chmod_private", Class: finding.ActionSafe, Path: path, Mode: "0600", RuleID: "SEC-003", Auto: true}
	res, err := Apply(a, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatalf("action not applied: %+v", res)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}

	msgs, err := Undo(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("undo messages = %v", msgs)
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("restored mode = %04o, want 0644", info.Mode().Perm())
	}
}

func TestRemoveJSONKeyAndUndo(t *testing.T) {
	isolatedState(t)
	original := `{
  // agent permissions
  "permissions": {
    "defaultMode": "bypassPermissions",
    "allow": ["Bash(*)"]
  }
}
`
	path := writeTemp(t, "settings.json", original, 0o644)

	a := Action{
		Kind:    "remove_json_key",
		Class:   finding.ActionModerate,
		Path:    path,
		KeyPath: "permissions.defaultMode",
		RuleID:  "AGT-001",
		Auto:    true,
	}
	res, err := Apply(a, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatalf("action not applied: %+v", res)
	}

	edited, _ := os.ReadFile(path)
	if strings.Contains(string(edited), "defaultMode") {
		t.Fatalf("defaultMode still present:\n%s", edited)
	}
	if !strings.Contains(string(edited), "// agent permissions") {
		t.Fatalf("comment lost:\n%s", edited)
	}
	if !strings.Contains(string(edited), `"allow"`) {
		t.Fatalf("sibling key lost:\n%s", edited)
	}

	if _, err := Undo(1); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(path)
	if string(restored) != original {
		t.Fatalf("undo not byte-identical:\n--- got ---\n%s\n--- want ---\n%s", restored, original)
	}
}

func TestDryRunDoesNotMutate(t *testing.T) {
	isolatedState(t)
	path := writeTemp(t, ".env", "x=1\n", 0o644)
	a := Action{Kind: "chmod_private", Class: finding.ActionSafe, Path: path, Mode: "0600", Auto: true}
	res, err := Apply(a, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied {
		t.Fatal("dry run reported applied")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("dry run mutated mode to %04o", info.Mode().Perm())
	}
}

func TestMissingKeySkips(t *testing.T) {
	isolatedState(t)
	path := writeTemp(t, "settings.json", `{"permissions":{"allow":[]}}`, 0o644)
	a := Action{Kind: "remove_json_key", Class: finding.ActionModerate, Path: path, KeyPath: "permissions.defaultMode", Auto: true}
	res, err := Apply(a, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped {
		t.Fatalf("expected skip, got %+v", res)
	}
}

func TestRefusesSymlink(t *testing.T) {
	isolatedState(t)
	target := writeTemp(t, "real.env", "x=1\n", 0o644)
	link := filepath.Join(t.TempDir(), "link.env")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	a := Action{Kind: "chmod_private", Class: finding.ActionSafe, Path: link, Mode: "0600", Auto: true}
	if _, err := Apply(a, false); err == nil {
		t.Fatal("expected refusal for symlink")
	}
}

func TestRefusesSensitiveRoot(t *testing.T) {
	isolatedState(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sshDir, "config")
	if err := os.WriteFile(path, []byte("Host *\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := Action{Kind: "chmod_private", Class: finding.ActionSafe, Path: path, Mode: "0600", Auto: true}
	if _, err := Apply(a, false); err == nil {
		t.Fatal("expected refusal for ~/.ssh path")
	}
}

func TestManualActionSkipped(t *testing.T) {
	res, err := Apply(Action{Class: finding.ActionRisky, Summary: "firewall"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped {
		t.Fatal("manual action should be skipped")
	}
}
