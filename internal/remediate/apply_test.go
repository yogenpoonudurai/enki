package remediate

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/fingerprint"
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

func withFingerprint(t *testing.T, a Action) Action {
	t.Helper()
	sha, size, err := fingerprint.Capture(a.Path)
	if err != nil {
		t.Fatal(err)
	}
	a.ExpectedSHA256 = sha
	a.ExpectedSize = size
	return a
}

func TestChmodThenUndo(t *testing.T) {
	isolatedState(t)
	path := writeTemp(t, ".env", "OPENAI_API_KEY=sk-proj-abc\n", 0o644)

	a := withFingerprint(t, Action{Kind: "chmod_private", Class: finding.ActionSafe, Path: path, Mode: "0600", RuleID: "SEC-003", Auto: true})
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

	msgs, err := Undo(1, false)
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

	a := withFingerprint(t, Action{
		Kind:    "remove_json_key",
		Class:   finding.ActionModerate,
		Path:    path,
		KeyPath: "permissions.defaultMode",
		RuleID:  "AGT-001",
		Auto:    true,
	})
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

	if _, err := Undo(1, false); err != nil {
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
	a := withFingerprint(t, Action{Kind: "chmod_private", Class: finding.ActionSafe, Path: path, Mode: "0600", Auto: true})
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
	a := withFingerprint(t, Action{Kind: "remove_json_key", Class: finding.ActionModerate, Path: path, KeyPath: "permissions.defaultMode", Auto: true})
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

func TestRejectsStaleContent(t *testing.T) {
	isolatedState(t)
	path := writeTemp(t, "settings.json", `{"permissions":{"defaultMode":"bypassPermissions"}}`, 0o644)
	a := withFingerprint(t, Action{
		Kind: "remove_json_key", Class: finding.ActionModerate, Path: path,
		KeyPath: "permissions.defaultMode", Auto: true,
	})
	if err := os.WriteFile(path, []byte(`{"permissions":{"defaultMode":"plan"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(a, false); err == nil || !strings.Contains(err.Error(), "changed since scan") {
		t.Fatalf("stale apply = %v, want changed-since-scan error", err)
	}
	current, _ := os.ReadFile(path)
	if !strings.Contains(string(current), `"plan"`) {
		t.Fatalf("stale apply modified the file: %s", current)
	}
}

func TestRejectsMissingFingerprint(t *testing.T) {
	isolatedState(t)
	path := writeTemp(t, ".env", "x=1\n", 0o644)
	a := Action{Kind: "chmod_private", Class: finding.ActionSafe, Path: path, Mode: "0600", Auto: true}
	if _, err := Apply(a, false); err == nil || !strings.Contains(err.Error(), "missing scan fingerprint") {
		t.Fatalf("missing fingerprint = %v, want explicit error", err)
	}
}

func TestRefusesSymlinkedParentIntoSSH(t *testing.T) {
	isolatedState(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(sshDir, "config")
	if err := os.WriteFile(target, []byte("Host *\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "conf")
	if err := os.Symlink(sshDir, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	path := filepath.Join(link, "config")
	a := withFingerprint(t, Action{Kind: "chmod_private", Class: finding.ActionSafe, Path: path, Mode: "0600", Auto: true})
	if _, err := Apply(a, false); err == nil || !strings.Contains(err.Error(), "sensitive path") {
		t.Fatalf("symlinked parent = %v, want sensitive-path refusal", err)
	}
}

func TestUndoRefusesNewerEdit(t *testing.T) {
	isolatedState(t)
	original := "{\n  \"version\": 1,\n  \"permissions\": {\"defaultMode\": \"bypassPermissions\"}\n}\n"
	path := writeTemp(t, "settings.json", original, 0o644)
	a := withFingerprint(t, Action{
		Kind: "remove_json_key", Class: finding.ActionModerate, Path: path,
		KeyPath: "permissions.defaultMode", Auto: true,
	})
	if _, err := Apply(a, false); err != nil {
		t.Fatal(err)
	}

	newer := "{\n  \"version\": 2,\n  \"permissions\": {\"defaultMode\": \"bypassPermissions\"}\n}\n"
	if err := os.WriteFile(path, []byte(newer), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Undo(1, false); err == nil || !strings.Contains(err.Error(), "use --force") {
		t.Fatalf("undo without force = %v, want refusal", err)
	}
	current, _ := os.ReadFile(path)
	if string(current) != newer {
		t.Fatalf("undo clobbered newer content:\n%s", current)
	}
	if _, err := Undo(1, true); err != nil {
		t.Fatalf("forced undo: %v", err)
	}
	restored, _ := os.ReadFile(path)
	if string(restored) != original {
		t.Fatalf("forced undo did not restore original:\n%s", restored)
	}
}

func TestReconcileRecoversInterruptedChmod(t *testing.T) {
	isolatedState(t)
	path := writeTemp(t, ".env", "A=1\n", 0o600)
	sha, size, err := fingerprint.Capture(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := record{
		ID: "crash-chmod", Kind: "chmod", Status: statusPending, Path: path,
		OriginalMode: 0o644, NewMode: 0o600,
		BeforeSHA256: sha, AfterSHA256: sha, OriginalSize: size, NewSize: size,
	}
	if err := appendRecord(rec); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(); err != nil {
		t.Fatal(err)
	}
	applied, err := appliedRecords()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range applied {
		if r.ID == rec.ID && r.Status == statusApplied {
			found = true
		}
	}
	if !found {
		t.Fatalf("interrupted chmod not recovered: %+v", applied)
	}
}

func TestConcurrentApplySerializes(t *testing.T) {
	isolatedState(t)
	mk := func(name string) Action {
		path := writeTemp(t, name, "A=1\n", 0o644)
		return withFingerprint(t, Action{Kind: "chmod_private", Class: finding.ActionSafe, Path: path, Mode: "0600", Auto: true})
	}
	actions := []Action{mk("a.env"), mk("b.env")}
	var wg sync.WaitGroup
	errs := make([]error, len(actions))
	for i, a := range actions {
		wg.Add(1)
		go func(i int, a Action) {
			defer wg.Done()
			_, errs[i] = Apply(a, false)
		}(i, a)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent apply %d: %v", i, err)
		}
		info, _ := os.Stat(actions[i].Path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("apply %d mode = %04o", i, info.Mode().Perm())
		}
	}
}

func TestReconcileFlagsOrphanBackups(t *testing.T) {
	isolatedState(t)
	if err := os.MkdirAll(BackupsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(BackupsDir(), "orphan-backup")
	if err := os.WriteFile(orphan, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(auditPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "orphan backup") {
		t.Fatalf("orphan backup not flagged: %s", log)
	}
}
