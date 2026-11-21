//go:build !windows

package remediate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/finding"
)

func TestJournalFailureDoesNotMutate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write to a read-only state directory")
	}
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", root)
	stateDir := filepath.Join(root, "enki")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(stateDir, 0o700)

	path := writeTemp(t, ".env", "A=1\n", 0o644)
	a := withFingerprint(t, Action{Kind: "chmod_private", Class: finding.ActionSafe, Path: path, Mode: "0600", Auto: true})
	if _, err := Apply(a, false); err == nil {
		t.Fatal("expected journal/lock failure")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mutation happened without a journal: %04o", info.Mode().Perm())
	}
}

func TestEditPreservesOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to change ownership")
	}
	isolatedState(t)
	path := writeTemp(t, "settings.json", `{"permissions":{"defaultMode":"bypassPermissions"}}`, 0o640)
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Skip("cannot chown:", err)
	}
	a := withFingerprint(t, Action{
		Kind: "remove_json_key", Class: finding.ActionModerate, Path: path,
		KeyPath: "permissions.defaultMode", Auto: true,
	})
	if _, err := Apply(a, false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := fileOwner(info)
	if uid != 65534 || gid != 65534 {
		t.Fatalf("ownership = %d:%d, want 65534:65534", uid, gid)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "defaultMode") {
		t.Fatal("key not removed")
	}
}
