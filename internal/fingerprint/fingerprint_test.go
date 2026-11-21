package fingerprint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCaptureAndVerify(t *testing.T) {
	path := tempFile(t, `{"a":1}`)
	sha, size, err := Capture(path)
	if err != nil {
		t.Fatal(err)
	}
	if sha == "" || size != int64(len(`{"a":1}`)) {
		t.Fatalf("unexpected fingerprint %q %d", sha, size)
	}
	if err := Verify(path, sha, size); err != nil {
		t.Fatalf("verify unchanged: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"a":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = Verify(path, sha, size)
	if err == nil || !strings.Contains(err.Error(), "changed since scan") {
		t.Fatalf("verify changed = %v, want changed-since-scan error", err)
	}
}

func TestCaptureRejectsSymlink(t *testing.T) {
	target := tempFile(t, "x")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, _, err := Capture(link); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestVerifyRequiresFingerprint(t *testing.T) {
	path := tempFile(t, "x")
	if err := Verify(path, "", 0); err == nil {
		t.Fatal("expected missing-fingerprint error")
	}
}
