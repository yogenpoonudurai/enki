// Package fingerprint records the content identity of a remediation target at
// scan time so apply can refuse to overwrite a file that changed afterwards.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const (
	// ParamSHA256 and ParamSize are stored in finding.Remediation.Params and
	// carried into remediate.Action.
	ParamSHA256 = "target_sha256"
	ParamSize   = "target_size"

	// MaxBytes bounds hashing so a pathological file cannot stall a scan.
	MaxBytes = 8 << 20
)

// Capture returns the sha256 and size of a regular file. Symlinks and
// non-regular files are rejected so a fingerprint always describes the file
// that apply will modify.
func Capture(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", 0, fmt.Errorf("refusing to fingerprint symlink %s", path)
	}
	if !info.Mode().IsRegular() {
		return "", 0, fmt.Errorf("refusing to fingerprint non-regular file %s", path)
	}
	if info.Size() > MaxBytes {
		return "", 0, fmt.Errorf("file %s exceeds %d bytes", path, MaxBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return "", 0, err
	}
	if n > MaxBytes {
		return "", 0, fmt.Errorf("file %s exceeds %d bytes", path, MaxBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Verify compares the current file against a captured fingerprint. An empty
// expected hash means the report predates fingerprinting and must be rescanned.
func Verify(path, expectedSHA256 string, expectedSize int64) error {
	if expectedSHA256 == "" {
		return fmt.Errorf("missing scan fingerprint for %s; rerun enki scan", path)
	}
	got, size, err := Capture(path)
	if err != nil {
		return err
	}
	if expectedSize > 0 && size != expectedSize {
		return fmt.Errorf("%s changed since scan (size %d, expected %d); rerun enki scan", path, size, expectedSize)
	}
	if got != expectedSHA256 {
		return fmt.Errorf("%s changed since scan (content hash mismatch); rerun enki scan", path)
	}
	return nil
}
