package remediate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yogenpoonudurai/enki/internal/platform"
)

type record struct {
	ID           string    `json:"id"`
	Time         time.Time `json:"time"`
	Kind         string    `json:"kind"` // chmod | edit
	RuleID       string    `json:"rule_id,omitempty"`
	FindingID    string    `json:"finding_id,omitempty"`
	Path         string    `json:"path,omitempty"`
	BackupPath   string    `json:"backup_path,omitempty"`
	OriginalMode uint32    `json:"original_mode,omitempty"`
	Detail       string    `json:"detail,omitempty"`
}

func statePath() string { return filepath.Join(platform.StateDir(), "state.jsonl") }
func auditPath() string { return filepath.Join(platform.StateDir(), "audit.log") }

func ensureStateDir() error { return os.MkdirAll(platform.StateDir(), 0o700) }

func appendRecord(rec record) error {
	if err := ensureStateDir(); err != nil {
		return err
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(statePath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func loadState() ([]record, error) {
	data, err := os.ReadFile(statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var recs []record
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		recs = append(recs, r)
	}
	return recs, nil
}

func writeState(recs []record) error {
	if err := ensureStateDir(); err != nil {
		return err
	}
	var sb strings.Builder
	for _, r := range recs {
		line, err := json.Marshal(r)
		if err != nil {
			return err
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	return writeFileAtomic(statePath(), []byte(sb.String()), 0o600)
}

func audit(line string) {
	if err := ensureStateDir(); err != nil {
		return
	}
	f, err := os.OpenFile(auditPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), line)
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

// BackupsDir exposes the backup location for diagnostics.
func BackupsDir() string { return filepath.Join(platform.StateDir(), "backups") }

func makeBackup(path string, data []byte) (string, error) {
	dir := filepath.Join(platform.StateDir(), "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s-%s", time.Now().UTC().Format("20060102T150405Z"), newID(), filepath.Base(path))
	dst := filepath.Join(dir, name)
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	return dst, nil
}

// writeFileAtomic writes data to path via a temp file in the same directory,
// preserving the requested mode and replacing the target only on success.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".enki-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// guardPath refuses to modify files under sensitive credential roots.
func guardPath(path string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	abs := filepath.Clean(path)
	for _, rel := range []string{".ssh", ".aws", ".gnupg", ".config/gcloud"} {
		root := filepath.Join(home, rel)
		if abs == root || strings.HasPrefix(abs, root+string(os.PathSeparator)) {
			return fmt.Errorf("refusing to modify sensitive path %s", abs)
		}
	}
	return nil
}
