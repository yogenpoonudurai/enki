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

	"github.com/yogenpoonudurai/enki/internal/fingerprint"
	"github.com/yogenpoonudurai/enki/internal/platform"
)

const (
	statusPending  = "pending"
	statusApplied  = "applied"
	statusUndone   = "undone"
	statusAborted  = "aborted"
	statusConflict = "conflict"
)

type record struct {
	ID           string    `json:"id"`
	Time         time.Time `json:"time"`
	Kind         string    `json:"kind"` // chmod | edit
	Status       string    `json:"status,omitempty"`
	RuleID       string    `json:"rule_id,omitempty"`
	FindingID    string    `json:"finding_id,omitempty"`
	Path         string    `json:"path,omitempty"`
	BackupPath   string    `json:"backup_path,omitempty"`
	OriginalMode uint32    `json:"original_mode,omitempty"`
	NewMode      uint32    `json:"new_mode,omitempty"`
	OriginalUID  int       `json:"original_uid,omitempty"`
	OriginalGID  int       `json:"original_gid,omitempty"`
	BeforeSHA256 string    `json:"before_sha256,omitempty"`
	AfterSHA256  string    `json:"after_sha256,omitempty"`
	OriginalSize int64     `json:"original_size,omitempty"`
	NewSize      int64     `json:"new_size,omitempty"`
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

func appendStatus(id, status, detail string) error {
	return appendRecord(record{ID: id, Time: time.Now().UTC(), Status: status, Detail: detail})
}

func loadJournal() ([]record, error) {
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

// resolveJournal collapses append-only status lines into one record per action.
// Records written before status tracking have no status and count as applied.
func resolveJournal(raw []record) []record {
	index := make(map[string]int, len(raw))
	out := make([]record, 0, len(raw))
	for _, r := range raw {
		if i, ok := index[r.ID]; ok {
			if r.Status != "" {
				out[i].Status = r.Status
			}
			if r.Detail != "" {
				out[i].Detail = r.Detail
			}
			if r.AfterSHA256 != "" {
				out[i].AfterSHA256 = r.AfterSHA256
			}
			if r.NewSize != 0 {
				out[i].NewSize = r.NewSize
			}
			if !r.Time.IsZero() {
				out[i].Time = r.Time
			}
			continue
		}
		if r.Status == "" {
			r.Status = statusApplied
		}
		index[r.ID] = len(out)
		out = append(out, r)
	}
	return out
}

func appliedRecords() ([]record, error) {
	raw, err := loadJournal()
	if err != nil {
		return nil, err
	}
	resolved := resolveJournal(raw)
	var out []record
	for _, r := range resolved {
		if r.Status == statusApplied {
			out = append(out, r)
		}
	}
	return out, nil
}

// reconcile resolves actions interrupted mid-flight and flags orphan backups.
// A pending record is committed when the file matches the intended result, and
// aborted when it still matches the original.
func reconcile() error {
	raw, err := loadJournal()
	if err != nil {
		return err
	}
	resolved := resolveJournal(raw)
	for _, r := range resolved {
		if r.Status != statusPending {
			continue
		}
		switch r.Kind {
		case "chmod":
			info, err := os.Lstat(r.Path)
			switch {
			case err == nil && r.NewMode != 0 && info.Mode().Perm() == fs.FileMode(r.NewMode):
				_ = appendStatus(r.ID, statusApplied, "recovered interrupted chmod")
			case err == nil:
				_ = appendStatus(r.ID, statusAborted, "interrupted chmod did not complete")
			default:
				_ = appendStatus(r.ID, statusConflict, "target missing after interrupted chmod")
			}
		case "edit":
			sha, _, err := fingerprint.Capture(r.Path)
			switch {
			case err == nil && r.AfterSHA256 != "" && sha == r.AfterSHA256:
				_ = appendStatus(r.ID, statusApplied, "recovered interrupted edit")
			case err == nil && r.BeforeSHA256 != "" && sha == r.BeforeSHA256:
				_ = appendStatus(r.ID, statusAborted, "interrupted edit did not complete")
			default:
				_ = appendStatus(r.ID, statusConflict, "file changed during interrupted edit")
			}
		}
	}
	flagOrphanBackups(resolveJournal(raw))
	return nil
}

func flagOrphanBackups(recs []record) {
	referenced := map[string]bool{}
	for _, r := range recs {
		if r.BackupPath != "" {
			referenced[filepath.Base(r.BackupPath)] = true
		}
	}
	entries, err := os.ReadDir(BackupsDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if !referenced[e.Name()] {
			audit("orphan backup " + e.Name() + " (no journal record)")
		}
	}
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

// writeFileAtomic writes data via a temp file in the same directory, preserves
// ownership, and replaces the target only on success.
func writeFileAtomic(path string, data []byte, mode fs.FileMode, uid, gid int) error {
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
	if err := preserveOwner(tmpName, uid, gid); err != nil {
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// guardPath refuses to modify files that resolve into sensitive credential
// roots. Symlinks are resolved so a symlinked parent cannot bypass the check.
func guardPath(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", path, err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	for _, rel := range []string{".ssh", ".aws", ".gnupg", ".config/gcloud"} {
		root := filepath.Join(home, rel)
		if rr, err := filepath.EvalSymlinks(root); err == nil {
			root = rr
		}
		if resolved == root || strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
			return fmt.Errorf("refusing to modify sensitive path %s", resolved)
		}
	}
	return nil
}
