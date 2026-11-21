package remediate

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/hujson"
)

// Apply executes (or, when dryRun is true, validates) a single action.
func Apply(a Action, dryRun bool) (Result, error) {
	res := Result{Action: a}
	if !a.Auto {
		res.Skipped = true
		res.Reason = "manual action; see guidance/command"
		return res, nil
	}
	switch a.Kind {
	case "chmod_private":
		return applyChmod(a, dryRun)
	case "remove_json_key":
		return applyRemoveJSONKey(a, dryRun)
	default:
		res.Skipped = true
		res.Reason = "unsupported action"
		return res, nil
	}
}

func applyChmod(a Action, dryRun bool) (Result, error) {
	res := Result{Action: a}
	info, err := os.Lstat(a.Path)
	if err != nil {
		return res, fmt.Errorf("%s: %w", a.Path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return res, fmt.Errorf("refusing to modify symlink %s", a.Path)
	}
	if !info.Mode().IsRegular() {
		return res, fmt.Errorf("refusing to modify non-regular file %s", a.Path)
	}
	if err := guardPath(a.Path); err != nil {
		return res, err
	}
	mode64, err := strconv.ParseUint(strings.TrimPrefix(a.Mode, "0o"), 8, 32)
	if err != nil {
		return res, fmt.Errorf("invalid mode %q", a.Mode)
	}
	target := fs.FileMode(mode64)
	if info.Mode().Perm() == target {
		res.Skipped = true
		res.Reason = "already restricted"
		return res, nil
	}
	if dryRun {
		res.Reason = fmt.Sprintf("dry run: would chmod %04o", target)
		return res, nil
	}
	if err := os.Chmod(a.Path, target); err != nil {
		return res, err
	}
	rec := record{
		ID:           newID(),
		Time:         time.Now().UTC(),
		Kind:         "chmod",
		RuleID:       a.RuleID,
		FindingID:    a.FindingID,
		Path:         a.Path,
		OriginalMode: uint32(info.Mode().Perm()),
		Detail:       a.Mode,
	}
	if err := appendRecord(rec); err != nil {
		return res, err
	}
	audit(fmt.Sprintf("chmod %04o %s (%s)", target, a.Path, a.RuleID))
	res.Applied = true
	return res, nil
}

func applyRemoveJSONKey(a Action, dryRun bool) (Result, error) {
	res := Result{Action: a}
	info, err := os.Lstat(a.Path)
	if err != nil {
		return res, fmt.Errorf("%s: %w", a.Path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return res, fmt.Errorf("refusing to modify symlink %s", a.Path)
	}
	if !info.Mode().IsRegular() {
		return res, fmt.Errorf("refusing to modify non-regular file %s", a.Path)
	}
	if err := guardPath(a.Path); err != nil {
		return res, err
	}
	data, err := os.ReadFile(a.Path)
	if err != nil {
		return res, err
	}
	patched, err := removeJSONKey(data, a.KeyPath)
	if err != nil {
		return res, err
	}
	if patched == nil {
		res.Skipped = true
		res.Reason = "key not present"
		return res, nil
	}
	if dryRun {
		res.Reason = "dry run: would remove " + a.KeyPath
		return res, nil
	}
	backup, err := makeBackup(a.Path, data)
	if err != nil {
		return res, err
	}
	if err := writeFileAtomic(a.Path, patched, info.Mode().Perm()); err != nil {
		return res, err
	}
	rec := record{
		ID:           newID(),
		Time:         time.Now().UTC(),
		Kind:         "edit",
		RuleID:       a.RuleID,
		FindingID:    a.FindingID,
		Path:         a.Path,
		BackupPath:   backup,
		OriginalMode: uint32(info.Mode().Perm()),
		Detail:       "removed " + a.KeyPath,
	}
	if err := appendRecord(rec); err != nil {
		return res, err
	}
	audit(fmt.Sprintf("remove %s from %s (%s)", a.KeyPath, a.Path, a.RuleID))
	res.Applied = true
	res.Backup = backup
	return res, nil
}

// removeJSONKey deletes a dotted key path from a JSON/JSONC document while
// preserving comments and formatting. Returns nil data when the key is absent.
func removeJSONKey(data []byte, dotted string) ([]byte, error) {
	parts := strings.Split(dotted, ".")
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(p, "~", "~0"), "/", "~1")
	}
	ptr := "/" + strings.Join(parts, "/")

	v, err := hujson.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", dotted, err)
	}
	if v.Find(ptr) == nil {
		return nil, nil
	}
	patch, err := json.Marshal([]map[string]string{{"op": "remove", "path": ptr}})
	if err != nil {
		return nil, err
	}
	if err := v.Patch(patch); err != nil {
		return nil, fmt.Errorf("remove %s: %w", dotted, err)
	}
	// Do not call Format: Patch already preserves the original whitespace and
	// comments, while Format would reindent the whole document.
	out := v.Pack()

	std, err := hujson.Standardize(append([]byte(nil), out...))
	if err != nil {
		return nil, fmt.Errorf("post-edit validation failed: %w", err)
	}
	if !json.Valid(std) {
		return nil, fmt.Errorf("post-edit validation failed: invalid JSON")
	}
	return out, nil
}

// Undo restores the last n applied actions in reverse order.
func Undo(n int) ([]string, error) {
	if n <= 0 {
		n = 1
	}
	recs, err := loadState()
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, nil
	}
	if n > len(recs) {
		n = len(recs)
	}
	undone := recs[len(recs)-n:]
	remaining := recs[:len(recs)-n]

	var msgs []string
	for i := len(undone) - 1; i >= 0; i-- {
		r := undone[i]
		switch r.Kind {
		case "chmod":
			if err := os.Chmod(r.Path, fs.FileMode(r.OriginalMode)); err != nil {
				return msgs, fmt.Errorf("restore mode on %s: %w", r.Path, err)
			}
			msgs = append(msgs, fmt.Sprintf("restored mode %04o on %s", r.OriginalMode, r.Path))
			audit(fmt.Sprintf("undo chmod %04o %s", r.OriginalMode, r.Path))
		case "edit":
			if err := restoreBackup(r); err != nil {
				return msgs, fmt.Errorf("restore %s: %w", r.Path, err)
			}
			msgs = append(msgs, "restored "+r.Path)
			audit("undo edit " + r.Path)
		}
	}
	if err := writeState(remaining); err != nil {
		return msgs, err
	}
	return msgs, nil
}

func restoreBackup(r record) error {
	if r.BackupPath == "" {
		return fmt.Errorf("no backup recorded")
	}
	data, err := os.ReadFile(r.BackupPath)
	if err != nil {
		return err
	}
	mode := fs.FileMode(r.OriginalMode)
	if mode == 0 {
		mode = 0o600
	}
	if err := writeFileAtomic(r.Path, data, mode); err != nil {
		return err
	}
	return nil
}
