//go:build !windows

package remediate

import (
	"os"
	"syscall"
)

func fileOwner(info os.FileInfo) (int, int) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int(st.Uid), int(st.Gid)
}

// preserveOwner restores the original ownership on a temp file before rename.
// It skips the chown when the temp file already has the target ownership,
// which avoids unnecessary privilege checks (including setgid directories).
func preserveOwner(path string, uid, gid int) error {
	if uid < 0 || gid < 0 {
		return nil
	}
	if info, err := os.Lstat(path); err == nil {
		curUID, curGID := fileOwner(info)
		if curUID == uid && curGID == gid {
			return nil
		}
	}
	return os.Chown(path, uid, gid)
}
