//go:build windows

package remediate

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/yogenpoonudurai/enki/internal/platform"
)

func acquireStateLock() (func(), error) {
	if err := ensureStateDir(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(platform.StateDir(), "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ol := &windows.Overlapped{}
	handle := windows.Handle(f.Fd())
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("another enki fix or undo is running")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, ol)
		f.Close()
	}, nil
}
