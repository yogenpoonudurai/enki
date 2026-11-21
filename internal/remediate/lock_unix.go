//go:build !windows

package remediate

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

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
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
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
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
