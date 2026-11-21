package platform

import (
	"os"
	"path/filepath"
	"runtime"
)

// ConfigDir returns the per-user configuration directory for enki.
func ConfigDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "enki")
	}
	return filepath.Join(home(), ".enki")
}

// CacheDir returns the per-user cache directory for enki.
func CacheDir() string {
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "enki")
	}
	return filepath.Join(home(), ".cache", "enki")
}

// StateDir returns the state directory used for audit logs and undo backups.
func StateDir() string {
	if runtime.GOOS == "windows" {
		if d, err := os.UserConfigDir(); err == nil {
			return filepath.Join(d, "enki", "state")
		}
		return filepath.Join(home(), "AppData", "Local", "enki", "state")
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "enki")
	}
	return filepath.Join(home(), ".local", "state", "enki")
}

func home() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}
