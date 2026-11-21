//go:build !windows

package platform

import "os"

// Elevated reports whether enki is running with root privileges.
func Elevated() bool { return os.Geteuid() == 0 }
