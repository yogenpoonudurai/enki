//go:build windows

package platform

import "golang.org/x/sys/windows"

// Elevated reports whether the current process token is elevated.
func Elevated() bool {
	t := windows.GetCurrentProcessToken()
	return t.IsElevated()
}
