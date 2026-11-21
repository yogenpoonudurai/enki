//go:build !linux && !darwin && !windows

package collector

import "runtime"

// Listeners is unsupported on this platform.
func Listeners() ([]Listener, []Gap) {
	return nil, []Gap{{Module: "listeners", Reason: "listener enumeration unsupported on " + runtime.GOOS}}
}
