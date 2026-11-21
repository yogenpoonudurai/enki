//go:build !linux

package collector

// ProcEnv returns the environment of a process where supported. Platform
// backends that cannot read process environments return nil.
func ProcEnv(pid int) []string { return nil }
