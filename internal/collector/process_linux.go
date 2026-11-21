//go:build linux

package collector

import (
	"os"
	"strconv"
	"strings"
)

// ProcEnv returns the environment of a process, or nil if unreadable.
func ProcEnv(pid int) []string {
	if pid <= 0 {
		return nil
	}
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return nil
	}
	parts := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	out := parts[:0]
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
