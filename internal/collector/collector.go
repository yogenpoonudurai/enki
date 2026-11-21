// Package collector gathers host facts (listeners, configs) for scanner
// modules. Collection is platform-specific; everything else is shared.
package collector

import (
	"io/fs"
	"time"
)

// Listener is a listening TCP/UDP socket with best-effort process attribution.
type Listener struct {
	Proto   string   `json:"proto"`
	Addr    string   `json:"addr"`
	Port    int      `json:"port"`
	PID     int      `json:"pid,omitempty"`
	Process string   `json:"process,omitempty"`
	Cmdline []string `json:"cmdline,omitempty"`
	User    string   `json:"user,omitempty"`
}

// ConfigFile is a discovered agent/MCP configuration file, loaded eagerly so
// modules never race with the user's editor on re-read.
type ConfigFile struct {
	Path   string      `json:"path"`
	Agent  string      `json:"agent"` // claude-desktop, claude-code, cursor, vscode, windsurf, zed
	Kind   string      `json:"kind"`  // mcp, settings
	Format string      `json:"-"`     // json or jsonc
	Mode   fs.FileMode `json:"-"`
	Data   []byte      `json:"-"`
	Loaded time.Time   `json:"-"`
}

// Gap records a collection capability that was unavailable (e.g. permission
// denied, tool missing) so reports can distinguish "clean" from "blind".
type Gap struct {
	Module string `json:"module"`
	Reason string `json:"reason"`
}
