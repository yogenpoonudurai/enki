package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const maxConfigSize = 2 << 20

type configTarget struct {
	path  string
	agent string
	kind  string
}

// DiscoverConfigs locates MCP and agent configuration files for supported
// tools, both user-level and repository-level (relative to workdir).
func DiscoverConfigs(home, workdir string) ([]ConfigFile, []Gap) {
	cfgDir, _ := os.UserConfigDir()

	var targets []configTarget
	add := func(path, agent, kind string) {
		if path != "" {
			targets = append(targets, configTarget{path: path, agent: agent, kind: kind})
		}
	}

	// Claude Desktop
	if cfgDir != "" {
		add(filepath.Join(cfgDir, "Claude", "claude_desktop_config.json"), "claude-desktop", "mcp")
	}
	// Claude Code
	add(filepath.Join(home, ".claude.json"), "claude-code", "mcp")
	add(filepath.Join(home, ".claude", "settings.json"), "claude-code", "settings")
	// Cursor
	add(filepath.Join(home, ".cursor", "mcp.json"), "cursor", "mcp")
	// VS Code
	if cfgDir != "" {
		add(filepath.Join(cfgDir, "Code", "User", "mcp.json"), "vscode", "mcp")
		add(filepath.Join(cfgDir, "Code", "User", "settings.json"), "vscode", "settings")
	}
	// Windsurf
	add(filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), "windsurf", "mcp")
	// Zed
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			add(filepath.Join(appData, "Zed", "settings.json"), "zed", "settings")
		}
	} else {
		add(filepath.Join(home, ".config", "zed", "settings.json"), "zed", "settings")
	}

	// Repository-scoped configuration in the current working directory.
	add(filepath.Join(workdir, ".mcp.json"), "claude-code", "mcp")
	add(filepath.Join(workdir, ".claude", "settings.json"), "claude-code", "settings")
	add(filepath.Join(workdir, ".claude", "settings.local.json"), "claude-code", "settings")
	add(filepath.Join(workdir, ".cursor", "mcp.json"), "cursor", "mcp")
	add(filepath.Join(workdir, ".vscode", "mcp.json"), "vscode", "mcp")
	add(filepath.Join(workdir, ".vscode", "settings.json"), "vscode", "settings")
	add(filepath.Join(workdir, ".zed", "settings.json"), "zed", "settings")
	add(filepath.Join(workdir, ".windsurf", "mcp_config.json"), "windsurf", "mcp")

	seen := map[string]bool{}
	var out []ConfigFile
	var gaps []Gap
	for _, t := range targets {
		p := filepath.Clean(t.path)
		if seen[p] {
			continue
		}
		seen[p] = true

		info, err := os.Stat(p)
		if err != nil {
			continue // absent configs are the norm
		}
		if info.IsDir() {
			continue
		}
		if info.Size() > maxConfigSize {
			gaps = append(gaps, Gap{Module: "config", Reason: fmt.Sprintf("skipped oversized config %s", p)})
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			gaps = append(gaps, Gap{Module: "config", Reason: fmt.Sprintf("cannot read %s (permission denied?)", p)})
			continue
		}
		out = append(out, ConfigFile{
			Path:   p,
			Agent:  t.agent,
			Kind:   t.kind,
			Format: "json",
			Mode:   info.Mode(),
			Data:   data,
			Loaded: time.Now(),
		})
	}
	return out, gaps
}
