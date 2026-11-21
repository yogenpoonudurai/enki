package mcp

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/collector"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

func TestUnpinnedPackage(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		args     []string
		wantPkg  string
		unpinned bool
	}{
		{"npx unpinned scoped", "npx", []string{"-y", "@upstash/context7-mcp"}, "@upstash/context7-mcp", true},
		{"npx pinned", "npx", []string{"-y", "pkg@1.4.2"}, "", false},
		{"npx latest", "npx", []string{"-y", "@scope/pkg@latest"}, "@scope/pkg@latest", true},
		{"npx package flag", "npx", []string{"-y", "--package=@mcp/server-filesystem@1.0.0"}, "", false},
		{"npx registry flag", "npx", []string{"--registry", "https://registry.npmjs.org", "chrome-devtools-mcp@0.21.0"}, "", false},
		{"npx registry flag unpinned", "npx", []string{"--registry", "https://registry.npmjs.org", "chrome-devtools-mcp"}, "chrome-devtools-mcp", true},
		{"npx cache and workspace", "npx", []string{"--cache", "/tmp/npm", "-w", "apps/web", "server@2.0.0"}, "", false},
		{"npx end of options", "npx", []string{"-y", "--", "server@2.0.0"}, "", false},
		{"npx.cmd unpinned", "npx.cmd", []string{"-y", "server"}, "server", true},
		{"uvx unpinned", "uvx", []string{"mcp-server-git"}, "mcp-server-git", true},
		{"uvx pinned", "uvx", []string{"--from", "pkg==1.2.3", "cmd"}, "", false},
		{"uvx index flag", "uvx", []string{"--index-url", "https://pypi.org/simple", "pkg==1.2.3"}, "", false},
		{"uvx index flag unpinned", "uvx", []string{"--index-url=https://pypi.org/simple", "mcp-server-git"}, "mcp-server-git", true},
		{"node not applicable", "node", []string{"server.js"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkg, unpinned := unpinnedPackage(tc.cmd, tc.args)
			if unpinned != tc.unpinned || pkg != tc.wantPkg {
				t.Fatalf("got (%q, %v), want (%q, %v)", pkg, unpinned, tc.wantPkg, tc.unpinned)
			}
		})
	}
}

func TestHasPinnedVersion(t *testing.T) {
	for spec, want := range map[string]bool{
		"pkg@1.2.3":       true,
		"@scope/pkg@2.0":  true,
		"@scope/pkg":      false,
		"pkg":             false,
		"pkg@latest":      false,
		"@scope/pkg@next": false,
	} {
		if got := hasPinnedVersion(spec); got != want {
			t.Errorf("hasPinnedVersion(%q) = %v, want %v", spec, got, want)
		}
	}
}

const mcpFixture = `{
  // comment must not break parsing
  "mcpServers": {
    "context7": {
      "command": "npx",
      "args": ["-y", "@upstash/context7-mcp"]
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
    },
    "pinned": {
      "command": "npx",
      "args": ["-y", "pinned-helper@1.4.2"]
    },
    "remote": {
      "type": "http",
      "url": "http://mcp.example.internal/sse"
    },
    "leaky": {
      "command": "npx",
      "args": ["-y", "pinned-helper@1.4.2"],
      "env": {"OPENAI_API_KEY": "sk-test-abcdefghijklmnopqrstuvwxyz123456"}
    },
    "shell-runner": {
      "command": "npx",
      "args": ["-y", "runner@1.0.0"]
    }
  }
}`

func TestServersFromJSONC(t *testing.T) {
	cf := collector.ConfigFile{Path: "/tmp/config.json", Data: []byte(mcpFixture)}
	defs, err := serversFrom(cf)
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) != 6 {
		t.Fatalf("servers = %d, want 6", len(defs))
	}
}

func TestRunFindsMCPRisks(t *testing.T) {
	cf := collector.ConfigFile{
		Path:  "/tmp/config.json",
		Agent: "claude-desktop",
		Kind:  "mcp",
		Mode:  fs.FileMode(0o644),
		Data:  []byte(mcpFixture),
	}
	sc := &scanner.Context{HomeDir: "/home/alice", Configs: []collector.ConfigFile{cf}}
	mod := New()
	fs, _, err := mod.Run(sc)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, f := range fs {
		got[f.RuleID] = true
	}
	for _, want := range []string{"MCP-001", "MCP-002", "MCP-003", "MCP-004", "MCP-005", "MCP-006"} {
		if !got[want] {
			t.Errorf("missing rule %s; got %v", want, got)
		}
	}

	for _, f := range fs {
		if f.RuleID == "MCP-001" && strings.Contains(f.Title, "pinned-helper") {
			t.Errorf("pinned package reported as unpinned: %s", f.Title)
		}
		if strings.Contains(f.Evidence, "sk-test-abcdefghijklmnopqrstuvwxyz123456") {
			t.Fatalf("secret leaked into evidence: %s", f.Evidence)
		}
		if f.RuleID == "MCP-006" && f.Remediation == nil {
			t.Fatal("MCP-006 should carry a machine remediation")
		}
	}
}

func TestBroadRoot(t *testing.T) {
	for _, arg := range []string{"/", "~", "/home/alice", "C:\\"} {
		if !broadRoot(arg, "/home/alice") {
			t.Errorf("broadRoot(%q) = false", arg)
		}
	}
	for _, arg := range []string{"./src", "/home/alice/project", ""} {
		if broadRoot(arg, "/home/alice") {
			t.Errorf("broadRoot(%q) = true", arg)
		}
	}
}
