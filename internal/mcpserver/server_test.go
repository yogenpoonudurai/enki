package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	server := New()
	st, ct := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "enki-test", Version: "0"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func callText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("%s returned an error result", name)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestToolsListed(t *testing.T) {
	cs := connect(t)
	names := toolNames(t, cs)
	want := []string{"enki_scan", "enki_plan_fix", "enki_rules", "enki_sbom", "enki_explain_rule", "enki_triage"}
	for _, w := range want {
		found := false
		for _, n := range names {
			if n == w {
				found = true
			}
		}
		if !found {
			t.Errorf("missing tool %s in %v", w, names)
		}
	}
}

func TestRulesTool(t *testing.T) {
	cs := connect(t)
	out := callText(t, cs, "enki_rules", map[string]any{"module": "mcp"})
	if !strings.Contains(out, "MCP-001") || !strings.Contains(out, "builtin-1") {
		t.Fatalf("rules output = %s", out)
	}
	if strings.Contains(out, "AEP-001") {
		t.Fatal("module filter leaked other modules")
	}
}

func TestExplainTool(t *testing.T) {
	cs := connect(t)
	out := callText(t, cs, "enki_explain_rule", map[string]any{"rule_id": "AEP-001"})
	if !strings.Contains(out, "AEP-001") || !strings.Contains(out, "endpoint-exposure") {
		t.Fatalf("explain output = %s", out)
	}
}

func TestScanToolAgentModule(t *testing.T) {
	cs := connect(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(`{"mcpServers":{"x":{"command":"npx","args":["-y","unpinned"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := callText(t, cs, "enki_scan", map[string]any{
		"paths":       []string{dir},
		"modules":     []string{"agent-permissions"},
		"os_packages": false,
		"include_dev": false,
	})
	if !strings.Contains(out, `"tool"`) || !strings.Contains(out, `"findings"`) {
		t.Fatalf("scan output not a report: %.200s", out)
	}
}

func TestSBOMTool(t *testing.T) {
	cs := connect(t)
	dir := t.TempDir()
	pkg := `{"name":"fixture","version":"1.0.0","dependencies":{"openai":"4.0.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatal(err)
	}
	out := callText(t, cs, "enki_sbom", map[string]any{
		"paths":       []string{dir},
		"os_packages": false,
	})
	if !strings.Contains(out, "CycloneDX") || !strings.Contains(out, "pkg:npm/openai@4.0.0") {
		t.Fatalf("sbom output = %.300s", out)
	}
}

func TestExplainUnknownRule(t *testing.T) {
	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "enki_explain_rule",
		Arguments: map[string]any{"rule_id": "NOPE-999"},
	})
	if err != nil {
		return // transport-level error is acceptable for unknown rules
	}
	if !res.IsError {
		t.Fatal("unknown rule should return an error result")
	}
}
