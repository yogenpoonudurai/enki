package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type authTransport struct {
	token   string
	headers map[string]string
}

func (a authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+a.token)
	for k, v := range a.headers {
		r2.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r2)
}

func connectMCP(t *testing.T, ts *httptest.Server, transport authTransport) *sdkmcp.ClientSession {
	t.Helper()
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "enki-cloud-test"}, nil)
	cs, err := client.Connect(context.Background(), &sdkmcp.StreamableClientTransport{
		Endpoint:             ts.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: transport},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func reportObject(t *testing.T, title string) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(testReport(t), &obj); err != nil {
		t.Fatal(err)
	}
	findings, ok := obj["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatal("fixture report has no findings")
	}
	findings[0].(map[string]any)["title"] = title
	return obj
}

func callMCP(t *testing.T, cs *sdkmcp.ClientSession, name string, args map[string]any) (string, error) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdkmcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	if res.IsError {
		return b.String(), fmt.Errorf("tool error: %s", b.String())
	}
	return b.String(), nil
}

func TestMCPToolsAndTriage(t *testing.T) {
	srv, _, fp := setup(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	cs := connectMCP(t, ts, authTransport{token: "tok_test"})

	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range list.Tools {
		names[tool.Name] = true
	}
	for _, want := range []string{"enki_triage", "enki_plan_fix", "enki_rules", "enki_explain_rule", "enki_usage"} {
		if !names[want] {
			t.Errorf("missing tool %s", want)
		}
	}

	usage, err := callMCP(t, cs, "enki_usage", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(usage, `"plan": "free"`) || !strings.Contains(usage, `"remaining": 3`) {
		t.Fatalf("usage = %s", usage)
	}

	out, err := callMCP(t, cs, "enki_triage", map[string]any{
		"report":  reportObject(t, "Ollama exposed via MCP"),
		"consent": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Focus on the exposed endpoint.") {
		t.Fatalf("triage output = %s", out)
	}
	if fp.calls != 1 {
		t.Fatalf("provider calls = %d", fp.calls)
	}

	if _, err := callMCP(t, cs, "enki_triage", map[string]any{
		"report":  reportObject(t, "consent test"),
		"consent": false,
	}); err == nil {
		t.Fatal("triage without consent should fail")
	}
}

func TestMCPQuotaEnforced(t *testing.T) {
	srv, store, _ := setup(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	cs := connectMCP(t, ts, authTransport{token: "tok_test"})

	for i := 0; i < FreeQuota; i++ {
		if _, err := callMCP(t, cs, "enki_triage", map[string]any{
			"report":  reportObject(t, fmt.Sprintf("Ollama exposed %d", i)),
			"consent": true,
		}); err != nil {
			t.Fatalf("call %d failed: %v", i+1, err)
		}
	}
	if _, err := callMCP(t, cs, "enki_triage", map[string]any{
		"report":  reportObject(t, "quota exceeded"),
		"consent": true,
	}); err == nil {
		t.Fatal("4th triage should fail")
	}
	tok, _ := store.GetToken(context.Background(), "tok_test")
	if tok.Remaining() != 0 {
		t.Fatalf("remaining = %d", tok.Remaining())
	}
}

func TestMCPBYOK(t *testing.T) {
	srv, store, fp := setup(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	cs := connectMCP(t, ts, authTransport{
		token:   "tok_test",
		headers: map[string]string{"X-Enki-Provider-Key": "byok-key"},
	})

	if _, err := callMCP(t, cs, "enki_triage", map[string]any{
		"report":  reportObject(t, "byok"),
		"consent": true,
	}); err != nil {
		t.Fatal(err)
	}
	if fp.lastKey != "byok-key" {
		t.Fatalf("provider key = %q", fp.lastKey)
	}
	tok, _ := store.GetToken(context.Background(), "tok_test")
	if tok.Remaining() != FreeQuota {
		t.Fatalf("BYOK consumed quota: %d", tok.Remaining())
	}
}

func TestMCPPlanFixAndRules(t *testing.T) {
	srv, _, _ := setup(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	cs := connectMCP(t, ts, authTransport{token: "tok_test"})

	out, err := callMCP(t, cs, "enki_plan_fix", map[string]any{"report": reportObject(t, "plan")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"actions"`) {
		t.Fatalf("plan output = %s", out)
	}
	rulesOut, err := callMCP(t, cs, "enki_rules", map[string]any{"module": "mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rulesOut, "MCP-001") {
		t.Fatalf("rules output = %s", rulesOut)
	}
}

func TestMCPRequiresAuth(t *testing.T) {
	srv, _, _ := setup(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
