package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func postInitialize(url string, header http.Header) int {
	req, err := http.NewRequest(http.MethodPost, url,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestHTTPAuth(t *testing.T) {
	srv := httptest.NewServer(HTTPHandler(New(), HTTPOptions{Token: "s3cret"}))
	t.Cleanup(srv.Close)

	cases := []struct {
		name   string
		path   string
		header http.Header
		want   int
	}{
		{"no token", "/mcp", nil, http.StatusUnauthorized},
		{"wrong token", "/mcp", http.Header{"Authorization": {"Bearer nope"}}, http.StatusUnauthorized},
		{"bare token without scheme", "/mcp", http.Header{"Authorization": {"s3cret"}}, http.StatusUnauthorized},
		{"valid token on /mcp", "/mcp", http.Header{"Authorization": {"Bearer s3cret"}}, http.StatusOK},
		{"valid token at root", "/", http.Header{"Authorization": {"Bearer s3cret"}}, http.StatusOK},
		{"healthz needs no token", "/healthz", nil, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := postInitialize(srv.URL+tc.path, tc.header); got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestHTTPSessionTools(t *testing.T) {
	srv := httptest.NewServer(HTTPHandler(New(), HTTPOptions{Token: "s3cret"}))
	t.Cleanup(srv.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "enki-http-test", Version: "0"}, nil)
	transport := &mcp.StreamableClientTransport{
		Endpoint: srv.URL + "/mcp",
		HTTPClient: &http.Client{
			Transport: bearerTransport{token: "s3cret", base: http.DefaultTransport},
			Timeout:   30 * time.Second,
		},
		DisableStandaloneSSE: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })

	for _, name := range toolNames(t, cs) {
		if !strings.HasPrefix(name, "enki_") {
			t.Errorf("unexpected tool %q", name)
		}
	}
	out := callText(t, cs, "enki_explain_rule", map[string]any{"rule_id": "AEP-001"})
	if !strings.Contains(out, "AEP-001") {
		t.Fatalf("explain over http output = %s", out)
	}
}
