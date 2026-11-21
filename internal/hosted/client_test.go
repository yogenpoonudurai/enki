package hosted

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/ai"
)

func testPayload() *ai.Payload {
	return &ai.Payload{
		RubricVersion: ai.RubricVersion,
		Findings: []ai.PayloadFinding{{
			ID: "f1", RuleID: "SEC-001", Module: "secrets",
			Severity: "high", Confidence: "high", Title: "provider key in .env",
		}},
	}
}

func newTestClient(t *testing.T, h http.Handler, token string) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL + "/", Token: token})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestTriageSuccess(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/triage" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer enki_test" {
			t.Errorf("authorization = %q", got)
		}
		if r.Header.Get("X-Enki-Provider-Key") != "" {
			t.Errorf("unexpected provider key header")
		}
		if r.Header.Get("User-Agent") == "" {
			t.Errorf("missing user agent")
		}
		var body struct {
			Payload *ai.Payload `json:"payload"`
			Consent bool        `json:"consent"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
			return
		}
		if !body.Consent {
			t.Errorf("consent = false")
		}
		if body.Payload == nil || len(body.Payload.Findings) != 1 {
			t.Errorf("payload = %+v", body.Payload)
		}
		writeJSON(w, 200, map[string]any{
			"result": map[string]any{
				"summary": "ok", "top": []any{}, "rubric_version": ai.RubricVersion,
				"findings_sent": 1,
				"cost":          map[string]any{"model": "m", "usd": 0.02, "metered": true},
			},
			"usage":  map[string]any{"plan": "pro", "remaining": 299},
			"cached": true,
		})
	})
	c := newTestClient(t, handler, "enki_test")

	res, usage, cached, err := c.Triage(context.Background(), testPayload(), true, "")
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if !cached {
		t.Errorf("cached = false")
	}
	if usage.Plan != "pro" || usage.Remaining != 299 {
		t.Errorf("usage = %+v", usage)
	}
	if res.Summary != "ok" || res.FindingsSent != 1 {
		t.Errorf("result = %+v", res)
	}
	if res.Cost.USD != 0 {
		t.Errorf("server-side cost leaked: %v", res.Cost.USD)
	}
}

func TestTriageBYOK(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Enki-Provider-Key"); got != "sk-user" {
			t.Errorf("provider key = %q", got)
		}
		writeJSON(w, 200, map[string]any{
			"result": map[string]any{
				"summary": "ok", "top": []any{}, "findings_sent": 1,
				"cost": map[string]any{"model": "m", "usd": 0.02, "metered": true},
			},
			"usage": map[string]any{"plan": "free", "remaining": 3, "free_quota": 3},
		})
	})
	c := newTestClient(t, handler, "enki_test")

	res, _, _, err := c.Triage(context.Background(), testPayload(), true, "sk-user")
	if err != nil {
		t.Fatalf("Triage: %v", err)
	}
	if res.Cost.USD != 0.02 {
		t.Errorf("BYOK cost = %v", res.Cost.USD)
	}
}

func TestTriageRequiresConsent(t *testing.T) {
	hits := 0
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}), "enki_test")

	_, _, _, err := c.Triage(context.Background(), testPayload(), false, "")
	if !errors.Is(err, ErrConsentRequired) {
		t.Fatalf("err = %v", err)
	}
	if hits != 0 {
		t.Errorf("server called %d times", hits)
	}
}

func TestTriageUnauthorized(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
	}), "enki_secret_token")

	_, _, _, err := c.Triage(context.Background(), testPayload(), true, "")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "enki_secret_token") {
		t.Errorf("error leaks token: %v", err)
	}
}

func TestTriageQuota(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusPaymentRequired, map[string]any{
			"error":   "free triage quota exhausted",
			"upgrade": "subscribe to Pro",
			"usage":   map[string]any{"plan": "free", "remaining": 0, "free_quota": 3},
		})
	}), "enki_test")

	_, _, _, err := c.Triage(context.Background(), testPayload(), true, "")
	var q *QuotaError
	if !errors.As(err, &q) {
		t.Fatalf("err = %v", err)
	}
	if q.Upgrade != "subscribe to Pro" || q.Usage.Plan != "free" || q.Usage.FreeQuota != 3 {
		t.Errorf("quota error = %+v", q)
	}
}

func TestTriageBadRequest(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid enki report"})
	}), "enki_test")

	_, _, _, err := c.Triage(context.Background(), testPayload(), true, "")
	var api *APIError
	if !errors.As(err, &api) || api.Status != 400 || api.Message != "invalid enki report" {
		t.Fatalf("err = %v", err)
	}
}

func TestTriageServerError(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "provider unavailable"})
	}), "enki_test")

	_, _, _, err := c.Triage(context.Background(), testPayload(), true, "")
	var api *APIError
	if !errors.As(err, &api) || api.Status != 502 {
		t.Fatalf("err = %v", err)
	}
}

func TestTriageMalformedJSON(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"result":`))
	}), "enki_test")

	_, _, _, err := c.Triage(context.Background(), testPayload(), true, "")
	if err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("err = %v", err)
	}
}

func TestTriageResponseTooLarge(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", maxResponseBytes+1)))
	}), "enki_test")

	_, _, _, err := c.Triage(context.Background(), testPayload(), true, "")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v", err)
	}
}

func TestUsage(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/usage" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 200, map[string]any{"plan": "team", "remaining": 1000, "org": "acme"})
	}), "enki_test")

	u, err := c.Usage(context.Background())
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if u.Plan != "team" || u.Remaining != 1000 || u.Org != "acme" {
		t.Errorf("usage = %+v", u)
	}
}

func TestNewValidation(t *testing.T) {
	cases := []Config{
		{Token: "t"},
		{BaseURL: "ftp://example.com", Token: "t"},
		{BaseURL: "https://", Token: "t"},
		{BaseURL: "https://example.com"},
	}
	for _, cfg := range cases {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded, want error", cfg)
		}
	}
}

func TestNoRedirects(t *testing.T) {
	followed := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed = true
	}))
	defer target.Close()
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}), "enki_test")

	_, err := c.Usage(context.Background())
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusFound {
		t.Fatalf("err = %v", err)
	}
	if followed {
		t.Errorf("redirect was followed")
	}
}
