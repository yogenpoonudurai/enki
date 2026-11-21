package cloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yogenpoonudurai/enki/internal/ai"
	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/report"
)

type fakeProvider struct {
	lastKey string
	calls   int
}

func (f *fakeProvider) Name() string { return "fake" }

func (f *fakeProvider) Complete(_ context.Context, _ ai.Request) (ai.Response, error) {
	f.calls++
	return ai.Response{
		Text:         `{"summary":"Focus on the exposed endpoint.","top":[{"finding_id":"f1","rule_id":"AEP-001","priority":1,"why":"reachable","recommended_action":"manual","action_verified":true}]}`,
		Model:        "deepseek-flash",
		InputTokens:  1200,
		OutputTokens: 120,
	}, nil
}

var fixedNow = time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)

func testReport(t *testing.T) []byte {
	t.Helper()
	rep := report.Report{
		Tool: report.Tool{Name: "enki", Version: "test", SchemaVersion: "1"},
		Scan: report.Scan{ID: "scan", Host: "unit", OS: "linux", Arch: "amd64", User: "tester"},
		Summary: report.Summary{
			Score: 80, Verdict: "AT RISK",
			Counts: map[string]int{"CRITICAL": 1},
		},
		Findings: []finding.Finding{{
			ID: "f1", RuleID: "AEP-001", Module: "endpoint-exposure",
			Title: "Ollama exposed on 0.0.0.0:11434", Description: "d",
			Severity: finding.SeverityCritical, Confidence: finding.ConfidenceHigh,
			Location: finding.Location{Addr: "0.0.0.0:11434"},
		}},
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func setup(t *testing.T) (*Server, *MemoryStore, *fakeProvider) {
	t.Helper()
	store := NewMemoryStore()
	fp := &fakeProvider{}
	srv := New(Config{
		AdminKey:            "admin-secret",
		StripeWebhookSecret: "whsec_test",
		Model:               "deepseek-flash",
		Now:                 func() time.Time { return fixedNow },
		Retention:           24 * time.Hour,
		ProviderFactory: func(key string) (ai.Provider, error) {
			fp.lastKey = key
			return fp, nil
		},
	}, store)
	if err := store.CreateToken(context.Background(), &Token{ID: "tok_test", Plan: PlanFree}); err != nil {
		t.Fatal(err)
	}
	return srv, store, fp
}

func do(srv *Server, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		switch v := body.(type) {
		case []byte:
			reader = bytes.NewReader(v)
		default:
			data, _ := json.Marshal(v)
			reader = bytes.NewReader(data)
		}
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func authHeader() map[string]string {
	return map[string]string{"Authorization": "Bearer tok_test"}
}

func triageBody(t *testing.T) map[string]any {
	return map[string]any{"report": json.RawMessage(testReport(t)), "consent": true}
}

func TestAuthAndConsent(t *testing.T) {
	srv, _, _ := setup(t)
	if rec := do(srv, "POST", "/v1/triage", triageBody(t), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth code = %d", rec.Code)
	}
	body := triageBody(t)
	body["consent"] = false
	if rec := do(srv, "POST", "/v1/triage", body, authHeader()); rec.Code != http.StatusBadRequest {
		t.Fatalf("consent code = %d", rec.Code)
	}
}

func TestFreeQuota(t *testing.T) {
	srv, store, _ := setup(t)
	for i := 0; i < FreeQuota; i++ {
		body := triageBody(t)
		body["report"] = json.RawMessage(bytes.Replace(
			testReport(t), []byte("Ollama exposed on"), []byte(fmt.Sprintf("Ollama exposed on %d", i+1)), 1))
		rec := do(srv, "POST", "/v1/triage", body, authHeader())
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d code = %d (%s)", i+1, rec.Code, rec.Body.String())
		}
	}
	body := triageBody(t)
	body["report"] = json.RawMessage(bytes.Replace(
		testReport(t), []byte("Ollama exposed on"), []byte("Ollama exposed on final"), 1))
	rec := do(srv, "POST", "/v1/triage", body, authHeader())
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("4th call code = %d, want 402", rec.Code)
	}
	tok, _ := store.GetToken(context.Background(), "tok_test")
	if tok.Remaining() != 0 {
		t.Fatalf("remaining = %d", tok.Remaining())
	}
}

func TestBYOKDoesNotConsume(t *testing.T) {
	srv, store, fp := setup(t)
	h := authHeader()
	h["X-Enki-Provider-Key"] = "byok-key"
	rec := do(srv, "POST", "/v1/triage", triageBody(t), h)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	if fp.lastKey != "byok-key" {
		t.Fatalf("provider key = %q", fp.lastKey)
	}
	tok, _ := store.GetToken(context.Background(), "tok_test")
	if tok.Remaining() != FreeQuota {
		t.Fatalf("BYOK consumed quota: remaining %d", tok.Remaining())
	}
}

func TestCachedResultDoesNotConsume(t *testing.T) {
	srv, store, fp := setup(t)
	first := do(srv, "POST", "/v1/triage", triageBody(t), authHeader())
	second := do(srv, "POST", "/v1/triage", triageBody(t), authHeader())
	if first.Code != 200 || second.Code != 200 {
		t.Fatalf("codes = %d/%d", first.Code, second.Code)
	}
	if !strings.Contains(second.Body.String(), `"cached":true`) {
		t.Fatalf("second call not cached: %s", second.Body.String())
	}
	if fp.calls != 1 {
		t.Fatalf("provider calls = %d, want 1", fp.calls)
	}
	tok, _ := store.GetToken(context.Background(), "tok_test")
	if tok.Remaining() != FreeQuota-1 {
		t.Fatalf("cache consumed a credit: remaining %d", tok.Remaining())
	}
}

func TestPurgeAndDeleteData(t *testing.T) {
	srv, store, _ := setup(t)
	if rec := do(srv, "POST", "/v1/triage", triageBody(t), authHeader()); rec.Code != 200 {
		t.Fatalf("triage code = %d", rec.Code)
	}
	if len(store.ListAudit(context.Background(), "tok_test")) == 0 {
		t.Fatal("audit event missing")
	}
	events, _ := store.Purge(context.Background(), fixedNow.Add(25*time.Hour))
	if events == 0 {
		t.Fatal("purge removed nothing")
	}
	// Use a different report so the cache does not absorb the call.
	body := triageBody(t)
	body["report"] = json.RawMessage(bytes.Replace(
		testReport(t), []byte("Ollama exposed on"), []byte("Ollama reachable on"), 1))
	if rec := do(srv, "POST", "/v1/triage", body, authHeader()); rec.Code != 200 {
		t.Fatalf("second triage code = %d", rec.Code)
	}
	rec := do(srv, "POST", "/v1/data/delete", nil, authHeader())
	if rec.Code != 200 {
		t.Fatalf("delete code = %d", rec.Code)
	}
	remaining := store.ListAudit(context.Background(), "tok_test")
	if len(remaining) != 1 || remaining[0].Action != "data_delete" {
		t.Fatalf("data delete should leave only the deletion audit record: %+v", remaining)
	}
}

func TestAdminTokensAndUsage(t *testing.T) {
	srv, _, _ := setup(t)
	if rec := do(srv, "POST", "/v1/admin/tokens", map[string]any{"plan": "pro"}, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin without key code = %d", rec.Code)
	}
	rec := do(srv, "POST", "/v1/admin/tokens", map[string]any{"plan": "pro", "org": "acme"},
		map[string]string{"Authorization": "Bearer admin-secret"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin create code = %d (%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Token == "" {
		t.Fatalf("created token = %q", created.Token)
	}
	usage := do(srv, "GET", "/v1/usage", nil, map[string]string{"Authorization": "Bearer " + created.Token})
	if usage.Code != 200 || !strings.Contains(usage.Body.String(), `"remaining":300`) {
		t.Fatalf("usage = %d %s", usage.Code, usage.Body.String())
	}
}

func TestAuditHasNoFindingContent(t *testing.T) {
	srv, store, _ := setup(t)
	do(srv, "POST", "/v1/triage", triageBody(t), authHeader())
	events := store.ListAudit(context.Background(), "tok_test")
	if len(events) == 0 {
		t.Fatal("no audit events")
	}
	data, _ := json.Marshal(events)
	for _, forbidden := range []string{"Ollama", "0.0.0.0", "api/tags"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("audit leaked %q: %s", forbidden, data)
		}
	}
}

func stripeSign(secret string, body []byte, ts time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", ts.Unix())
	mac.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

func TestStripeWebhookUpgradesPlan(t *testing.T) {
	srv, store, _ := setup(t)
	event := map[string]any{
		"type": "checkout.session.completed",
		"data": map[string]any{"object": map[string]any{
			"metadata": map[string]string{"token_id": "tok_test", "plan": "pro", "credits": "300"},
			"customer": "cus_123",
		}},
	}
	body, _ := json.Marshal(event)
	rec := do(srv, "POST", "/v1/stripe/webhook", body, map[string]string{
		"Stripe-Signature": stripeSign("whsec_test", body, fixedNow),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("webhook code = %d (%s)", rec.Code, rec.Body.String())
	}
	tok, _ := store.GetToken(context.Background(), "tok_test")
	if tok.Plan != PlanPro || tok.Credits != 300 {
		t.Fatalf("token after webhook = %+v", tok)
	}
}

func TestStripeWebhookRejectsBadSignature(t *testing.T) {
	srv, _, _ := setup(t)
	body := []byte(`{"type":"checkout.session.completed","data":{"object":{"metadata":{"token_id":"tok_test"}}}}`)
	rec := do(srv, "POST", "/v1/stripe/webhook", body, map[string]string{
		"Stripe-Signature": "t=1,v1=deadbeef",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad signature code = %d", rec.Code)
	}
}
