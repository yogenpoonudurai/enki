package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yogenpoonudurai/enki/internal/ai"
)

func TestBillingCheckout(t *testing.T) {
	var gotForm url.Values
	var gotAuth string
	stripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		gotForm = r.PostForm
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id":  "cs_test_123",
			"url": "https://checkout.stripe.test/cs_test_123",
		})
	}))
	defer stripe.Close()

	store := NewMemoryStore()
	_ = store.CreateToken(context.Background(), &Token{ID: "tok_test", Plan: PlanFree, Org: "acme"})
	srv := New(Config{
		AdminKey: "admin",
		Billing: BillingConfig{
			SecretKey:  "sk_test",
			PricePro:   "price_pro",
			PriceTeam:  "price_team",
			APIBase:    stripe.URL,
			SuccessURL: "https://app.test/success",
			CancelURL:  "https://app.test/cancel",
		},
		ProviderFactory: func(string) (ai.Provider, error) { return nil, nil },
		Now:             func() time.Time { return fixedNow },
	}, store)

	rec := do(srv, "POST", "/v1/billing/checkout", map[string]any{"plan": "pro"}, authHeader())
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "https://checkout.stripe.test/cs_test_123") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if gotAuth != "Bearer sk_test" {
		t.Fatalf("stripe auth = %q", gotAuth)
	}
	if gotForm.Get("metadata[token_id]") != "tok_test" ||
		gotForm.Get("metadata[plan]") != "pro" ||
		gotForm.Get("line_items[0][price]") != "price_pro" ||
		gotForm.Get("mode") != "subscription" {
		t.Fatalf("stripe form = %v", gotForm)
	}
	if gotForm.Get("client_reference_id") != "tok_test" {
		t.Fatal("client_reference_id missing")
	}
}

func TestBillingCheckoutUnconfigured(t *testing.T) {
	srv, _, _ := setup(t) // no billing config
	rec := do(srv, "POST", "/v1/billing/checkout", map[string]any{"plan": "pro"}, authHeader())
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
}

func TestBillingCheckoutRequiresAuth(t *testing.T) {
	srv, _, _ := setup(t)
	rec := do(srv, "POST", "/v1/billing/checkout", map[string]any{"plan": "pro"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
}

func TestBillingCheckoutRejectsBadPlan(t *testing.T) {
	srv, _, _ := setup(t)
	rec := do(srv, "POST", "/v1/billing/checkout", map[string]any{"plan": "free"}, authHeader())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}
