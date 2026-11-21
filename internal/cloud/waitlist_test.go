package cloud

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestWaitlistSignup(t *testing.T) {
	srv, store, _ := setup(t)

	rec := do(srv, "POST", "/v1/waitlist", map[string]any{
		"email":    "Alice@Example.com",
		"role":     "Platform engineer",
		"use_case": "Audit GPU hosts and CI",
	}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("code = %d (%s)", rec.Code, rec.Body.String())
	}
	entries := store.ListWaitlist()
	if len(entries) != 1 || entries[0].Email != "alice@example.com" {
		t.Fatalf("entries = %+v", entries)
	}
	if entries[0].Role != "Platform engineer" {
		t.Fatalf("role = %q", entries[0].Role)
	}

	dup := do(srv, "POST", "/v1/waitlist", map[string]any{"email": "alice@example.com"}, nil)
	if dup.Code != http.StatusOK || !strings.Contains(dup.Body.String(), "already subscribed") {
		t.Fatalf("duplicate = %d %s", dup.Code, dup.Body.String())
	}
	if len(store.ListWaitlist()) != 1 {
		t.Fatal("duplicate stored")
	}

	if rec := do(srv, "POST", "/v1/waitlist", map[string]any{"email": "not-an-email"}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid email code = %d", rec.Code)
	}
}

func TestWaitlistCORS(t *testing.T) {
	srv, _, _ := setup(t)
	rec := do(srv, "OPTIONS", "/v1/waitlist", nil, map[string]string{"Origin": "https://example.com"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing CORS header")
	}
}

func TestWaitlistAdmin(t *testing.T) {
	srv, _, _ := setup(t)
	do(srv, "POST", "/v1/waitlist", map[string]any{"email": "bob@example.com"}, nil)

	if rec := do(srv, "GET", "/v1/admin/waitlist", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized code = %d", rec.Code)
	}
	rec := do(srv, "GET", "/v1/admin/waitlist", nil, map[string]string{"Authorization": "Bearer admin-secret"})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin code = %d", rec.Code)
	}
	var out struct {
		Count   int             `json:"count"`
		Entries []WaitlistEntry `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || out.Entries[0].Email != "bob@example.com" {
		t.Fatalf("admin output = %+v", out)
	}
}
