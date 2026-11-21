package cloud

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BillingConfig configures Stripe checkout creation.
type BillingConfig struct {
	SecretKey  string
	PricePro   string
	PriceTeam  string
	APIBase    string
	SuccessURL string
	CancelURL  string
	Client     *http.Client
}

func (s *Server) handleCheckout(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.auth(w, r)
	if !ok {
		return
	}
	var req struct {
		Plan string `json:"plan"`
	}
	if err := decodeJSON(r, &req, 1<<16); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	plan := Plan(strings.ToLower(strings.TrimSpace(req.Plan)))
	var price string
	switch plan {
	case PlanPro:
		price = s.cfg.Billing.PricePro
	case PlanTeam:
		price = s.cfg.Billing.PriceTeam
	default:
		writeError(w, http.StatusBadRequest, "plan must be pro or team")
		return
	}
	if s.cfg.Billing.SecretKey == "" || price == "" {
		writeError(w, http.StatusServiceUnavailable, "billing is not configured")
		return
	}

	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("line_items[0][price]", price)
	form.Set("line_items[0][quantity]", "1")
	form.Set("success_url", s.cfg.Billing.SuccessURL)
	form.Set("cancel_url", s.cfg.Billing.CancelURL)
	form.Set("client_reference_id", tok.ID)
	form.Set("metadata[token_id]", tok.ID)
	form.Set("metadata[plan]", string(plan))
	if tok.Org != "" {
		form.Set("metadata[org]", tok.Org)
	}

	client := s.cfg.Billing.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	apiBase := s.cfg.Billing.APIBase
	if apiBase == "" {
		apiBase = "https://api.stripe.com"
	}
	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		strings.TrimRight(apiBase, "/")+"/v1/checkout/sessions", strings.NewReader(form.Encode()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpReq.Header.Set("Authorization", "Bearer "+s.cfg.Billing.SecretKey)
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("User-Agent", "enki-cloud/0.3")

	resp, err := client.Do(httpReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "stripe request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, "stripe returned HTTP "+resp.Status)
		return
	}
	var session struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &session); err != nil || session.URL == "" {
		writeError(w, http.StatusBadGateway, "invalid stripe response")
		return
	}
	_ = s.store.Audit(r.Context(), Event{
		TokenID: tok.ID, Plan: tok.Plan, Action: "billing_checkout", Detail: string(plan),
	})
	writeJSON(w, http.StatusOK, map[string]string{"checkout_url": session.URL, "session_id": session.ID})
}
