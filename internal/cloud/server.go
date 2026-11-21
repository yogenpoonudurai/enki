package cloud

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yogenpoonudurai/enki/internal/ai"
	"github.com/yogenpoonudurai/enki/internal/report"
)

// Config configures the hosted triage service.
type Config struct {
	AdminKey            string
	StripeWebhookSecret string
	Model               string
	Retention           time.Duration
	Now                 func() time.Time
	MaxReportBytes      int64
	TriageLimit         int
	ProviderFactory     func(byokKey string) (ai.Provider, error)
	Billing             BillingConfig
}

// Server is the hosted triage HTTP API.
type Server struct {
	cfg   Config
	store *MemoryStore
	mux   *http.ServeMux
}

// New builds the API server.
func New(cfg Config, store *MemoryStore) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 24 * time.Hour
	}
	if cfg.MaxReportBytes <= 0 {
		cfg.MaxReportBytes = 5 << 20
	}
	if cfg.TriageLimit <= 0 {
		cfg.TriageLimit = 40
	}
	if cfg.Model == "" {
		cfg.Model = ai.DefaultConfig().Model
	}
	if cfg.ProviderFactory == nil {
		cfg.ProviderFactory = defaultProviderFactory
	}
	s := &Server{cfg: cfg, store: store, mux: http.NewServeMux()}
	s.mux.Handle("/mcp", s.mcpHandler())
	s.mux.HandleFunc("POST /v1/triage", s.handleTriage)
	s.mux.HandleFunc("GET /v1/usage", s.handleUsage)
	s.mux.HandleFunc("POST /v1/admin/tokens", s.handleCreateToken)
	s.mux.HandleFunc("POST /v1/data/delete", s.handleDeleteData)
	s.mux.HandleFunc("/v1/waitlist", s.handleWaitlist)
	s.mux.HandleFunc("GET /v1/admin/waitlist", s.handleWaitlistAdmin)
	s.mux.HandleFunc("POST /v1/billing/checkout", s.handleCheckout)
	s.mux.HandleFunc("POST /v1/stripe/webhook", s.handleStripeWebhook)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return s
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

func defaultProviderFactory(byok string) (ai.Provider, error) {
	cfg := ai.DefaultConfig()
	if byok != "" {
		cfg.APIKey = byok
		if cfg.Provider == "" {
			cfg.Provider = "deepseek"
		}
		if cfg.BaseURL == "" {
			cfg.BaseURL = "https://api.deepseek.com"
		}
	}
	return ai.NewProvider(cfg)
}

type usageInfo struct {
	Plan      Plan   `json:"plan"`
	Remaining int    `json:"remaining"`
	FreeQuota int    `json:"free_quota,omitempty"`
	Org       string `json:"org,omitempty"`
}

func usageFor(t *Token) usageInfo {
	u := usageInfo{Plan: t.Plan, Remaining: t.Remaining(), Org: t.Org}
	if t.Plan == PlanFree {
		u.FreeQuota = FreeQuota
	}
	return u
}

type triageRequest struct {
	Report  json.RawMessage `json:"report"`
	Consent bool            `json:"consent"`
}

type triageResponse struct {
	Result *ai.TriageResult `json:"result"`
	Usage  usageInfo        `json:"usage"`
	Cached bool             `json:"cached,omitempty"`
}

type providerConfigError struct{ err error }

func (e providerConfigError) Error() string { return "provider configuration error: " + e.err.Error() }
func (e providerConfigError) Unwrap() error { return e.err }

type providerCallError struct{ err error }

func (e providerCallError) Error() string { return "triage provider error: " + e.err.Error() }
func (e providerCallError) Unwrap() error { return e.err }

// triageForToken implements the shared triage pipeline for the REST and MCP
// surfaces: cache, quota, provider call, refund on failure, audit.
func (s *Server) triageForToken(ctx context.Context, tok *Token, byok string, rep *report.Report) (*ai.TriageResult, usageInfo, bool, error) {
	payload := ai.BuildPayload(rep, s.cfg.TriageLimit)
	digest := payloadDigest(payload)
	now := s.cfg.Now()
	if cached, ok := s.store.GetCached(digest, now); ok {
		return cached, usageFor(tok), true, nil
	}

	remaining, err := s.store.Consume(ctx, tok.ID, byok != "")
	if err != nil {
		return nil, usageFor(tok), false, err
	}
	provider, err := s.cfg.ProviderFactory(byok)
	if err != nil {
		if byok == "" {
			s.store.Refund(ctx, tok.ID)
		}
		return nil, usageFor(tok), false, providerConfigError{err}
	}

	tctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	result, _, err := ai.Triage(tctx, provider, s.cfg.Model, rep, s.cfg.TriageLimit)
	if err != nil {
		if byok == "" {
			s.store.Refund(ctx, tok.ID)
		}
		return nil, usageFor(tok), false, providerCallError{err}
	}

	s.store.PutCached(digest, result, s.cfg.Retention, now)
	detail := "server-key"
	if byok != "" {
		detail = "byok"
	}
	_ = s.store.Audit(ctx, Event{
		Time: now, TokenID: tok.ID, Plan: tok.Plan, Action: "triage",
		Findings: len(payload.Findings), CostUSD: result.Cost.USD, Detail: detail,
	})

	usage := usageFor(tok)
	if byok == "" {
		usage.Remaining = remaining
	}
	if fresh, err := s.store.GetToken(ctx, tok.ID); err == nil {
		usage = usageFor(fresh)
	}
	return result, usage, false, nil
}

func (s *Server) handleTriage(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.auth(w, r)
	if !ok {
		return
	}
	var req triageRequest
	if err := decodeJSON(r, &req, s.cfg.MaxReportBytes); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !req.Consent {
		writeError(w, http.StatusBadRequest,
			"consent required: confirm that a redacted findings payload may be sent to the model provider")
		return
	}
	var rep report.Report
	if err := json.Unmarshal(req.Report, &rep); err != nil {
		writeError(w, http.StatusBadRequest, "invalid enki report: "+err.Error())
		return
	}

	byok := strings.TrimSpace(r.Header.Get("X-Enki-Provider-Key"))

	result, usage, cached, err := s.triageForToken(r.Context(), tok, byok, &rep)
	if err != nil {
		switch {
		case errors.Is(err, ErrQuotaExceeded):
			writeJSON(w, http.StatusPaymentRequired, map[string]any{
				"error":   "free triage quota exhausted",
				"upgrade": "subscribe to Pro for more triage credits, or supply X-Enki-Provider-Key",
				"usage":   usageFor(tok),
			})
		case errors.Is(err, ErrUnauthorized):
			writeError(w, http.StatusUnauthorized, "invalid token")
		default:
			var cfgErr providerConfigError
			if errors.As(err, &cfgErr) {
				writeError(w, http.StatusInternalServerError, err.Error())
			} else {
				writeError(w, http.StatusBadGateway, err.Error())
			}
		}
		return
	}
	writeJSON(w, http.StatusOK, triageResponse{Result: result, Usage: usage, Cached: cached})
}

func payloadDigest(p *ai.Payload) string {
	data, _ := json.Marshal(p)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.auth(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, usageFor(tok))
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeError(w, http.StatusUnauthorized, "admin key required")
		return
	}
	var req struct {
		Plan    Plan   `json:"plan"`
		Credits int    `json:"credits"`
		Org     string `json:"org"`
	}
	if err := decodeJSON(r, &req, 1<<16); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch req.Plan {
	case PlanFree, PlanPro, PlanTeam, PlanEnterprise:
	default:
		writeError(w, http.StatusBadRequest, "plan must be free, pro, team, or enterprise")
		return
	}
	if req.Credits == 0 {
		switch req.Plan {
		case PlanPro:
			req.Credits = 300
		case PlanTeam:
			req.Credits = 1000
		}
	}
	tok := &Token{Plan: req.Plan, Credits: req.Credits, Org: req.Org}
	if err := s.store.CreateToken(r.Context(), tok); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.Audit(r.Context(), Event{TokenID: tok.ID, Plan: tok.Plan, Action: "token_create", Detail: req.Org})
	writeJSON(w, http.StatusCreated, map[string]any{"token": tok.ID, "usage": usageFor(tok)})
}

func (s *Server) handleDeleteData(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.auth(w, r)
	if !ok {
		return
	}
	removed := s.store.DeleteTokenData(r.Context(), tok.ID)
	_ = s.store.Audit(r.Context(), Event{TokenID: tok.ID, Plan: tok.Plan, Action: "data_delete", Detail: "audit events removed"})
	writeJSON(w, http.StatusOK, map[string]int{"audit_events_removed": removed})
}

func (s *Server) auth(w http.ResponseWriter, r *http.Request) (*Token, bool) {
	id := bearerToken(r)
	if id == "" {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return nil, false
	}
	tok, err := s.store.GetToken(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return nil, false
	}
	return tok, true
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

func (s *Server) isAdmin(r *http.Request) bool {
	if s.cfg.AdminKey == "" {
		return false
	}
	key := r.Header.Get("X-Admin-Key")
	if key == "" {
		key = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(s.cfg.AdminKey)) == 1
}

func decodeJSON(r *http.Request, v any, maxBytes int64) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBytes))
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body: " + err.Error())
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("unexpected trailing data in JSON body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// StartPurge periodically removes audit events and cached results older than
// the retention window.
func (s *Server) StartPurge(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.store.Purge(ctx, now.Add(-s.cfg.Retention))
		}
	}
}
