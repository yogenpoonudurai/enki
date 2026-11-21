package cloud

import (
	"errors"
	"net/http"
	"net/mail"
	"strings"
)

type waitlistRequest struct {
	Email   string `json:"email"`
	Role    string `json:"role"`
	UseCase string `json:"use_case"`
}

func (s *Server) handleWaitlist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req waitlistRequest
	if err := decodeJSON(r, &req, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	email, err := normalizeEmail(req.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entry := WaitlistEntry{
		Email:   email,
		Role:    cleanField(req.Role, 80),
		UseCase: cleanField(req.UseCase, 280),
	}
	created, err := s.store.AddWaitlist(entry)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	_ = s.store.Audit(r.Context(), Event{Action: "waitlist_signup", Detail: "signup"})
	if created {
		writeJSON(w, http.StatusCreated, map[string]string{"status": "accepted"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "already subscribed"})
}

func (s *Server) handleWaitlistAdmin(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeError(w, http.StatusUnauthorized, "admin key required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(s.store.ListWaitlist()),
		"entries": s.store.ListWaitlist(),
	})
}

func normalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > 254 {
		return "", errors.New("a valid email is required")
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || strings.ToLower(addr.Address) != email {
		return "", errors.New("a valid email is required")
	}
	return email, nil
}

func cleanField(s string, max int) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= max {
			break
		}
	}
	return b.String()
}
