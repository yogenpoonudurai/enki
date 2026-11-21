package cloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const signatureTolerance = 5 * time.Minute

// verifyStripeSignature validates the Stripe-Signature header (t=...,v1=...).
func verifyStripeSignature(secret string, payload []byte, header string, now time.Time) error {
	if secret == "" {
		return errors.New("stripe webhook secret not configured")
	}
	var ts int64
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts, _ = strconv.ParseInt(kv[1], 10, 64)
		case "v1":
			sigs = append(sigs, kv[1])
		}
	}
	if ts == 0 || len(sigs) == 0 {
		return errors.New("malformed Stripe-Signature header")
	}
	signedAt := time.Unix(ts, 0)
	if delta := now.Sub(signedAt); delta > signatureTolerance || delta < -signatureTolerance {
		return errors.New("stripe signature timestamp outside tolerance")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	for _, sig := range sigs {
		if hmac.Equal([]byte(sig), []byte(expected)) {
			return nil
		}
	}
	return errors.New("invalid stripe signature")
}

type stripeEvent struct {
	Type string `json:"type"`
	Data struct {
		Object struct {
			Metadata          map[string]string `json:"metadata"`
			ClientReferenceID string            `json:"client_reference_id"`
			Customer          string            `json:"customer"`
		} `json:"object"`
	} `json:"data"`
}

func (s *Server) handleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StripeWebhookSecret == "" {
		writeError(w, http.StatusServiceUnavailable, "billing is not configured")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot read body")
		return
	}
	if err := verifyStripeSignature(s.cfg.StripeWebhookSecret, body, r.Header.Get("Stripe-Signature"), s.cfg.Now()); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var ev stripeEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		writeError(w, http.StatusBadRequest, "invalid event payload")
		return
	}

	obj := ev.Data.Object
	tokenID := obj.Metadata["token_id"]
	if tokenID == "" {
		tokenID = obj.ClientReferenceID
	}
	if tokenID == "" {
		writeJSON(w, http.StatusOK, map[string]bool{"received": true, "ignored": true})
		return
	}

	switch ev.Type {
	case "checkout.session.completed", "customer.subscription.created", "customer.subscription.updated", "invoice.paid":
		plan := Plan(obj.Metadata["plan"])
		if plan == "" {
			plan = PlanPro
		}
		credits := 0
		if v := obj.Metadata["credits"]; v != "" {
			credits, _ = strconv.Atoi(v)
		}
		if credits == 0 {
			switch plan {
			case PlanPro:
				credits = 300
			case PlanTeam:
				credits = 1000
			}
		}
		if err := s.store.UpdateToken(r.Context(), tokenID, plan, credits, obj.Metadata["org"]); err != nil {
			writeError(w, http.StatusNotFound, "unknown token for this event")
			return
		}
		_ = s.store.Audit(r.Context(), Event{
			TokenID: tokenID, Plan: plan, Action: "billing_" + ev.Type,
			Detail: "customer=" + obj.Customer,
		})
	default:
		writeJSON(w, http.StatusOK, map[string]bool{"received": true, "ignored": true})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"received": true})
}
