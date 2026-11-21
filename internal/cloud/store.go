// Package cloud implements the hosted enki triage beta: token auth, quota,
// consent, 24h retention, BYOK passthrough, and Stripe webhook hooks.
package cloud

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/yogenpoonudurai/enki/internal/ai"
)

type Plan string

const (
	PlanFree       Plan = "free"
	PlanPro        Plan = "pro"
	PlanTeam       Plan = "team"
	PlanEnterprise Plan = "enterprise"
)

const FreeQuota = 3

var (
	ErrUnauthorized  = errors.New("unauthorized")
	ErrQuotaExceeded = errors.New("triage quota exceeded")
)

// Token is a hosted account token.
type Token struct {
	ID        string    `json:"-"`
	Plan      Plan      `json:"plan"`
	Org       string    `json:"org,omitempty"`
	FreeUsed  int       `json:"free_used,omitempty"`
	Credits   int       `json:"credits"`
	CreatedAt time.Time `json:"created_at"`
}

// Remaining returns the triage allowance left (-1 = unlimited).
func (t *Token) Remaining() int {
	switch t.Plan {
	case PlanFree:
		return FreeQuota - t.FreeUsed
	case PlanEnterprise:
		return -1
	default:
		return t.Credits
	}
}

// Event is an audit record; it never contains finding content.
type Event struct {
	Time     time.Time `json:"time"`
	TokenID  string    `json:"token_id"`
	Plan     Plan      `json:"plan"`
	Action   string    `json:"action"`
	Findings int       `json:"findings,omitempty"`
	CostUSD  float64   `json:"cost_usd,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

type cachedResult struct {
	Result  *ai.TriageResult
	Expires time.Time
}

// MemoryStore is the beta store (Postgres later).
// WaitlistEntry is a hosted-beta signup. Email is stored lowercased; PII is
// never copied into audit events.
type WaitlistEntry struct {
	Email     string    `json:"email"`
	Role      string    `json:"role,omitempty"`
	UseCase   string    `json:"use_case,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

const maxWaitlist = 50000

type MemoryStore struct {
	mu            sync.Mutex
	tokens        map[string]*Token
	events        []Event
	cache         map[string]cachedResult
	waitlist      map[string]WaitlistEntry
	waitlistOrder []string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		tokens:   map[string]*Token{},
		cache:    map[string]cachedResult{},
		waitlist: map[string]WaitlistEntry{},
	}
}

func (s *MemoryStore) CreateToken(_ context.Context, t *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.ID == "" {
		t.ID = newTokenID()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	cp := *t
	s.tokens[t.ID] = &cp
	return nil
}

func (s *MemoryStore) GetToken(_ context.Context, id string) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return nil, ErrUnauthorized
	}
	cp := *t
	return &cp, nil
}

// UpdateToken replaces plan/credits while preserving ID and counters.
func (s *MemoryStore) UpdateToken(_ context.Context, id string, plan Plan, credits int, org string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return ErrUnauthorized
	}
	if plan != "" {
		t.Plan = plan
	}
	if credits >= 0 {
		t.Credits = credits
	}
	if org != "" {
		t.Org = org
	}
	return nil
}

// Consume reserves one triage; BYOK calls do not consume quota.
func (s *MemoryStore) Consume(_ context.Context, id string, byok bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return 0, ErrUnauthorized
	}
	if byok {
		return t.Remaining(), nil
	}
	switch t.Plan {
	case PlanFree:
		if t.FreeUsed >= FreeQuota {
			return 0, ErrQuotaExceeded
		}
		t.FreeUsed++
	case PlanEnterprise:
		return -1, nil
	default:
		if t.Credits <= 0 {
			return 0, ErrQuotaExceeded
		}
		t.Credits--
	}
	return t.Remaining(), nil
}

func (s *MemoryStore) Refund(_ context.Context, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return
	}
	switch t.Plan {
	case PlanFree:
		if t.FreeUsed > 0 {
			t.FreeUsed--
		}
	case PlanEnterprise:
	default:
		t.Credits++
	}
}

func (s *MemoryStore) Audit(_ context.Context, e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	s.events = append(s.events, e)
	return nil
}

func (s *MemoryStore) ListAudit(_ context.Context, tokenID string) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, e := range s.events {
		if tokenID == "" || e.TokenID == tokenID {
			out = append(out, e)
		}
	}
	return out
}

// Purge removes audit events older than the cutoff and expired cache entries.
func (s *MemoryStore) Purge(_ context.Context, cutoff time.Time) (events int, cache int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.events[:0]
	for _, e := range s.events {
		if e.Time.Before(cutoff) {
			events++
			continue
		}
		kept = append(kept, e)
	}
	s.events = kept
	now := time.Now()
	for k, v := range s.cache {
		if now.After(v.Expires) {
			delete(s.cache, k)
			cache++
		}
	}
	return events, cache
}

// DeleteTokenData removes audit events for a token (right-to-delete).
func (s *MemoryStore) DeleteTokenData(_ context.Context, tokenID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.events[:0]
	removed := 0
	for _, e := range s.events {
		if e.TokenID == tokenID {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	s.events = kept
	return removed
}

func (s *MemoryStore) GetCached(key string, now time.Time) (*ai.TriageResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.cache[key]
	if !ok || now.After(v.Expires) {
		return nil, false
	}
	return v.Result, true
}

func (s *MemoryStore) PutCached(key string, result *ai.TriageResult, ttl time.Duration, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[key] = cachedResult{Result: result, Expires: now.Add(ttl)}
}

func newTokenID() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return "enki_" + hex.EncodeToString(b[:])
}

// AddWaitlist inserts a signup. Returns false when the email already exists.
func (s *MemoryStore) AddWaitlist(e WaitlistEntry) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(e.Email))
	if _, ok := s.waitlist[key]; ok {
		return false, nil
	}
	if len(s.waitlist) >= maxWaitlist {
		return false, errors.New("waitlist is full")
	}
	e.Email = key
	e.CreatedAt = time.Now().UTC()
	s.waitlist[key] = e
	s.waitlistOrder = append(s.waitlistOrder, key)
	return true, nil
}

// ListWaitlist returns entries in signup order.
func (s *MemoryStore) ListWaitlist() []WaitlistEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]WaitlistEntry, 0, len(s.waitlistOrder))
	for _, key := range s.waitlistOrder {
		if e, ok := s.waitlist[key]; ok {
			out = append(out, e)
		}
	}
	return out
}
