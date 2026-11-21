// Package hosted is the client for enki's paid hosted triage service.
//
// The service itself is a separate, private product. This package only speaks
// its HTTP contract: it uploads an already-redacted payload and reports the
// plan and allowance the server returns. It contains no entitlements, no
// license checks, and no local feature gating.
package hosted

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/yogenpoonudurai/enki/internal/ai"
	"github.com/yogenpoonudurai/enki/internal/version"
)

const (
	// EnvURL is the base URL of the hosted service.
	EnvURL = "ENKI_CLOUD_URL"
	// EnvToken is the account token used to authenticate.
	EnvToken = "ENKI_CLOUD_TOKEN"

	maxRequestBytes  = 5 << 20
	maxResponseBytes = 2 << 20
	defaultTimeout   = 90 * time.Second
)

// ErrConsentRequired is returned when consent was not given.
var ErrConsentRequired = errors.New("hosted triage requires consent")

// ErrUnauthorized is returned when the token is missing or invalid.
var ErrUnauthorized = errors.New("hosted service: invalid or missing token")

// QuotaError is returned when the account has no triage allowance left.
type QuotaError struct {
	Message string
	Upgrade string
	Usage   Usage
}

func (e *QuotaError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = "triage quota exhausted"
	}
	if e.Upgrade != "" {
		msg += " (" + e.Upgrade + ")"
	}
	return msg
}

// APIError is a non-success response that is not handled specially.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("hosted service returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("hosted service returned HTTP %d: %s", e.Status, e.Message)
}

// Config configures a Client.
type Config struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
	UserAgent  string
}

// ConfigFromEnv reads ENKI_CLOUD_URL and ENKI_CLOUD_TOKEN.
func ConfigFromEnv() Config {
	return Config{
		BaseURL: strings.TrimSpace(os.Getenv(EnvURL)),
		Token:   strings.TrimSpace(os.Getenv(EnvToken)),
	}
}

// Usage is the account allowance reported by the service.
type Usage struct {
	Plan      string `json:"plan"`
	Remaining int    `json:"remaining"`
	FreeQuota int    `json:"free_quota,omitempty"`
	Org       string `json:"org,omitempty"`
}

// Client talks to the hosted triage API.
type Client struct {
	baseURL   string
	token     string
	userAgent string
	http      *http.Client
}

// New validates config and builds a Client.
func New(cfg Config) (*Client, error) {
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, fmt.Errorf("%s is not set", EnvURL)
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", EnvURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("invalid %s: scheme must be http or https", EnvURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid %s: missing host", EnvURL)
	}
	if strings.TrimSpace(cfg.Token) == "" {
		return nil, fmt.Errorf("%s is not set", EnvToken)
	}
	ua := cfg.UserAgent
	if ua == "" {
		ua = "enki/" + version.Version
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: defaultTimeout,
			// The API never redirects; refusing keeps a configured endpoint
			// from silently bouncing the bearer token somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Client{baseURL: base, token: cfg.Token, userAgent: ua, http: hc}, nil
}

type triageRequest struct {
	Payload *ai.Payload `json:"payload"`
	Consent bool        `json:"consent"`
}

type triageResponse struct {
	Result *ai.TriageResult `json:"result"`
	Usage  Usage            `json:"usage"`
	Cached bool             `json:"cached,omitempty"`
}

type errorEnvelope struct {
	Error   string `json:"error"`
	Upgrade string `json:"upgrade,omitempty"`
	Usage   *Usage `json:"usage,omitempty"`
}

// Triage uploads a redacted payload and returns the ranking. providerKey is an
// optional BYOK key forwarded to the service; when it is set the call does not
// consume credits. The server-side cost is never surfaced to the caller.
func (c *Client) Triage(ctx context.Context, payload *ai.Payload, consent bool, providerKey string) (*ai.TriageResult, Usage, bool, error) {
	if !consent {
		return nil, Usage{}, false, ErrConsentRequired
	}
	if payload == nil {
		return nil, Usage{}, false, errors.New("hosted triage: payload is nil")
	}
	body, err := json.Marshal(triageRequest{Payload: payload, Consent: true})
	if err != nil {
		return nil, Usage{}, false, err
	}
	if len(body) > maxRequestBytes {
		return nil, Usage{}, false, fmt.Errorf("hosted triage: payload is %d bytes, limit is %d", len(body), maxRequestBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/triage", bytes.NewReader(body))
	if err != nil {
		return nil, Usage{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", "Bearer "+c.token)
	if key := strings.TrimSpace(providerKey); key != "" {
		req.Header.Set("X-Enki-Provider-Key", key)
	}

	var out triageResponse
	cached, err := c.do(req, &out)
	if err != nil {
		return nil, Usage{}, false, err
	}
	if out.Result == nil {
		return nil, out.Usage, cached, errors.New("hosted triage: response has no result")
	}
	if strings.TrimSpace(providerKey) == "" {
		out.Result.Cost.USD = 0
	}
	out.Result.Cost.Hosted = true
	return out.Result, out.Usage, cached, nil
}

// Usage returns the plan and remaining allowance for the account.
func (c *Client) Usage(ctx context.Context) (Usage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/usage", nil)
	if err != nil {
		return Usage{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Authorization", "Bearer "+c.token)

	var out Usage
	if _, err := c.do(req, &out); err != nil {
		return Usage{}, err
	}
	return out, nil
}

// do executes req, maps error statuses, and decodes a bounded JSON response.
// The returned bool reports whether the service answered from its cache.
func (c *Client) do(req *http.Request, out any) (cached bool, err error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return false, err
	}
	if int64(len(data)) > maxResponseBytes {
		return false, fmt.Errorf("hosted service response exceeds %d bytes", maxResponseBytes)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var env errorEnvelope
		_ = json.Unmarshal(data, &env)
		switch resp.StatusCode {
		case http.StatusBadRequest:
			return false, &APIError{Status: resp.StatusCode, Message: env.Error}
		case http.StatusUnauthorized, http.StatusForbidden:
			return false, fmt.Errorf("%w: %s", ErrUnauthorized, env.Error)
		case http.StatusPaymentRequired:
			q := &QuotaError{Message: env.Error, Upgrade: env.Upgrade}
			if env.Usage != nil {
				q.Usage = *env.Usage
			}
			return false, q
		default:
			return false, &APIError{Status: resp.StatusCode, Message: env.Error}
		}
	}

	var meta struct {
		Cached bool `json:"cached"`
	}
	if err := json.Unmarshal(data, &meta); err == nil {
		cached = meta.Cached
	}
	if err := json.Unmarshal(data, out); err != nil {
		return false, fmt.Errorf("hosted service returned invalid JSON: %w", err)
	}
	return cached, nil
}
