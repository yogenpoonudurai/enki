package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/platform"
)

const (
	osvBase    = "https://api.osv.dev"
	kevFeed    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssAPI    = "https://api.first.org/data/v1/epss"
	userAgent  = "enki/0.1 (AI-SPM scanner; +https://github.com/yogenpoonudurai/enki)"
	cacheTTL   = 24 * time.Hour
	kevName    = "kev.json"
	maxBodyLen = 32 << 20
)

// Query identifies one package version for vulnerability lookup.
type Query struct {
	Name      string
	Version   string
	Ecosystem string
}

// Advisory is the normalized subset of an OSV record enki uses.
type Advisory struct {
	ID       string           `json:"id"`
	Summary  string           `json:"summary,omitempty"`
	Details  string           `json:"details,omitempty"`
	Aliases  []string         `json:"aliases,omitempty"`
	Severity finding.Severity `json:"severity"`
	Fixed    []string         `json:"fixed,omitempty"`
	Refs     []string         `json:"refs,omitempty"`
	KEV      bool             `json:"kev,omitempty"`
	EPSS     float64          `json:"epss,omitempty"`
	CVSS     float64          `json:"cvss,omitempty"`
}

// Client abstracts OSV for testing.
type Client interface {
	QueryBatch(ctx context.Context, qs []Query) ([][]string, error)
	Advisory(ctx context.Context, id string) (*Advisory, error)
	Enrich(ctx context.Context, advs []*Advisory)
}

type httpClient struct {
	hc       *http.Client
	cacheDir string

	mu        sync.Mutex
	kev       map[string]bool
	kevLoaded bool
}

func newClient() *httpClient {
	return &httpClient{
		hc:       &http.Client{Timeout: 20 * time.Second},
		cacheDir: filepath.Join(platform.CacheDir(), "osv"),
	}
}

type osvQuery struct {
	Package osvPkg `json:"package"`
	Version string `json:"version"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// QueryBatch resolves package versions to advisory IDs in chunks.
func (c *httpClient) QueryBatch(ctx context.Context, qs []Query) ([][]string, error) {
	out := make([][]string, len(qs))
	const chunk = 500
	for start := 0; start < len(qs); start += chunk {
		end := start + chunk
		if end > len(qs) {
			end = len(qs)
		}
		req := osvBatchRequest{Queries: make([]osvQuery, 0, end-start)}
		for _, q := range qs[start:end] {
			req.Queries = append(req.Queries, osvQuery{
				Package: osvPkg{Name: q.Name, Ecosystem: q.Ecosystem},
				Version: q.Version,
			})
		}
		var resp osvBatchResponse
		if err := c.doJSON(ctx, http.MethodPost, osvBase+"/v1/querybatch", req, &resp); err != nil {
			return out, err
		}
		for i := 0; i < len(resp.Results) && start+i < len(out); i++ {
			ids := make([]string, 0, len(resp.Results[i].Vulns))
			for _, v := range resp.Results[i].Vulns {
				ids = append(ids, v.ID)
			}
			out[start+i] = ids
		}
	}
	return out, nil
}

type osvVuln struct {
	ID               string         `json:"id"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Aliases          []string       `json:"aliases"`
	Severity         []osvSeverity  `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
	Affected         []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Advisory fetches one OSV record, using the cache when fresh (or as a stale
// fallback when the network fails).
func (c *httpClient) Advisory(ctx context.Context, id string) (*Advisory, error) {
	cached, fresh := c.loadCache(id)
	if cached != nil && fresh {
		cached.KEV = c.isKEV(ctx, cached)
		return cached, nil
	}
	var raw osvVuln
	if err := c.doJSON(ctx, http.MethodGet, osvBase+"/v1/vulns/"+url.PathEscape(id), nil, &raw); err != nil {
		if cached != nil {
			return cached, nil
		}
		return nil, err
	}
	adv := convertVuln(&raw)
	adv.KEV = c.isKEV(ctx, adv)
	c.writeCache(id, adv)
	return adv, nil
}

func convertVuln(raw *osvVuln) *Advisory {
	adv := &Advisory{
		ID:       raw.ID,
		Summary:  strings.TrimSpace(raw.Summary),
		Details:  strings.TrimSpace(raw.Details),
		Aliases:  raw.Aliases,
		Severity: finding.SeverityMedium,
	}
	// Prefer a computed CVSS v3 base score; fall back to the GHSA qualitative
	// rating, then Medium. V4-only advisories still carry the GHSA rating.
	graded := false
	for _, s := range raw.Severity {
		if sev, score, ok := severityFromVector(s.Score); ok {
			adv.Severity = sev
			adv.CVSS = score
			graded = true
			break
		}
	}
	if !graded {
		if sev, ok := raw.DatabaseSpecific["severity"].(string); ok {
			adv.Severity = mapGitHubSeverity(sev)
		}
	}
	seenRef := map[string]bool{}
	for _, ref := range raw.References {
		if ref.URL != "" && !seenRef[ref.URL] && len(adv.Refs) < 5 {
			seenRef[ref.URL] = true
			adv.Refs = append(adv.Refs, ref.URL)
		}
	}
	seenFixed := map[string]bool{}
	for _, aff := range raw.Affected {
		for _, rng := range aff.Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed != "" && !seenFixed[ev.Fixed] {
					seenFixed[ev.Fixed] = true
					adv.Fixed = append(adv.Fixed, ev.Fixed)
				}
			}
		}
	}
	return adv
}

func mapGitHubSeverity(s string) finding.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MODERATE", "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	}
	return finding.SeverityMedium
}

// Enrich attaches EPSS scores for advisories with CVE identifiers.
func (c *httpClient) Enrich(ctx context.Context, advs []*Advisory) {
	byCVE := map[string][]*Advisory{}
	var cves []string
	for _, a := range advs {
		for _, id := range append([]string{a.ID}, a.Aliases...) {
			u := strings.ToUpper(id)
			if !strings.HasPrefix(u, "CVE-") {
				continue
			}
			if _, ok := byCVE[u]; !ok {
				cves = append(cves, u)
			}
			byCVE[u] = append(byCVE[u], a)
		}
	}
	if len(cves) == 0 {
		return
	}
	for start := 0; start < len(cves); start += 100 {
		end := start + 100
		if end > len(cves) {
			end = len(cves)
		}
		var resp struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		u := epssAPI + "?cve=" + url.QueryEscape(strings.Join(cves[start:end], ","))
		if err := c.doJSON(ctx, http.MethodGet, u, nil, &resp); err != nil {
			continue
		}
		for _, d := range resp.Data {
			var score float64
			if _, err := fmt.Sscanf(d.EPSS, "%f", &score); err != nil {
				continue
			}
			for _, a := range byCVE[strings.ToUpper(d.CVE)] {
				if score > a.EPSS {
					a.EPSS = score
				}
			}
		}
	}
}

func (c *httpClient) isKEV(ctx context.Context, adv *Advisory) bool {
	set := c.kevSet(ctx)
	if len(set) == 0 {
		return false
	}
	for _, id := range append([]string{adv.ID}, adv.Aliases...) {
		if set[strings.ToUpper(id)] {
			return true
		}
	}
	return false
}

type kevCache struct {
	FetchedAt time.Time `json:"fetched_at"`
	CVEs      []string  `json:"cves"`
}

func (c *httpClient) kevSet(ctx context.Context) map[string]bool {
	c.mu.Lock()
	if c.kevLoaded {
		m := c.kev
		c.mu.Unlock()
		return m
	}
	c.mu.Unlock()

	set := map[string]bool{}
	path := filepath.Join(c.cacheDir, kevName)
	if data, err := os.ReadFile(path); err == nil {
		var cached kevCache
		if json.Unmarshal(data, &cached) == nil && time.Since(cached.FetchedAt) < cacheTTL {
			for _, cve := range cached.CVEs {
				set[strings.ToUpper(cve)] = true
			}
		}
	}
	if len(set) == 0 {
		var feed struct {
			Vulnerabilities []struct {
				CVEID string `json:"cveID"`
			} `json:"vulnerabilities"`
		}
		if err := c.doJSON(ctx, http.MethodGet, kevFeed, nil, &feed); err == nil {
			var cves []string
			for _, v := range feed.Vulnerabilities {
				if v.CVEID != "" {
					cves = append(cves, v.CVEID)
					set[strings.ToUpper(v.CVEID)] = true
				}
			}
			if len(cves) > 0 {
				if data, err := json.Marshal(kevCache{FetchedAt: time.Now(), CVEs: cves}); err == nil {
					_ = os.MkdirAll(c.cacheDir, 0o700)
					_ = os.WriteFile(path, data, 0o600)
				}
			}
		}
	}

	c.mu.Lock()
	c.kev = set
	c.kevLoaded = true
	c.mu.Unlock()
	return set
}

type cachedAdvisory struct {
	FetchedAt time.Time `json:"fetched_at"`
	Advisory  *Advisory `json:"advisory"`
}

func (c *httpClient) cachePath(id string) string {
	return filepath.Join(c.cacheDir, "vulns", sanitizeForID(id)+".json")
}

func (c *httpClient) loadCache(id string) (*Advisory, bool) {
	data, err := os.ReadFile(c.cachePath(id))
	if err != nil {
		return nil, false
	}
	var ca cachedAdvisory
	if json.Unmarshal(data, &ca) != nil || ca.Advisory == nil {
		return nil, false
	}
	return ca.Advisory, time.Since(ca.FetchedAt) < cacheTTL
}

func (c *httpClient) writeCache(id string, a *Advisory) {
	data, err := json.Marshal(cachedAdvisory{FetchedAt: time.Now(), Advisory: a})
	if err != nil {
		return
	}
	dir := filepath.Join(c.cacheDir, "vulns")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = os.WriteFile(c.cachePath(id), data, 0o600)
}

type httpStatusError struct {
	code int
	url  string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d", e.url, e.code)
}

func (c *httpClient) doJSON(ctx context.Context, method, rawURL string, body, out any) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		err := c.doJSONOnce(ctx, method, rawURL, body, out)
		if err == nil {
			return nil
		}
		lastErr = err
		var se *httpStatusError
		retryable := errors.As(err, &se) && (se.code == http.StatusTooManyRequests || se.code >= 500)
		if !retryable {
			return err
		}
		delay := time.Duration(250*(1<<attempt)+rand.IntN(250)) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return lastErr
}

func (c *httpClient) doJSONOnce(ctx context.Context, method, rawURL string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &httpStatusError{code: resp.StatusCode, url: rawURL}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxBodyLen)).Decode(out)
}
