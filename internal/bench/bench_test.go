package bench

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yogenpoonudurai/enki/internal/collector"
	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/rules"
	"github.com/yogenpoonudurai/enki/internal/scanner"
	"github.com/yogenpoonudurai/enki/internal/scanner/agentcfg"
	"github.com/yogenpoonudurai/enki/internal/scanner/aiendpoint"
	"github.com/yogenpoonudurai/enki/internal/scanner/mcp"
	"github.com/yogenpoonudurai/enki/internal/scanner/model"
	"github.com/yogenpoonudurai/enki/internal/scanner/sbom"
	"github.com/yogenpoonudurai/enki/internal/scanner/secrets"
)

var (
	update  = flag.Bool("update", false, "rewrite the baseline and generated benchmark docs")
	liveOSV = flag.Bool("live-osv", false, "use live OSV advisory data for SBOM cases")
)

type fileSpec struct {
	Content string `json:"content"`
	Mode    string `json:"mode,omitempty"`
}

type listenerSpec struct {
	Addr    string   `json:"addr"`
	Port    int      `json:"port,omitempty"`
	Server  string   `json:"server,omitempty"` // ollama|ollama401|jupyter|jupyter401|generic|none
	CORS    string   `json:"cors,omitempty"`   // "", "*", "reflect", or a fixed origin
	Process string   `json:"process,omitempty"`
	Cmdline []string `json:"cmdline,omitempty"`
}

type sourceSpec struct {
	Repo         string `json:"repo,omitempty"`
	Commit       string `json:"commit,omitempty"`
	Path         string `json:"path,omitempty"`
	URL          string `json:"url,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	SHA256Prefix string `json:"sha256_prefix,omitempty"`
	WorkPath     string `json:"work_path"`
	Mode         string `json:"mode,omitempty"`
	LocalPath    string `json:"local_path,omitempty"`
	Notes        string `json:"notes,omitempty"`
}

type labelSpec struct {
	RuleID   string `json:"rule_id"`
	Count    int    `json:"count,omitempty"`
	Presence bool   `json:"presence,omitempty"`
}

type benchCase struct {
	Name      string              `json:"name"`
	Category  string              `json:"category,omitempty"`
	Module    string              `json:"module"`
	Rule      string              `json:"rule"`
	Type      string              `json:"type"` // positive|negative|adversarial
	Files     map[string]fileSpec `json:"files,omitempty"`
	HomeFiles map[string]fileSpec `json:"home_files,omitempty"`
	Listeners []listenerSpec      `json:"listeners,omitempty"`
	Source    *sourceSpec         `json:"source,omitempty"`
	Labels    []labelSpec         `json:"labels,omitempty"`
	Evaluate  []string            `json:"evaluate,omitempty"`
	Notes     string              `json:"notes,omitempty"`
	Expect    []string            `json:"expect,omitempty"`
	Forbid    []string            `json:"forbid,omitempty"`
}

type manifest struct {
	Cases []benchCase `json:"cases"`
}

type ruleCounts struct {
	Positive    int `json:"positive"`
	Negative    int `json:"negative"`
	Adversarial int `json:"adversarial"`
}

type baseline struct {
	Rules map[string]ruleCounts `json:"rules"`
}

func TestDetectionBenchmark(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Cases) == 0 {
		t.Fatal("no benchmark cases")
	}

	stats := map[string]*ruleCounts{}
	for _, r := range rules.Catalog {
		stats[r.ID] = &ruleCounts{}
	}

	var failures []string
	for _, c := range m.Cases {
		if c.Name == "" || c.Module == "" || c.Rule == "" {
			failures = append(failures, "case with empty name/module/rule")
			continue
		}
		if stats[c.Rule] == nil {
			failures = append(failures, fmt.Sprintf("%s: unknown rule %s", c.Name, c.Rule))
			continue
		}
		switch c.Type {
		case "positive":
			stats[c.Rule].Positive++
		case "negative":
			stats[c.Rule].Negative++
		case "adversarial":
			stats[c.Rule].Adversarial++
		default:
			failures = append(failures, fmt.Sprintf("%s: invalid type %q", c.Name, c.Type))
			continue
		}

		got, err := runCase(t, c)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", c.Name, err))
			continue
		}
		for _, want := range c.Expect {
			if got[want] == 0 {
				failures = append(failures, fmt.Sprintf("%s: expected %s", c.Name, want))
			}
		}
		forbid := map[string]bool{}
		for _, id := range c.Forbid {
			forbid[id] = true
		}
		if c.Type != "positive" {
			forbid[c.Rule] = true
		}
		for id := range forbid {
			if got[id] > 0 {
				failures = append(failures, fmt.Sprintf("%s: unexpected %s", c.Name, id))
			}
		}
	}

	for _, r := range rules.Catalog {
		s := stats[r.ID]
		if s.Positive < 1 || s.Negative < 2 || s.Adversarial < 1 {
			failures = append(failures, fmt.Sprintf("%s: fixtures positive=%d negative=%d adversarial=%d (need >=1/2/1)",
				r.ID, s.Positive, s.Negative, s.Adversarial))
		}
	}

	got := baseline{Rules: map[string]ruleCounts{}}
	for id, s := range stats {
		got.Rules[id] = *s
	}

	if len(failures) > 0 {
		for _, f := range failures {
			t.Errorf("%s", f)
		}
		t.Fatalf("%d benchmark failure(s)", len(failures))
	}

	baselinePath := filepath.Join("testdata", "baseline.json")
	docPath := filepath.Join("..", "..", "docs", "detection-benchmark.md")
	if *update {
		writeJSON(t, baselinePath, got)
		writeDocs(t, docPath, m, got)
		t.Logf("updated %s and %s", baselinePath, docPath)
		return
	}

	raw, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("read baseline: %v (run make bench-update)", err)
	}
	var want baseline
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("parse baseline: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("benchmark baseline drift; run make bench-update\n got: %+v\nwant: %+v", got, want)
	}
}

func runCase(t *testing.T, c benchCase) (map[string]int, error) {
	t.Helper()
	work := t.TempDir()
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if c.Source != nil {
		if err := writeSource(t, work, c.Source); err != nil {
			return nil, err
		}
	}
	if err := writeFiles(work, c.Files); err != nil {
		return nil, err
	}
	if err := writeFiles(home, c.HomeFiles); err != nil {
		return nil, err
	}

	sc := &scanner.Context{
		Ctx:        context.Background(),
		Now:        time.Now(),
		HomeDir:    home,
		WorkingDir: work,
		Scope:      scanner.ScopeFull,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
	}
	sc.Configs, _ = collector.DiscoverConfigs(home, work, true, true)

	var fs []finding.Finding
	var err error
	switch c.Module {
	case "endpoint-exposure":
		sc.Listeners = startListeners(t, c.Listeners)
		fs, _, err = aiendpoint.New().Run(sc)
	case "mcp":
		fs, _, err = mcp.New().Run(sc)
	case "agent-permissions":
		fs, _, err = agentcfg.New().Run(sc)
	case "secrets":
		fs, _, err = secrets.New().Run(sc)
	case "model-artifacts":
		fs, _, err = model.New().Run(sc)
	case "sbom":
		opts := sbom.Options{Deps: "all", Roots: []string{work}, Depth: 3, IncludeDev: true, OSPackages: false}
		var client sbom.Client = fakeOSV{}
		if *liveOSV {
			client = sbom.NewClient()
		}
		fs, _, err = sbom.NewWithClient(opts, client).Run(sc)
	default:
		return nil, fmt.Errorf("unknown module %q", c.Module)
	}
	if err != nil {
		return nil, err
	}

	got := map[string]int{}
	for _, f := range fs {
		got[f.RuleID]++
	}
	return got, nil
}

func writeFiles(root string, files map[string]fileSpec) error {
	for name, spec := range files {
		if err := writeOneFile(root, name, []byte(spec.Content), spec.Mode); err != nil {
			return err
		}
	}
	return nil
}

func writeSource(t *testing.T, root string, src *sourceSpec) error {
	t.Helper()
	var data []byte
	var err error
	if src.LocalPath != "" {
		local := filepath.Clean(filepath.FromSlash(src.LocalPath))
		if filepath.IsAbs(local) || strings.HasPrefix(local, ".."+string(os.PathSeparator)) || local == ".." {
			return fmt.Errorf("unsafe local source path %q", src.LocalPath)
		}
		data, err = os.ReadFile(filepath.Join("testdata", "realworld", local))
	} else {
		data, err = fetchSource(src)
	}
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if src.SHA256 != "" {
		got := hex.EncodeToString(sum[:])
		if got != src.SHA256 {
			return fmt.Errorf("source hash mismatch for %s: got %s, want %s", src.URL, got, src.SHA256)
		}
	}
	if src.SHA256Prefix != "" {
		got := hex.EncodeToString(sum[:])
		if !strings.HasPrefix(got, strings.ToLower(src.SHA256Prefix)) {
			return fmt.Errorf("source hash prefix mismatch for %s: got %s, want prefix %s", src.URL, got, src.SHA256Prefix)
		}
	}
	return writeOneFile(root, src.WorkPath, data, src.Mode)
}

func fetchSource(src *sourceSpec) ([]byte, error) {
	srcURL := src.URL
	if srcURL == "" {
		commit := strings.ReplaceAll(src.Commit, "-", "")
		srcURL = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", src.Repo, commit, src.Path)
	}
	parsed, err := url.Parse(srcURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" || parsed.Hostname() != "raw.githubusercontent.com" {
		return nil, fmt.Errorf("refusing source URL %q: only https://raw.githubusercontent.com is allowed", srcURL)
	}
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	cacheDir = filepath.Join(cacheDir, "enki", "bench-realworld")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, err
	}
	name := sha256.Sum256([]byte(srcURL))
	cachePath := filepath.Join(cacheDir, hex.EncodeToString(name[:])+".src")
	if data, err := os.ReadFile(cachePath); err == nil {
		return data, nil
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, srcURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "enki-bench/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", srcURL, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cachePath, data, 0o600); err != nil {
		return nil, err
	}
	return data, nil
}

func writeOneFile(root, name string, data []byte, modeText string) error {
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || filepath.IsAbs(clean) {
		return fmt.Errorf("unsafe fixture path %q", name)
	}
	path := filepath.Join(root, clean)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if modeText != "" {
		parsed, err := strconv.ParseUint(modeText, 8, 32)
		if err != nil {
			return fmt.Errorf("mode %q: %w", modeText, err)
		}
		mode = os.FileMode(parsed)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func startListeners(t *testing.T, specs []listenerSpec) []collector.Listener {
	t.Helper()
	var out []collector.Listener
	for _, spec := range specs {
		port := spec.Port
		if spec.Server != "" && spec.Server != "none" {
			srv := httptest.NewServer(handler(spec.Server, spec.CORS))
			t.Cleanup(srv.Close)
			u, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			port, _ = strconv.Atoi(u.Port())
		}
		if port == 0 {
			port = 7860
		}
		out = append(out, collector.Listener{
			Proto: "tcp", Addr: spec.Addr, Port: port,
			Process: spec.Process, Cmdline: spec.Cmdline,
		})
	}
	return out
}

func handler(kind, cors string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cors != "" {
			if cors == "reflect" {
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			} else {
				w.Header().Set("Access-Control-Allow-Origin", cors)
			}
		}
		switch kind {
		case "ollama":
			if r.URL.Path != "/api/tags" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = io.WriteString(w, `{"models":[{"name":"llama3.1:8b"}]}`)
		case "ollama401":
			w.WriteHeader(http.StatusUnauthorized)
		case "jupyter":
			if r.URL.Path != "/api/status" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = io.WriteString(w, `{"kernels":[]}`)
		case "jupyter401":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	})
}

type fakeOSV struct{}

func (fakeOSV) QueryBatch(_ context.Context, qs []sbom.Query) ([][]string, error) {
	out := make([][]string, len(qs))
	for i, q := range qs {
		if q.Name == "lodash" && q.Version == "4.17.20" {
			out[i] = []string{"GHSA-bench-0001"}
		}
	}
	return out, nil
}

func (fakeOSV) Advisory(_ context.Context, id string) (*sbom.Advisory, error) {
	if id != "GHSA-bench-0001" {
		return nil, fmt.Errorf("unknown advisory %s", id)
	}
	return &sbom.Advisory{
		ID: "GHSA-bench-0001", Summary: "Prototype pollution", Severity: finding.SeverityHigh,
		Fixed: []string{"4.17.21"}, Refs: []string{"https://example.invalid/GHSA-bench-0001"},
	}, nil
}

func (fakeOSV) Enrich(context.Context, []*sbom.Advisory) {}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeDocs(t *testing.T, path string, m manifest, b baseline) {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("# Detection benchmark\n\n")
	sb.WriteString("Generated from `internal/bench/testdata/cases.json`. Do not edit by hand; run `make bench-update`.\n\n")
	sb.WriteString(fmt.Sprintf("%d offline fixtures across %d rules. Positive fixtures must produce the rule under test; negative and adversarial fixtures must not produce that rule (or any explicitly forbidden rule).\n\n", len(m.Cases), len(rules.Catalog)))
	sb.WriteString("| Rule | Module | Positive | Negative | Adversarial |\n|---|---|---:|---:|---:|\n")
	moduleByRule := map[string]string{}
	for _, r := range rules.Catalog {
		moduleByRule[r.ID] = r.Module
	}
	ids := make([]string, 0, len(b.Rules))
	for id := range b.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c := b.Rules[id]
		sb.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %d |\n", id, moduleByRule[id], c.Positive, c.Negative, c.Adversarial))
	}
	sb.WriteString("\n## Scope\n\n")
	sb.WriteString("The corpus covers deterministic detectors offline. Network listeners are simulated with loopback HTTP servers; OSV is replaced with a deterministic fake client. It does not measure real-world prevalence, only rule behavior on known fixtures.\n")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
