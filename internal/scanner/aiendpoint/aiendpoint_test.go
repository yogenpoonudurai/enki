package aiendpoint

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yogenpoonudurai/enki/internal/collector"
	"github.com/yogenpoonudurai/enki/internal/diagnostics"
	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

func testDiag() diagnostics.Report {
	return diagnostics.Report{OS: "linux", Arch: "amd64", Firewalls: []string{"ufw"}, Elevated: false}
}

func testContext(t *testing.T) *scanner.Context {
	t.Helper()
	return &scanner.Context{
		Ctx:     context.Background(),
		Now:     time.Now(),
		OS:      "linux",
		HomeDir: t.TempDir(),
	}
}

func testClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func serverPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestIdentify(t *testing.T) {
	def, processMatch := identify(collector.Listener{Addr: "127.0.0.1", Port: 11434})
	if def == nil || def.ID != "ollama" || processMatch {
		t.Fatalf("port identify = %+v, %v", def, processMatch)
	}

	def, processMatch = identify(collector.Listener{
		Addr: "127.0.0.1", Port: 9999, Process: "ollama",
		Cmdline: []string{"ollama", "serve"},
	})
	if def == nil || def.ID != "ollama" || !processMatch {
		t.Fatalf("process identify = %+v, %v", def, processMatch)
	}

	// Ambiguous port without a matching process must not be classified.
	if def, _ := identify(collector.Listener{Addr: "127.0.0.1", Port: 8080, Process: "nginx"}); def != nil {
		t.Fatalf("nginx on 8080 misidentified as %s", def.ID)
	}
}

func TestExposedOllamaIsCritical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = io.WriteString(w, `{"models":[{"name":"llama3.1:8b"}]}`)
	}))
	defer srv.Close()

	sc := testContext(t)
	def := &services[0]
	res := evaluate(sc, testClient(), target{
		listener: collector.Listener{Addr: "0.0.0.0", Port: serverPort(t, srv)},
		def:      def,
	})
	if !res.probed || !res.confirmed || res.authRequired {
		t.Fatalf("unexpected probe result: %+v", res)
	}
	if !res.corsReflect {
		t.Fatal("expected CORS reflection to be detected")
	}

	fs := findingsFor(sc, res, testDiag())
	if len(fs) != 1 || fs[0].RuleID != "AEP-001" {
		t.Fatalf("findings = %+v", fs)
	}
	if fs[0].Severity != finding.SeverityCritical || fs[0].Confidence != finding.ConfidenceHigh {
		t.Fatalf("severity/confidence = %s/%s", fs[0].Severity, fs[0].Confidence)
	}
	if fs[0].Remediation == nil || fs[0].Remediation.Command == "" {
		t.Fatal("expected firewall command in remediation")
	}
}

func TestLoopbackCORSRaisesAEP002(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://enki-probe.invalid")
		_, _ = io.WriteString(w, `{"models":[]}`)
	}))
	defer srv.Close()

	sc := testContext(t)
	res := evaluate(sc, testClient(), target{
		listener: collector.Listener{Addr: "127.0.0.1", Port: serverPort(t, srv)},
		def:      &services[0],
	})
	fs := findingsFor(sc, res, testDiag())
	found := false
	for _, f := range fs {
		if f.RuleID == "AEP-002" {
			found = true
		}
		if f.RuleID == "AEP-001" {
			t.Fatal("loopback listener must not be reported as network-exposed")
		}
	}
	if !found {
		t.Fatalf("expected AEP-002, got %+v", fs)
	}
}

func TestJupyterWithoutToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/status" {
			_, _ = io.WriteString(w, `{"kernels":[],"connections":0}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	var jupyter *serviceDef
	for i := range services {
		if services[i].ID == "jupyter" {
			jupyter = &services[i]
		}
	}
	sc := testContext(t)
	res := evaluate(sc, testClient(), target{
		listener: collector.Listener{Addr: "127.0.0.1", Port: serverPort(t, srv)},
		def:      jupyter,
	})
	fs := findingsFor(sc, res, testDiag())
	found := false
	for _, f := range fs {
		if f.RuleID == "AEP-004" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected AEP-004, got %+v", fs)
	}
}

func TestAuthRequiredIsNotExposure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	sc := testContext(t)
	res := evaluate(sc, testClient(), target{
		listener: collector.Listener{Addr: "0.0.0.0", Port: serverPort(t, srv)},
		def:      &services[0],
	})
	if !res.authRequired {
		t.Fatalf("expected auth-required probe, got %+v", res)
	}
	if fs := findingsFor(sc, res, testDiag()); len(fs) != 0 {
		t.Fatalf("authenticated service reported as exposed: %+v", fs)
	}
}

func TestGradioShareDetection(t *testing.T) {
	sc := testContext(t)
	sc.Listeners = []collector.Listener{{
		Addr: "127.0.0.1", Port: 7861,
		Cmdline: []string{"python", "app.py", "--share"},
	}}
	fs := gradioShare(sc)
	if len(fs) != 1 || fs[0].RuleID != "AEP-003" {
		t.Fatalf("gradio findings = %+v", fs)
	}
}

func TestGradioShareIgnoresUnrelatedShareFlags(t *testing.T) {
	sc := testContext(t)
	sc.Listeners = []collector.Listener{{
		Addr: "127.0.0.1", Port: 8080,
		Process: "brave",
		Cmdline: []string{"brave", "--type=utility", "--shared-files", "--share-thing"},
	}}
	if fs := gradioShare(sc); len(fs) != 0 {
		t.Fatalf("unrelated --share* flags flagged: %+v", fs)
	}
}

func TestOriginReflected(t *testing.T) {
	if !originReflected("*", "https://x") {
		t.Fatal("wildcard should reflect")
	}
	if !originReflected("https://x", "https://x") {
		t.Fatal("exact origin should reflect")
	}
	if originReflected("https://y", "https://x") {
		t.Fatal("different origin should not reflect")
	}
}

func TestFirewallCommandUsesAvailableTools(t *testing.T) {
	nft := diagnostics.Report{OS: "linux", Firewalls: []string{"nft"}, Elevated: true}
	cmd, tool := firewallCommand(nft, 11434)
	if tool != "nft" || !strings.Contains(cmd, "nft add rule") {
		t.Fatalf("nft resolution: %q / %q", tool, cmd)
	}

	none := diagnostics.Report{OS: "linux", Elevated: false}
	if cmd, tool := firewallCommand(none, 11434); cmd != "" || tool != "" {
		t.Fatalf("expected no command, got %q / %q", cmd, tool)
	}
	rm := firewallRemediation(none, "Ollama", 11434)
	if !strings.Contains(rm.Guidance, "No supported firewall CLI") ||
		!strings.Contains(rm.Guidance, "not running elevated") {
		t.Fatalf("guidance = %q", rm.Guidance)
	}

	mac := diagnostics.Report{OS: "darwin", Firewalls: []string{"pfctl"}, Elevated: true}
	if cmd, tool := firewallCommand(mac, 11434); tool != "pfctl" || !strings.Contains(cmd, "pfctl") {
		t.Fatalf("darwin resolution: %q / %q", tool, cmd)
	}
}
