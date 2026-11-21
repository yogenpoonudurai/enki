// Package aiendpoint detects exposed local AI inference services and unsafe
// exposure settings (public bind, missing auth, permissive CORS, Gradio
// tunnels, tokenless Jupyter).
package aiendpoint

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yogenpoonudurai/enki/internal/collector"
	"github.com/yogenpoonudurai/enki/internal/diagnostics"
	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/platform"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

const moduleName = "endpoint-exposure"

const userAgent = "enki/0.1 (AI configuration/exposure scanner)"

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }

func (m *Module) Description() string {
	return "Detects exposed AI inference endpoints (Ollama, LM Studio, ComfyUI, Jupyter, ...)"
}

type probe struct {
	Path   string
	Marker string // lowercase substring expected in a confirmed response body
}

type serviceDef struct {
	ID             string
	Name           string
	Ports          []int
	Probes         []probe
	RequireProcess bool // ambiguous port: only probe when the process also matches
}

var services = []serviceDef{
	{ID: "ollama", Name: "Ollama", Ports: []int{11434}, Probes: []probe{{"/api/tags", "models"}, {"/api/version", "version"}}},
	{ID: "lmstudio", Name: "LM Studio", Ports: []int{1234}, Probes: []probe{{"/v1/models", "\"data\""}}},
	{ID: "comfyui", Name: "ComfyUI", Ports: []int{8188}, Probes: []probe{{"/system_stats", "system"}}},
	{ID: "a1111", Name: "Stable Diffusion WebUI", Ports: []int{7860}, Probes: []probe{{"/sdapi/v1/options", "sd_model_checkpoint"}}},
	{ID: "vllm", Name: "vLLM", Ports: []int{8000}, Probes: []probe{{"/v1/models", "\"data\""}}, RequireProcess: true},
	{ID: "localai", Name: "LocalAI", Ports: []int{8080}, Probes: []probe{{"/readyz", ""}}, RequireProcess: true},
	{ID: "llamacpp", Name: "llama.cpp server", Ports: []int{8080}, Probes: []probe{{"/health", "status"}}, RequireProcess: true},
	{ID: "openwebui", Name: "Open WebUI", Ports: []int{3000, 8080}, Probes: []probe{{"/api/config", ""}}, RequireProcess: true},
	{ID: "kobold", Name: "KoboldCpp", Ports: []int{5001}, Probes: []probe{{"/api/v1/model", "result"}}},
	{ID: "jupyter", Name: "Jupyter", Ports: []int{8888}, Probes: []probe{{"/api/status", "kernels"}}},
}

var processHints = map[string][]string{
	"ollama":    {"ollama"},
	"lmstudio":  {"lm studio", "lmstudio"},
	"comfyui":   {"comfyui", "comfy"},
	"a1111":     {"stable-diffusion", "a1111"},
	"vllm":      {"vllm"},
	"localai":   {"local-ai", "localai"},
	"llamacpp":  {"llama-server", "llama.cpp"},
	"openwebui": {"open-webui", "openwebui"},
	"kobold":    {"kobold"},
	"jupyter":   {"jupyter"},
}

// Run probes AI-looking listeners and reports exposure findings.
func (m *Module) Run(sc *scanner.Context) ([]finding.Finding, []scanner.CoverageGap, error) {
	var targets []target
	seen := map[string]bool{}
	for _, l := range sc.Listeners {
		key := fmt.Sprintf("%s|%d", l.Addr, l.Port)
		if seen[key] {
			continue
		}
		def, processMatch := identify(l)
		if def == nil {
			continue
		}
		seen[key] = true
		targets = append(targets, target{listener: l, def: def, processMatch: processMatch})
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	results := make([]evalResult, len(targets))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = evaluate(sc, client, targets[i])
		}(i)
	}
	wg.Wait()

	var out []finding.Finding
	diag := diagnostics.Collect()
	for _, r := range results {
		out = append(out, findingsFor(sc, r, diag)...)
	}
	out = append(out, gradioShare(sc)...)
	finding.Sort(out)
	return out, nil, nil
}

type target struct {
	listener     collector.Listener
	def          *serviceDef
	processMatch bool
}

type evalResult struct {
	listener     collector.Listener
	def          *serviceDef
	processMatch bool
	probed       bool
	probePath    string
	status       int
	confirmed    bool
	authRequired bool
	corsReflect  bool
}

func identify(l collector.Listener) (*serviceDef, bool) {
	joined := strings.ToLower(l.Process + " " + strings.Join(l.Cmdline, " "))

	var byProc *serviceDef
	for i := range services {
		for _, hint := range processHints[services[i].ID] {
			if strings.Contains(joined, hint) {
				byProc = &services[i]
				break
			}
		}
		if byProc != nil {
			break
		}
	}
	if byProc != nil {
		return byProc, true
	}

	for i := range services {
		for _, p := range services[i].Ports {
			if p == l.Port && !services[i].RequireProcess {
				return &services[i], false
			}
		}
	}
	return nil, false
}

func probeTarget(l collector.Listener, sc *scanner.Context) (string, bool) {
	switch platform.ClassifyBindAddr(l.Addr) {
	case platform.ScopeLoopback, platform.ScopeAll:
		return "127.0.0.1", true
	case platform.ScopeLAN:
		if !sc.ProbeRemote {
			return "", false
		}
		ip := net.ParseIP(strings.Trim(l.Addr, "[]"))
		if ip == nil || !platform.IsPrivateOrLoopback(ip) {
			return "", false
		}
		return ip.String(), true
	}
	return "", false
}

func evaluate(sc *scanner.Context, client *http.Client, t target) evalResult {
	res := evalResult{listener: t.listener, def: t.def, processMatch: t.processMatch}
	host, ok := probeTarget(t.listener, sc)
	if !ok {
		return res
	}
	const origin = "https://enki-probe.invalid"
	for _, p := range t.def.Probes {
		status, body, acao, err := httpGet(sc.Ctx, client, host, t.listener.Port, p.Path, origin)
		if err != nil {
			continue
		}
		res.probed = true
		res.probePath = p.Path
		res.status = status
		res.authRequired = status == http.StatusUnauthorized || status == http.StatusForbidden
		res.confirmed = status == http.StatusOK && (p.Marker == "" || strings.Contains(strings.ToLower(body), p.Marker))
		res.corsReflect = status == http.StatusOK && originReflected(acao, origin)
		if res.confirmed || res.authRequired {
			return res
		}
	}
	return res
}

func httpGet(ctx context.Context, client *http.Client, host string, port int, path, origin string) (int, string, string, error) {
	url := "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Origin", origin)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, string(body), resp.Header.Get("Access-Control-Allow-Origin"), nil
}

func originReflected(acao, origin string) bool {
	acao = strings.TrimSpace(acao)
	return acao == "*" || strings.EqualFold(acao, origin)
}

func findingsFor(sc *scanner.Context, r evalResult, diag diagnostics.Report) []finding.Finding {
	addr := net.JoinHostPort(r.listener.Addr, strconv.Itoa(r.listener.Port))
	loc := finding.Location{Addr: addr}
	scope := platform.ClassifyBindAddr(r.listener.Addr)
	exposed := scope != platform.ScopeLoopback

	var out []finding.Finding

	if exposed {
		sev := finding.SeverityInfo
		conf := finding.ConfidenceLow
		switch {
		case r.confirmed:
			sev, conf = finding.SeverityCritical, finding.ConfidenceHigh
		case r.processMatch && r.status == http.StatusOK && !r.authRequired:
			sev, conf = finding.SeverityHigh, finding.ConfidenceMedium
		case r.processMatch && !r.probed:
			sev, conf = finding.SeverityHigh, finding.ConfidenceLow
		case !r.probed && !r.def.RequireProcess:
			// Distinctive AI port bound to a non-loopback address but the
			// service could not be probed (e.g. bound to a specific LAN IP).
			sev, conf = finding.SeverityHigh, finding.ConfidenceLow
		}
		if sev != finding.SeverityInfo {
			f := finding.New("AEP-001", moduleName,
				fmt.Sprintf("%s exposed on %s:%d", r.def.Name, r.listener.Addr, r.listener.Port),
				"An AI inference service is reachable from the network. Unauthenticated model endpoints allow model theft, prompt abuse, and compute hijacking.",
				sev, conf, loc)
			f.Evidence = evidenceFor(r)
			f.Remediation = firewallRemediation(diag, r.def.Name, r.listener.Port)
			f.References = []string{"https://genai.owasp.org/"}
			f.Tags = []string{"ai-service", "network-exposure"}
			out = append(out, f)
		}
	}

	if scope == platform.ScopeLoopback && r.confirmed && r.corsReflect {
		f := finding.New("AEP-002", moduleName,
			fmt.Sprintf("%s allows cross-origin requests", r.def.Name),
			"A loopback AI service answers requests from arbitrary web origins. A malicious page could use DNS rebinding or local requests to read prompts, models, or invoke inference.",
			finding.SeverityMedium, finding.ConfidenceMedium, loc)
		f.Evidence = fmt.Sprintf("GET %s with a hostile Origin header reflected in Access-Control-Allow-Origin", r.probePath)
		f.Remediation = &finding.Remediation{
			Class:    finding.ActionModerate,
			Summary:  fmt.Sprintf("Restrict allowed origins for %s", r.def.Name),
			Guidance: "Configure the service or its reverse proxy to allow only trusted origins, or keep the service bound to loopback with origin checks.",
		}
		f.Tags = []string{"ai-service", "cors"}
		out = append(out, f)
	}

	if r.confirmed && r.def.ID == "jupyter" && !r.authRequired {
		f := finding.New("AEP-004", moduleName,
			"Jupyter API reachable without a token",
			"A Jupyter server answered an API request without authentication. Jupyter permits arbitrary code execution, so this is a direct host compromise path.",
			finding.SeverityHigh, finding.ConfidenceHigh, loc)
		f.Evidence = fmt.Sprintf("GET %s → %d without credentials", r.probePath, r.status)
		f.Remediation = &finding.Remediation{
			Class:    finding.ActionRisky,
			Summary:  "Enable Jupyter token authentication or bind to 127.0.0.1",
			Guidance: "Set a token/password in the Jupyter config and restrict the bind address to loopback.",
		}
		f.Tags = []string{"ai-service", "rce"}
		out = append(out, f)
	}

	return out
}

func evidenceFor(r evalResult) string {
	parts := []string{fmt.Sprintf("service: %s", r.def.Name)}
	if r.probed {
		auth := "no auth"
		if r.authRequired {
			auth = "auth required"
		}
		parts = append(parts, fmt.Sprintf("probe: GET %s → %d (%s)", r.probePath, r.status, auth))
	} else {
		parts = append(parts, "probe: unavailable (bound to a specific address)")
	}
	if r.listener.Process != "" {
		parts = append(parts, "process: "+r.listener.Process)
	}
	if r.corsReflect {
		parts = append(parts, "CORS: reflects arbitrary origins")
	}
	return strings.Join(parts, " · ")
}

// firewallRemediation selects a firewall command that actually exists on this
// machine and states the privilege requirement.
func firewallRemediation(diag diagnostics.Report, service string, port int) *finding.Remediation {
	cmd, tool := firewallCommand(diag, port)
	summary := fmt.Sprintf("Bind %s to 127.0.0.1 or block inbound TCP/%d", service, port)
	guidance := "Rebinding the service to loopback is preferred. Firewall changes affect every service using this port."
	if tool != "" {
		summary = fmt.Sprintf("Bind %s to 127.0.0.1 or block inbound TCP/%d with %s", service, port, tool)
	}
	if cmd == "" {
		guidance = "No supported firewall CLI detected; rebind " + service + " to 127.0.0.1 instead. " + guidance
	}
	if !diag.Elevated {
		guidance += " This host is not running elevated: apply system changes with sudo/administrator."
	}
	if diag.ServiceManager != "" && diag.ServiceManager != "unknown" {
		guidance += " Restart the service after changing its bind address (via " + diag.ServiceManager + ")."
	}
	return &finding.Remediation{
		Class:    finding.ActionRisky,
		Summary:  summary,
		Command:  cmd,
		Guidance: guidance,
	}
}

func firewallCommand(diag diagnostics.Report, port int) (string, string) {
	has := func(name string) bool {
		for _, f := range diag.Firewalls {
			if f == name {
				return true
			}
		}
		return false
	}
	switch {
	case has("ufw"):
		return fmt.Sprintf("sudo ufw deny %d/tcp", port), "ufw"
	case has("nft"):
		return fmt.Sprintf("sudo nft add rule inet filter input tcp dport %d drop", port), "nft"
	case has("firewall-cmd"):
		return fmt.Sprintf("sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 destination-port port=\"%d\" protocol=tcp drop' && sudo firewall-cmd --reload", port), "firewalld"
	case has("iptables"):
		return fmt.Sprintf("sudo iptables -I INPUT -p tcp --dport %d -j DROP", port), "iptables"
	case has("pfctl"):
		return fmt.Sprintf("sudo pfctl -a enki -f - <<< 'block in proto tcp from any to any port %d'", port), "pfctl"
	case has("netsh"):
		return fmt.Sprintf(`netsh advfirewall firewall add rule name="enki-block-tcp-%d" dir=in action=block protocol=TCP localport=%d`, port, port), "netsh"
	}
	return "", ""
}

func gradioShare(sc *scanner.Context) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, l := range sc.Listeners {
		loc := finding.Location{Addr: net.JoinHostPort(l.Addr, strconv.Itoa(l.Port))}
		key := "AEP-003|" + loc.Addr
		if seen[key] {
			continue
		}

		joined := strings.ToLower(strings.Join(l.Cmdline, " "))
		shareFlag := false
		for _, arg := range l.Cmdline {
			if arg == "--share" || strings.HasPrefix(arg, "--share=") {
				shareFlag = true
				break
			}
		}
		// Gradio's global --share flag only matters for Python-based apps;
		// unrelated tools use flags like --shared-files.
		looksGradio := strings.Contains(joined, "python") || strings.Contains(joined, "gradio") ||
			strings.Contains(joined, "webui") || strings.Contains(joined, ".py")
		shareEnv := false
		for _, kv := range collector.ProcEnv(l.PID) {
			u := strings.ToUpper(kv)
			if strings.HasPrefix(u, "GRADIO_SHARE=1") || strings.HasPrefix(u, "GRADIO_SHARE=TRUE") {
				shareEnv = true
				break
			}
		}
		if !shareEnv && !(shareFlag && looksGradio) {
			continue
		}
		seen[key] = true

		conf := finding.ConfidenceMedium
		if shareEnv || strings.Contains(joined, "gradio") || strings.Contains(joined, "webui") {
			conf = finding.ConfidenceHigh
		}
		f := finding.New("AEP-003", moduleName,
			"Gradio app shared through a public tunnel",
			"Gradio share mode publishes the app through a public relay tunnel, bypassing network controls. Anyone with the URL can reach the model UI.",
			finding.SeverityHigh, conf, loc)
		if shareFlag {
			f.Evidence = "process command line contains --share"
		} else {
			f.Evidence = "GRADIO_SHARE is enabled for the process"
		}
		f.Remediation = &finding.Remediation{
			Class:    finding.ActionModerate,
			Summary:  "Disable Gradio share mode",
			Guidance: "Remove --share / GRADIO_SHARE and expose the app through an authenticated gateway instead.",
		}
		f.Tags = []string{"ai-service", "tunnel"}
		out = append(out, f)
	}
	return out
}
