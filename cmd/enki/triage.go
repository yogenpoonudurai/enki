package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/yogenpoonudurai/enki/internal/ai"
	"github.com/yogenpoonudurai/enki/internal/hosted"
	"github.com/yogenpoonudurai/enki/internal/platform"
	"github.com/yogenpoonudurai/enki/internal/remediate"
	"github.com/yogenpoonudurai/enki/internal/report"
)

type triageOptions struct {
	provider    string
	model       string
	baseURL     string
	key         string
	limit       int
	format      string
	apply       bool
	only        string
	yes         bool
	showPayload bool
	hosted      bool
	hostedURL   string
	consent     bool
}

func newTriageCmd() *cobra.Command {
	o := &triageOptions{limit: 40}
	cmd := &cobra.Command{
		Use:   "triage <report.json|->",
		Short: "Rank and explain findings with a constrained AI triage pass",
		Long: "Sends a redacted findings payload to the configured model provider and\n" +
			"returns a validated ranking. Configure with DEEPSEEK_API_KEY or\n" +
			"ENKI_AI_PROVIDER/ENKI_AI_BASE_URL (any OpenAI-compatible endpoint).\n" +
			"With --hosted, the payload is sent to the paid hosted service instead;\n" +
			"set ENKI_CLOUD_URL and ENKI_CLOUD_TOKEN and confirm with --consent.\n" +
			"The model may only rank and explain; it never executes actions. With\n" +
			"--apply, enki applies its own deterministic remediation for actions the\n" +
			"model selected and enki verified, after confirmation.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTriage(cmd, args[0], o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.provider, "provider", "", "provider name (deepseek, openai, ollama)")
	f.StringVar(&o.model, "model", "", "model name (default from provider)")
	f.StringVar(&o.baseURL, "base-url", "", "OpenAI-compatible base URL")
	f.StringVar(&o.key, "key", "", "API key (prefer env: ENKI_AI_KEY or DEEPSEEK_API_KEY)")
	f.IntVar(&o.limit, "limit", 40, "maximum findings sent to the model")
	f.StringVar(&o.format, "format", "auto", "output format: auto (text on a terminal, JSON otherwise), text, or json")
	f.BoolVar(&o.apply, "apply", false, "apply verified enki fixes after triage")
	f.StringVar(&o.only, "only", "", "apply only these verified rules, comma-separated (for example SEC-001,MCP-006)")
	f.BoolVar(&o.yes, "yes", false, "apply all verified fixes without prompting (requires --apply)")
	f.BoolVar(&o.showPayload, "show-payload", false, "include the redacted payload in the output")
	f.BoolVar(&o.hosted, "hosted", false, "use the paid hosted triage service (requires --consent)")
	f.StringVar(&o.hostedURL, "hosted-url", "", "hosted service base URL (default: ENKI_CLOUD_URL)")
	f.BoolVar(&o.consent, "consent", false, "confirm a redacted findings payload may be sent to the hosted service")
	return cmd
}

func runTriage(cmd *cobra.Command, path string, o *triageOptions) error {
	if o.yes && !o.apply {
		return fmt.Errorf("--yes requires --apply")
	}
	if o.only != "" && !o.apply {
		return fmt.Errorf("--only requires --apply")
	}
	if o.hosted {
		if o.provider != "" || o.baseURL != "" || o.model != "" {
			return fmt.Errorf("--provider, --base-url, and --model apply to BYOK mode; with --hosted use --key for provider passthrough")
		}
		if !o.consent {
			return fmt.Errorf("--hosted requires --consent: confirm that a redacted findings payload may be sent to the hosted service")
		}
	} else if o.consent {
		return fmt.Errorf("--consent is only used with --hosted")
	}
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(cmd.InOrStdin())
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return err
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return fmt.Errorf("invalid enki JSON report: %w", err)
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
	defer cancel()

	var result *ai.TriageResult
	var payload *ai.Payload
	if o.hosted {
		payload = ai.BuildPayload(&rep, o.limit)
		cfg := hosted.ConfigFromEnv()
		if o.hostedURL != "" {
			cfg.BaseURL = o.hostedURL
		}
		client, err := hosted.New(cfg)
		if err != nil {
			return fmt.Errorf("%w\nhint: set ENKI_CLOUD_URL and ENKI_CLOUD_TOKEN (see docs/premium.md)", err)
		}
		var usage hosted.Usage
		var cached bool
		result, usage, cached, err = client.Triage(ctx, payload, o.consent, o.key)
		if err != nil {
			return err
		}
		if cached {
			fmt.Fprintln(cmd.ErrOrStderr(), "hosted: cached result")
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "hosted: plan %s · %s\n", usage.Plan, remainingLabel(usage))
	} else {
		cfg := ai.DefaultConfig()
		if o.provider != "" {
			cfg.Provider = o.provider
		}
		if o.model != "" {
			cfg.Model = o.model
		}
		if o.baseURL != "" {
			cfg.BaseURL = o.baseURL
		}
		if o.key != "" {
			cfg.APIKey = o.key
		}
		provider, err := ai.NewProvider(cfg)
		if err != nil {
			return fmt.Errorf("%w\nhint: export DEEPSEEK_API_KEY, or ENKI_AI_BASE_URL/ENKI_AI_KEY for a self-hosted endpoint", err)
		}
		result, payload, err = ai.Triage(ctx, provider, cfg.Model, &rep, o.limit)
		if err != nil {
			return err
		}
	}

	switch o.format {
	case "auto", "text", "json":
	default:
		return fmt.Errorf("invalid --format %q: use auto, text, or json", o.format)
	}
	text := !o.showPayload && (o.format == "text" || (o.format == "auto" && isTerminal(cmd.OutOrStdout())))
	var plan []remediate.Action
	if o.apply {
		plan = verifiedRemediations(result, &rep)
		if o.only != "" {
			plan = filterActions(plan, o.only)
			if len(plan) == 0 {
				return fmt.Errorf("apply: no verified fixes matched --only %q", o.only)
			}
		}
	}
	if text {
		ai.WriteHuman(cmd.OutOrStdout(), result, &rep)
		if o.apply {
			if _, err := applyVerified(cmd.OutOrStdout(), cmd.ErrOrStderr(), cmd.InOrStdin(), plan, o.yes || o.only != ""); err != nil {
				return err
			}
		}
		return nil
	}

	out := struct {
		Result       *ai.TriageResult   `json:"result"`
		FindingsSent int                `json:"findings_sent"`
		Omitted      int                `json:"omitted,omitempty"`
		Applied      []remediate.Result `json:"applied,omitempty"`
		Payload      *ai.Payload        `json:"payload,omitempty"`
	}{
		Result:       result,
		FindingsSent: len(payload.Findings),
		Omitted:      payload.Omitted,
	}
	if o.apply {
		applied, err := applyVerified(io.Discard, cmd.ErrOrStderr(), cmd.InOrStdin(), plan, o.yes || o.only != "")
		if err != nil {
			return err
		}
		out.Applied = applied
	}
	if o.showPayload {
		out.Payload = payload
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	if o.hosted {
		fmt.Fprintf(cmd.ErrOrStderr(), "triage: %d findings sent\n", result.FindingsSent)
	} else if result.Cost.Metered {
		fmt.Fprintf(cmd.ErrOrStderr(), "triage: %d findings sent · ~$%.4f (%d in / %d out, %s)\n",
			result.FindingsSent, result.Cost.USD, result.Cost.InputTokens, result.Cost.OutputTokens, result.Cost.Model)
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "triage: %d findings sent · %s (unmetered/self-hosted, %d in / %d out)\n",
			result.FindingsSent, result.Cost.Model, result.Cost.InputTokens, result.Cost.OutputTokens)
	}
	if result.Omitted > 0 {
		var parts []string
		for rule, count := range result.OmittedRules {
			parts = append(parts, fmt.Sprintf("%s ×%d", rule, count))
		}
		sort.Strings(parts)
		fmt.Fprintf(cmd.ErrOrStderr(), "note: %d finding(s) omitted from triage (%s)\n",
			result.Omitted, strings.Join(parts, ", "))
	}
	return nil
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// verifiedRemediations returns only enki's own machine actions for findings
// where the model selected that exact action and validation accepted it.
func verifiedRemediations(result *ai.TriageResult, rep *report.Report) []remediate.Action {
	verified := make(map[string]string, len(result.Top))
	for _, item := range result.Top {
		if item.ActionVerified {
			verified[item.FindingID] = item.RecommendedAction
		}
	}
	filtered := *rep
	filtered.Findings = nil
	for _, f := range rep.Findings {
		want, ok := verified[f.ID]
		if ok && want != "manual" && f.Remediation != nil && f.Remediation.Action == want {
			filtered.Findings = append(filtered.Findings, f)
		}
	}
	return remediate.BuildPlan(&filtered)
}

func filterActions(plan []remediate.Action, only string) []remediate.Action {
	wanted := make(map[string]bool)
	for _, raw := range strings.Split(only, ",") {
		if rule := strings.ToUpper(strings.TrimSpace(raw)); rule != "" {
			wanted[rule] = true
		}
	}
	var out []remediate.Action
	for _, a := range plan {
		if wanted[a.RuleID] {
			out = append(out, a)
		}
	}
	return out
}

func applyVerified(reportOut, promptOut io.Writer, in io.Reader, plan []remediate.Action, autoAll bool) ([]remediate.Result, error) {
	if len(plan) == 0 {
		fmt.Fprintln(promptOut, "apply: no verified enki actions to apply")
		return nil, nil
	}
	selected := plan
	if !autoAll {
		if !platform.Interactive() {
			return nil, fmt.Errorf("apply: selection requires a terminal; use --only RULE or --yes")
		}
		idx, err := promptSelection(promptOut, in, plan)
		if err != nil {
			return nil, err
		}
		if len(idx) == 0 {
			fmt.Fprintln(promptOut, "apply: nothing selected")
			return nil, nil
		}
		selected = make([]remediate.Action, 0, len(idx))
		for _, i := range idx {
			selected = append(selected, plan[i-1])
		}
	}

	var results []remediate.Result
	applied := 0
	for _, a := range selected {
		res, err := remediate.Apply(a, false)
		if err != nil {
			fmt.Fprintf(promptOut, "ERROR    %s · %v\n", a.RuleID, err)
			continue
		}
		results = append(results, res)
		switch {
		case res.Applied:
			applied++
			fmt.Fprintf(reportOut, "APPLIED  %s · %s\n", a.RuleID, a.Summary)
		case res.Skipped:
			fmt.Fprintf(reportOut, "SKIPPED  %s · %s\n", a.RuleID, res.Reason)
		}
	}
	if applied > 0 {
		fmt.Fprintf(reportOut, "Applied %d verified fix(es). Undo with: enki undo\n", applied)
	}
	return results, nil
}

func promptSelection(out io.Writer, in io.Reader, plan []remediate.Action) ([]int, error) {
	fmt.Fprintln(out, "Verified enki fixes:")
	for i, a := range plan {
		fmt.Fprintf(out, "  %s\n", remediate.Describe(i, a))
	}
	reader := bufio.NewReader(in)
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprint(out, "Apply which? (e.g. 1,3 / all / none; Enter = none): ")
		line, _ := reader.ReadString('\n')
		idx, err := parseSelection(line, len(plan))
		if err == nil {
			return idx, nil
		}
		fmt.Fprintf(out, "invalid selection: %v\n", err)
	}
	return nil, fmt.Errorf("apply: no valid selection")
}

func parseSelection(answer string, n int) ([]int, error) {
	s := strings.ToLower(strings.TrimSpace(answer))
	switch s {
	case "", "none", "n", "no":
		return nil, nil
	case "all", "a", "y", "yes":
		idx := make([]int, n)
		for i := range idx {
			idx[i] = i + 1
		}
		return idx, nil
	}
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t'
	})
	seen := make(map[int]bool)
	for _, field := range fields {
		if strings.Contains(field, "-") {
			parts := strings.SplitN(field, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil || start < 1 || end > n || start > end {
				return nil, fmt.Errorf("invalid range %q (valid: 1-%d)", field, n)
			}
			for i := start; i <= end; i++ {
				seen[i] = true
			}
			continue
		}
		num, err := strconv.Atoi(field)
		if err != nil || num < 1 || num > n {
			return nil, fmt.Errorf("invalid fix %q (valid: 1-%d)", field, n)
		}
		seen[num] = true
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("no fixes selected")
	}
	idx := make([]int, 0, len(seen))
	for i := range seen {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	return idx, nil
}
