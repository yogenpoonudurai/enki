package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/yogenpoonudurai/enki/internal/ai"
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
	yes         bool
	showPayload bool
}

func newTriageCmd() *cobra.Command {
	o := &triageOptions{limit: 40}
	cmd := &cobra.Command{
		Use:   "triage <report.json|->",
		Short: "Rank and explain findings with a constrained AI triage pass",
		Long: "Sends a redacted findings payload to the configured model provider and\n" +
			"returns a validated ranking. Configure with DEEPSEEK_API_KEY or\n" +
			"ENKI_AI_PROVIDER/ENKI_AI_BASE_URL (any OpenAI-compatible endpoint).\n" +
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
	f.BoolVar(&o.yes, "yes", false, "skip the apply confirmation (requires --apply)")
	f.BoolVar(&o.showPayload, "show-payload", false, "include the redacted payload in the output")
	return cmd
}

func runTriage(cmd *cobra.Command, path string, o *triageOptions) error {
	if o.yes && !o.apply {
		return fmt.Errorf("--yes requires --apply")
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

	ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
	defer cancel()
	result, payload, err := ai.Triage(ctx, provider, cfg.Model, &rep, o.limit)
	if err != nil {
		return err
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
	}
	if text {
		ai.WriteHuman(cmd.OutOrStdout(), result, &rep)
		if o.apply {
			if _, err := applyVerified(cmd.OutOrStdout(), cmd.ErrOrStderr(), cmd.InOrStdin(), plan, o.yes); err != nil {
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
		applied, err := applyVerified(io.Discard, cmd.ErrOrStderr(), cmd.InOrStdin(), plan, o.yes)
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
	if result.Cost.Metered {
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

func applyVerified(reportOut, promptOut io.Writer, in io.Reader, plan []remediate.Action, yes bool) ([]remediate.Result, error) {
	if len(plan) == 0 {
		fmt.Fprintln(promptOut, "apply: no verified enki actions to apply")
		return nil, nil
	}
	if !yes {
		if !platform.Interactive() {
			return nil, fmt.Errorf("apply: confirmation requires a terminal; rerun with --yes")
		}
		fmt.Fprintf(promptOut, "Apply %d verified enki fix(es)? [y/N] ", len(plan))
		line, _ := bufio.NewReader(in).ReadString('\n')
		ans := strings.ToLower(strings.TrimSpace(line))
		if ans != "y" && ans != "yes" {
			fmt.Fprintln(promptOut, "apply: skipped")
			return nil, nil
		}
	}

	var results []remediate.Result
	applied := 0
	for _, a := range plan {
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
