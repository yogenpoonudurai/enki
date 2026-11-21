package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/ai"
	"github.com/yogenpoonudurai/enki/internal/report"
)

type triageOptions struct {
	provider    string
	model       string
	baseURL     string
	key         string
	limit       int
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
			"The model may only rank and explain; it never executes actions.",
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
	f.BoolVar(&o.showPayload, "show-payload", false, "include the redacted payload in the output")
	return cmd
}

func runTriage(cmd *cobra.Command, path string, o *triageOptions) error {
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

	out := struct {
		Result       *ai.TriageResult `json:"result"`
		FindingsSent int              `json:"findings_sent"`
		Omitted      int              `json:"omitted,omitempty"`
		Payload      *ai.Payload      `json:"payload,omitempty"`
	}{
		Result:       result,
		FindingsSent: len(payload.Findings),
		Omitted:      payload.Omitted,
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
