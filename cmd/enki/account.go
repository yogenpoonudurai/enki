package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/hosted"
)

func newAccountCmd() *cobra.Command {
	var (
		hostedURL string
		asJSON    bool
	)
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Show your hosted plan and triage allowance",
		Long: "Shows the plan, remaining triage allowance, and organization for the\n" +
			"hosted service account. Configure with ENKI_CLOUD_URL and\n" +
			"ENKI_CLOUD_TOKEN. Local scanning and BYOK triage never need an account.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := hosted.ConfigFromEnv()
			if hostedURL != "" {
				cfg.BaseURL = hostedURL
			}
			client, err := hosted.New(cfg)
			if err != nil {
				return fmt.Errorf("%w\nhint: set ENKI_CLOUD_URL and ENKI_CLOUD_TOKEN (see docs/premium.md)", err)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			usage, err := client.Usage(ctx)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(usage)
			}
			fmt.Fprintf(out, "plan: %s\n", usage.Plan)
			fmt.Fprintf(out, "remaining: %s\n", remainingLabel(usage))
			if usage.FreeQuota > 0 {
				fmt.Fprintf(out, "free quota: %d\n", usage.FreeQuota)
			}
			if usage.Org != "" {
				fmt.Fprintf(out, "org: %s\n", usage.Org)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&hostedURL, "hosted-url", "", "hosted service base URL (default: ENKI_CLOUD_URL)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// remainingLabel renders the allowance the service reports; -1 means unlimited.
func remainingLabel(u hosted.Usage) string {
	if u.Remaining < 0 {
		return "unlimited triages remaining"
	}
	if u.Remaining == 1 {
		return "1 triage remaining"
	}
	return fmt.Sprintf("%d triages remaining", u.Remaining)
}
