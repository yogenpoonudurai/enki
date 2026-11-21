package main

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/platform"
	"github.com/yogenpoonudurai/enki/internal/report"
	"github.com/yogenpoonudurai/enki/internal/report/tui"
	"github.com/yogenpoonudurai/enki/internal/scanner"
	"github.com/yogenpoonudurai/enki/internal/version"
)

// Execute runs the enki CLI.
func Execute() error {
	return newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "enki",
		Short: "AI security posture scanner for laptops and servers",
		Long: strings.Join(report.SmallLogoLines(), "\n") + "\n" +
			report.Title + " · " + version.Version + "\n\n" +
			"enki audits local AI tooling: exposed inference endpoints, MCP server\n" +
			"configurations, agent permissions, provider secrets, model artifacts,\n" +
			"and AI dependency vulnerabilities — with guarded, reversible fixes.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if platform.Interactive() {
				return runDashboard(cmd.Context())
			}
			opts := defaultScanOptions()
			return runScan(cmd.Context(), opts)
		},
	}
	root.AddCommand(
		newScanCmd(),
		newFixCmd(),
		newUndoCmd(),
		newReportCmd(),
		newSBOMCmd(),
		newTriageCmd(),
		newDoctorCmd(),
		newRulesCmd(),
		newBannerCmd(),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	var art bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if art {
				for _, line := range report.LogoGradient(platform.ColorEnabled()) {
					fmt.Fprintln(cmd.OutOrStdout(), line)
				}
				fmt.Fprintln(cmd.OutOrStdout())
			}
			fmt.Fprintln(cmd.OutOrStdout(), strings.Join(report.SmallLogoGradient(platform.ColorEnabled()), "\n"))
			fmt.Fprintf(cmd.OutOrStdout(), "\n%s %s (%s, %s)\n", report.Title, version.Version, version.Commit, version.Date)
			return nil
		},
	}
	cmd.Flags().BoolVar(&art, "art", false, "include the full-size artwork")
	return cmd
}

// runDashboard launches the interactive Bubble Tea dashboard and starts a
// scan immediately.
func runDashboard(ctx context.Context) error {
	scanFunc := func(scanCtx context.Context, onProgress func(scanner.Progress)) (*report.Report, error) {
		opts := defaultScanOptions()
		opts.failOn = "none"
		return scanHostWithProgress(scanCtx, opts, onProgress)
	}
	program := tea.NewProgram(tui.New(version.Version, scanFunc), tea.WithAltScreen())
	_, err := program.Run()
	return err
}
