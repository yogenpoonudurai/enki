package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/platform"
	"github.com/yogenpoonudurai/enki/internal/report"
	"github.com/yogenpoonudurai/enki/internal/version"
)

func newBannerCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "banner",
		Short: "Print the full-size enki artwork",
		Run: func(cmd *cobra.Command, _ []string) {
			w := cmd.OutOrStdout()
			for _, line := range report.LogoGradient(platform.ColorEnabled()) {
				fmt.Fprintln(w, line)
			}
			fmt.Fprintf(w, "\n%s · v%s\n", report.Title, version.Version)
		},
	}
}
