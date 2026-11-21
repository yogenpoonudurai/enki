package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/platform"
	"github.com/yogenpoonudurai/enki/internal/report"
	"github.com/yogenpoonudurai/enki/internal/report/asciireport"
)

func newReportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "report <file|->",
		Short: "Render an ASCII report from a saved JSON scan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var data []byte
			var err error
			if args[0] == "-" {
				data, err = io.ReadAll(cmd.InOrStdin())
			} else {
				data, err = os.ReadFile(args[0])
			}
			if err != nil {
				return err
			}
			var rep report.Report
			if err := json.Unmarshal(data, &rep); err != nil {
				return fmt.Errorf("invalid enki JSON report: %w", err)
			}
			_, err = io.WriteString(cmd.OutOrStdout(), asciireport.Render(&rep, platform.ColorEnabled()))
			return err
		},
	}
}
