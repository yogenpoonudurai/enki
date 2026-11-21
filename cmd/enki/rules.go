package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/rules"
	"github.com/yogenpoonudurai/enki/internal/scanrun"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Inspect and validate the built-in rule catalog",
	}

	var moduleFilter string
	list := &cobra.Command{
		Use:   "list",
		Short: "List built-in rules",
		Run: func(cmd *cobra.Command, _ []string) {
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-9s %-20s %-16s %s\n", "ID", "MODULE", "SEVERITY", "TITLE")
			for _, r := range rules.Catalog {
				if moduleFilter != "" && r.Module != moduleFilter {
					continue
				}
				fmt.Fprintf(w, "%-9s %-20s %-16s %s\n", r.ID, r.Module, r.Severity, r.Title)
			}
		},
	}
	list.Flags().StringVar(&moduleFilter, "module", "", "only show rules for this module")

	validate := &cobra.Command{
		Use:   "validate",
		Short: "Validate rule IDs, modules, and required fields",
		RunE: func(cmd *cobra.Command, _ []string) error {
			problems := rules.Validate(scanrun.ModuleNames())
			if len(problems) > 0 {
				return fmt.Errorf("rule catalog invalid:\n  %s", strings.Join(problems, "\n  "))
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d rules valid · pack %s\n", len(rules.Catalog), rules.Version)
			return nil
		},
	}

	cmd.AddCommand(list, validate)
	return cmd
}
