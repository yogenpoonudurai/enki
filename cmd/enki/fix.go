package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/platform"
	"github.com/yogenpoonudurai/enki/internal/remediate"
)

type fixOptions struct {
	apply           bool
	includeModerate bool
	yes             bool
	asJSON          bool
}

func newFixCmd() *cobra.Command {
	opts := &fixOptions{}
	cmd := &cobra.Command{
		Use:   "fix",
		Short: "Plan and apply guarded remediations for scan findings",
		Long: "Plan remediations for this host. Safe actions (file permissions) are applied\n" +
			"with --apply; config edits require --include-moderate; risky actions are\n" +
			"printed as commands for the operator. Every applied change is backed up and\n" +
			"can be reverted with `enki undo`.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFix(cmd, opts)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&opts.apply, "apply", false, "apply safe actions (dry run by default)")
	f.BoolVar(&opts.includeModerate, "include-moderate", false, "also apply moderate actions (config edits)")
	f.BoolVar(&opts.yes, "yes", false, "answer yes to confirmation prompts (moderate actions)")
	f.BoolVar(&opts.asJSON, "json", false, "emit the fix plan as JSON")
	return cmd
}

func runFix(cmd *cobra.Command, opts *fixOptions) error {
	scanOpts := defaultScanOptions()
	scanOpts.failOn = "none"
	rep, err := scanHost(cmd.Context(), scanOpts)
	if err != nil {
		return err
	}
	plan := remediate.BuildPlan(rep)

	if opts.asJSON {
		out := struct {
			DryRun  bool               `json:"dry_run"`
			Actions []remediate.Action `json:"actions"`
			Results []remediate.Result `json:"results,omitempty"`
		}{DryRun: !opts.apply, Actions: plan}
		if opts.apply {
			out.Results = executePlan(plan, opts, false)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	if len(plan) == 0 {
		fmt.Println("No automated or guided remediations available.")
		return nil
	}

	fmt.Printf("FIX PLAN · %d action(s) · %s\n\n", len(plan), modeLabel(opts.apply))
	for i, a := range plan {
		fmt.Println(remediate.Describe(i, a))
		if !a.Auto {
			switch {
			case a.Command != "":
				fmt.Printf("            run: %s\n", a.Command)
			case a.Guidance != "":
				fmt.Printf("            %s\n", a.Guidance)
			}
		}
	}
	fmt.Println()

	if !opts.apply {
		fmt.Println("Dry run. Apply safe actions with: enki fix --apply")
		fmt.Println("Include config edits with:      enki fix --apply --include-moderate")
		return nil
	}

	results := executePlan(plan, opts, true)
	applied := 0
	for _, res := range results {
		if res.Applied {
			applied++
		}
	}
	fmt.Printf("\n%d action(s) applied. Undo with: enki undo\n", applied)
	return nil
}

func executePlan(plan []remediate.Action, opts *fixOptions, verbose bool) []remediate.Result {
	var results []remediate.Result
	interactive := platform.Interactive()
	reader := bufio.NewReader(os.Stdin)

	for _, a := range plan {
		if !a.Auto {
			if verbose && a.Command != "" {
				fmt.Printf("MANUAL   %s → %s\n", a.RuleID, a.Command)
			}
			continue
		}
		if a.Class == finding.ActionModerate && !opts.includeModerate {
			if verbose {
				fmt.Printf("SKIPPED  %s · config edits need --include-moderate\n", a.RuleID)
			}
			continue
		}
		if a.Class != finding.ActionSafe && !opts.yes {
			if !interactive {
				if verbose {
					fmt.Printf("SKIPPED  %s · requires a terminal or --yes\n", a.RuleID)
				}
				continue
			}
			fmt.Printf("Apply %q? [y/N] ", a.Summary)
			line, _ := reader.ReadString('\n')
			ans := strings.ToLower(strings.TrimSpace(line))
			if ans != "y" && ans != "yes" {
				fmt.Printf("SKIPPED  %s\n", a.RuleID)
				continue
			}
		}
		res, err := remediate.Apply(a, false)
		if err != nil {
			if verbose {
				fmt.Printf("ERROR    %s · %v\n", a.RuleID, err)
			}
			continue
		}
		results = append(results, res)
		if verbose {
			switch {
			case res.Applied:
				fmt.Printf("APPLIED  %s · %s\n", a.RuleID, a.Summary)
			case res.Skipped:
				fmt.Printf("SKIPPED  %s · %s\n", a.RuleID, res.Reason)
			}
		}
	}
	return results
}

func modeLabel(apply bool) string {
	if apply {
		return "apply"
	}
	return "dry run"
}
