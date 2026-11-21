package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/diagnostics"
)

func newDoctorCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Show local diagnostics that tailor remediation advice",
		Long: "Prints the local system context enki provides to AI triage and the\n" +
			"deterministic fix planner: OS, service manager, firewall/package tools,\n" +
			"privileges, container status, capabilities, and limitations.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rep := diagnostics.Collect()
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "os:              %s/%s\n", rep.OS, rep.Arch)
			if rep.Distro != "" {
				fmt.Fprintf(w, "distro:          %s %s\n", rep.Distro, rep.DistroVersion)
			}
			if rep.Kernel != "" {
				fmt.Fprintf(w, "kernel:          %s\n", rep.Kernel)
			}
			fmt.Fprintf(w, "elevated:        %v\n", rep.Elevated)
			fmt.Fprintf(w, "container:       %v\n", rep.Container)
			if rep.Shell != "" {
				fmt.Fprintf(w, "shell:           %s\n", rep.Shell)
			}
			fmt.Fprintf(w, "service manager: %s\n", rep.ServiceManager)
			fmt.Fprintf(w, "firewall tools:  %s\n", listOrNone(rep.Firewalls))
			fmt.Fprintf(w, "package tools:   %s\n", listOrNone(rep.PackageManagers))
			fmt.Fprintln(w, "\ncapabilities:")
			for _, c := range rep.Capabilities {
				fmt.Fprintf(w, "  + %s\n", c)
			}
			fmt.Fprintln(w, "\nlimitations:")
			for _, l := range rep.Limitations {
				fmt.Fprintf(w, "  - %s\n", l)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit diagnostics as JSON")
	return cmd
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "(none detected)"
	}
	return strings.Join(items, ", ")
}
