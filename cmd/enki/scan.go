package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/platform"
	"github.com/yogenpoonudurai/enki/internal/report"
	"github.com/yogenpoonudurai/enki/internal/report/asciireport"
	"github.com/yogenpoonudurai/enki/internal/report/jsonout"
	"github.com/yogenpoonudurai/enki/internal/report/ocsf"
	"github.com/yogenpoonudurai/enki/internal/report/plain"
	"github.com/yogenpoonudurai/enki/internal/report/sarif"
	"github.com/yogenpoonudurai/enki/internal/scanner"
	"github.com/yogenpoonudurai/enki/internal/scanrun"
)

type scanOptions struct {
	scope       string
	asJSON      bool
	asSARIF     bool
	asOCSF      bool
	reportPath  string
	failOn      string
	modules     []string
	probeRemote bool
	ignore      []string

	deps            string
	paths           []string
	depth           int
	includeDev      bool
	includeGlobal   bool
	scanNodeModules bool
	osPackages      bool
}

// defaultScanOptions is the shared baseline for scan, fix and the dashboard.
func defaultScanOptions() *scanOptions {
	return &scanOptions{
		scope:      "full",
		failOn:     "high",
		deps:       "ai",
		depth:      3,
		includeDev: true,
		osPackages: false,
	}
}

func newScanCmd() *cobra.Command {
	opts := defaultScanOptions()
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan this host for AI security posture issues",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), opts)
		},
	}
	f := cmd.Flags()
	f.StringVar(&opts.scope, "scope", "full", "what to inspect: project (repository only), host (machine only), or full")
	f.BoolVar(&opts.asJSON, "json", false, "emit machine-readable JSON")
	f.BoolVar(&opts.asSARIF, "sarif", false, "emit SARIF 2.1.0 for code scanning UIs")
	f.BoolVar(&opts.asOCSF, "ocsf", false, "emit OCSF detection finding events for SIEM ingestion")
	f.StringVar(&opts.reportPath, "report", "", "also write an ASCII report to this file")
	f.StringVar(&opts.failOn, "fail-on", "high", "exit 1 when a finding at or above this severity exists (critical|high|medium|low|info|none)")
	f.StringSliceVar(&opts.modules, "modules", nil, "run only these modules: "+strings.Join(scanrun.ModuleNames(), ", "))
	f.BoolVar(&opts.probeRemote, "probe-remote", false, "allow probing private-network listeners (RFC1918), not just loopback")
	f.StringSliceVar(&opts.ignore, "ignore-rule", nil, "suppress a rule ID (repeatable)")
	f.StringVar(&opts.deps, "deps", "ai", "dependency scope: ai (AI catalog, default) or all (every package)")
	f.StringSliceVar(&opts.paths, "paths", nil, "additional project roots to scan for manifests (repeatable)")
	f.IntVar(&opts.depth, "depth", 3, "directory walk depth for manifest discovery")
	f.BoolVar(&opts.includeDev, "include-dev", true, "include dev dependencies (tagged dev when included)")
	f.BoolVar(&opts.includeGlobal, "include-global", false, "include globally installed npm packages")
	f.BoolVar(&opts.scanNodeModules, "scan-node-modules", false, "fallback: read node_modules when no lockfile exists")
	f.BoolVar(&opts.osPackages, "os-packages", false, "include the Linux OS package inventory (opt-in)")
	return cmd
}

func runScan(parent context.Context, opts *scanOptions) error {
	threshold, err := parseThreshold(opts.failOn)
	if err != nil {
		return err
	}
	if opts.deps != "all" && opts.deps != "ai" {
		return fmt.Errorf("invalid --deps value %q (use all or ai)", opts.deps)
	}
	if _, ok := scanner.ParseScope(opts.scope); !ok {
		return fmt.Errorf("invalid --scope value %q (use project, host, or full)", opts.scope)
	}
	formats := 0
	for _, on := range []bool{opts.asJSON, opts.asSARIF, opts.asOCSF} {
		if on {
			formats++
		}
	}
	if formats > 1 {
		return fmt.Errorf("choose one output format: --json, --sarif or --ocsf")
	}

	rep, err := scanHost(parent, opts)
	if err != nil {
		return err
	}

	switch {
	case opts.asJSON:
		err = jsonout.Write(os.Stdout, rep)
	case opts.asSARIF:
		err = sarif.Write(os.Stdout, rep)
	case opts.asOCSF:
		err = ocsf.Write(os.Stdout, rep)
	default:
		plain.Write(os.Stdout, rep, platform.ColorEnabled())
	}
	if err != nil {
		return err
	}

	if opts.reportPath != "" {
		f, ferr := os.Create(opts.reportPath)
		if ferr != nil {
			return ferr
		}
		if werr := asciireport.Write(f, rep); werr != nil {
			f.Close()
			return werr
		}
		if cerr := f.Close(); cerr != nil {
			return cerr
		}
		fmt.Fprintf(os.Stderr, "ASCII report written to %s\n", opts.reportPath)
	}

	if threshold != nil && plain.SeverityAtOrAbove(rep, *threshold) {
		return errThreshold
	}
	return nil
}

// scanHost gathers host facts, runs the selected modules and returns a report.
func scanHost(parent context.Context, opts *scanOptions) (*report.Report, error) {
	return scanHostWithProgress(parent, opts, nil)
}

func scanHostWithProgress(parent context.Context, opts *scanOptions, onProgress func(scanner.Progress)) (*report.Report, error) {
	scope, _ := scanner.ParseScope(opts.scope)
	return scanrun.Run(parent, scanrun.Options{
		Scope:           scope,
		Deps:            opts.deps,
		Paths:           opts.paths,
		Depth:           opts.depth,
		IncludeDev:      opts.includeDev,
		IncludeGlobal:   opts.includeGlobal,
		ScanNodeModules: opts.scanNodeModules,
		OSPackages:      opts.osPackages,
		ProbeRemote:     opts.probeRemote,
		Modules:         opts.modules,
		IgnoreRules:     opts.ignore,
	}, onProgress)
}

func parseThreshold(v string) (*finding.Severity, error) {
	if strings.EqualFold(v, "none") || v == "" {
		return nil, nil
	}
	s, ok := finding.ParseSeverity(v)
	if !ok {
		return nil, fmt.Errorf("invalid --fail-on value %q", v)
	}
	return &s, nil
}
