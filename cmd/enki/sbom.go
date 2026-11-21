package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/yogenpoonudurai/enki/internal/scanner/sbom"
	"github.com/yogenpoonudurai/enki/internal/version"
)

type sbomCmdOptions struct {
	deps            string
	paths           []string
	depth           int
	includeDev      bool
	includeGlobal   bool
	scanNodeModules bool
	osPackages      bool
	vulns           bool
	output          string
}

func newSBOMCmd() *cobra.Command {
	o := &sbomCmdOptions{deps: "all", depth: 3, includeDev: true, osPackages: true}
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Export a CycloneDX 1.5 SBOM of discovered dependencies",
		Long: "Discovers dependencies across npm, PyPI, Go, Cargo, NuGet and Linux OS\n" +
			"packages and emits a CycloneDX 1.5 JSON BOM. With --vulns, OSV advisories\n" +
			"are embedded (requires network access).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSBOM(cmd, o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.deps, "deps", "all", "dependency scope: all|ai")
	f.StringSliceVar(&o.paths, "paths", nil, "project roots to inventory (repeatable)")
	f.IntVar(&o.depth, "depth", 3, "directory walk depth")
	f.BoolVar(&o.includeDev, "include-dev", true, "include dev dependencies")
	f.BoolVar(&o.includeGlobal, "include-global", false, "include globally installed npm packages")
	f.BoolVar(&o.scanNodeModules, "scan-node-modules", false, "fallback: read node_modules when no lockfile exists")
	f.BoolVar(&o.osPackages, "os-packages", true, "include the Linux OS package inventory")
	f.BoolVar(&o.vulns, "vulns", false, "enrich with OSV vulnerabilities (network)")
	f.StringVarP(&o.output, "output", "o", "", "write the BOM to this file instead of stdout")
	return cmd
}

func runSBOM(cmd *cobra.Command, o *sbomCmdOptions) error {
	ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Minute)
	defer cancel()

	opts := sbom.Options{
		Deps:            o.deps,
		Roots:           o.paths,
		Depth:           o.depth,
		IncludeDev:      o.includeDev,
		IncludeGlobal:   o.includeGlobal,
		ScanNodeModules: o.scanNodeModules,
		OSPackages:      o.osPackages,
	}
	pkgs, gaps := sbom.Discover(ctx, opts, currentDir())
	if o.deps == "ai" {
		kept := pkgs[:0]
		for _, p := range pkgs {
			if sbom.IsAIPackage(p.Ecosystem, p.Name) {
				kept = append(kept, p)
			}
		}
		pkgs = kept
	}

	var vulns map[string][]*sbom.Advisory
	if o.vulns {
		v, vGaps := sbom.LookupAdvisories(ctx, sbom.NewClient(), pkgs)
		vulns = v
		gaps = append(gaps, vGaps...)
	}

	bom := sbom.BuildCycloneDX(pkgs, version.Version, vulns)

	w := cmd.OutOrStdout()
	if o.output != "" {
		f, err := os.Create(o.output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if err := bom.Write(w); err != nil {
		return err
	}
	for _, g := range gaps {
		fmt.Fprintf(cmd.ErrOrStderr(), "note [%s] %s\n", g.Module, g.Reason)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%d components · %d vulnerabilities\n", len(bom.Components), len(bom.Vulnerabilities))
	return nil
}

func currentDir() string {
	if w, err := os.Getwd(); err == nil {
		return w
	}
	return "."
}
