// Package mcpserver exposes enki as Model Context Protocol tools.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yogenpoonudurai/enki/internal/ai"
	"github.com/yogenpoonudurai/enki/internal/remediate"
	"github.com/yogenpoonudurai/enki/internal/rules"
	"github.com/yogenpoonudurai/enki/internal/scanner"
	"github.com/yogenpoonudurai/enki/internal/scanner/sbom"
	"github.com/yogenpoonudurai/enki/internal/scanrun"
	"github.com/yogenpoonudurai/enki/internal/version"
)

// New builds the enki MCP server with all tools registered.
func New() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "enki",
		Version: version.Version,
	}, nil)

	registerScan(s)
	registerPlanFix(s)
	registerRules(s)
	registerSBOM(s)
	registerExplain(s)
	registerTriage(s)
	return s
}

type scanArgs struct {
	Paths       []string `json:"paths,omitempty" jsonschema:"project roots to scan; defaults to the current working directory"`
	Deps        string   `json:"deps,omitempty" jsonschema:"dependency scope: ai or all (default ai)"`
	Modules     []string `json:"modules,omitempty" jsonschema:"limit checks to these modules"`
	IncludeDev  *bool    `json:"include_dev,omitempty" jsonschema:"include dev dependencies (default true)"`
	OSPackages  *bool    `json:"os_packages,omitempty" jsonschema:"include the Linux OS package inventory (default false)"`
	ProbeRemote bool     `json:"probe_remote,omitempty" jsonschema:"allow probing private-network listeners"`
}

func (a scanArgs) options() scanrun.Options {
	o := scanrun.Options{
		Deps:        a.Deps,
		Paths:       a.Paths,
		Modules:     a.Modules,
		ProbeRemote: a.ProbeRemote,
		IncludeDev:  true,
		OSPackages:  false,
		Timeout:     3 * time.Minute,
	}
	if a.IncludeDev != nil {
		o.IncludeDev = *a.IncludeDev
	}
	if a.OSPackages != nil {
		o.OSPackages = *a.OSPackages
	}
	return o
}

func registerScan(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "enki_scan",
		Description: "Scan the local host and project for AI configuration and exposure issues. Returns the full enki JSON report (findings, severities, remediation actions, coverage gaps). Dependency checks default to the AI catalog; deterministic and offline except OSV advisory lookups.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args scanArgs) (*mcp.CallToolResult, any, error) {
		rep, err := scanrun.Run(ctx, args.options(), nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(rep)
	})
}

func registerPlanFix(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "enki_plan_fix",
		Description: "Scan the host and return a remediation plan: SAFE actions (permissions), MODERATE config edits, and RISKY manual commands. Never applies changes.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args scanArgs) (*mcp.CallToolResult, any, error) {
		rep, err := scanrun.Run(ctx, args.options(), nil)
		if err != nil {
			return nil, nil, err
		}
		plan := remediate.BuildPlan(rep)
		out := struct {
			ScanID  string             `json:"scan_id"`
			Score   int                `json:"score"`
			Verdict string             `json:"verdict"`
			Actions []remediate.Action `json:"actions"`
		}{
			ScanID: rep.Scan.ID, Score: rep.Summary.Score, Verdict: rep.Summary.Verdict, Actions: plan,
		}
		return jsonResult(out)
	})
}

type rulesArgs struct {
	Module string `json:"module,omitempty" jsonschema:"only return rules for this module"`
}

func registerRules(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "enki_rules",
		Description: "List enki's built-in rule catalogue with rule IDs, modules, severities, and titles.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args rulesArgs) (*mcp.CallToolResult, any, error) {
		var list []rules.Rule
		for _, r := range rules.Catalog {
			if args.Module == "" || r.Module == args.Module {
				list = append(list, r)
			}
		}
		out := struct {
			Pack  string       `json:"pack"`
			Rules []rules.Rule `json:"rules"`
		}{Pack: rules.Version, Rules: list}
		return jsonResult(out)
	})
}

type sbomArgs struct {
	Paths           []string `json:"paths,omitempty" jsonschema:"project roots to inventory; defaults to the current working directory"`
	Depth           int      `json:"depth,omitempty" jsonschema:"directory walk depth (default 3)"`
	Deps            string   `json:"deps,omitempty" jsonschema:"dependency scope: all or ai"`
	IncludeDev      *bool    `json:"include_dev,omitempty" jsonschema:"include dev dependencies (default true)"`
	IncludeGlobal   bool     `json:"include_global,omitempty" jsonschema:"include global npm packages"`
	ScanNodeModules bool     `json:"scan_node_modules,omitempty" jsonschema:"fallback: read node_modules when no lockfile exists"`
	OSPackages      *bool    `json:"os_packages,omitempty" jsonschema:"include Linux OS packages (default true)"`
	Vulns           bool     `json:"vulns,omitempty" jsonschema:"enrich with OSV vulnerabilities (network)"`
}

func registerSBOM(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "enki_sbom",
		Description: "Generate a CycloneDX 1.5 SBOM of discovered dependencies (npm, PyPI, Go, Cargo, NuGet, Linux OS packages). Optionally enrich with OSV vulnerabilities.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args sbomArgs) (*mcp.CallToolResult, any, error) {
		opts := sbom.Options{
			Deps:            args.Deps,
			Roots:           args.Paths,
			Depth:           args.Depth,
			IncludeDev:      true,
			IncludeGlobal:   args.IncludeGlobal,
			ScanNodeModules: args.ScanNodeModules,
			OSPackages:      true,
		}
		if args.IncludeDev != nil {
			opts.IncludeDev = *args.IncludeDev
		}
		if args.OSPackages != nil {
			opts.OSPackages = *args.OSPackages
		}
		cwd, _ := os.Getwd()
		pkgs, gaps := sbom.Discover(ctx, opts, cwd)

		var vulns map[string][]*sbom.Advisory
		if args.Vulns {
			var vGaps []scanner.CoverageGap
			vulns, vGaps = sbom.LookupAdvisories(ctx, sbom.NewClient(), pkgs)
			gaps = append(gaps, vGaps...)
		}
		bom := sbom.BuildCycloneDX(pkgs, version.Version, vulns)
		out := struct {
			BOM  *sbom.CycloneDX       `json:"bom"`
			Gaps []scanner.CoverageGap `json:"coverage_gaps,omitempty"`
		}{BOM: bom, Gaps: gaps}
		return jsonResult(out)
	})
}

type explainArgs struct {
	RuleID string `json:"rule_id" jsonschema:"the enki rule ID to explain (e.g. AEP-001)"`
}

func registerExplain(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "enki_explain_rule",
		Description: "Explain a rule ID: what it checks, its severity, and its module. Use enki_scan to obtain findings and enki_plan_fix for remediation.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, args explainArgs) (*mcp.CallToolResult, any, error) {
		for _, r := range rules.Catalog {
			if r.ID == args.RuleID {
				return jsonResult(r)
			}
		}
		return nil, nil, fmt.Errorf("unknown rule %q", args.RuleID)
	})
}

func registerTriage(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "enki_triage",
		Description: "Scan the host and rank/explain findings with the configured AI provider. Sends a redacted payload (no secrets or absolute paths). Requires an explicit provider configuration (DEEPSEEK_API_KEY or ENKI_AI_BASE_URL) and user consent. The model may only rank and explain; it never executes actions.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args scanArgs) (*mcp.CallToolResult, any, error) {
		cfg := ai.DefaultConfig()
		provider, err := ai.NewProvider(cfg)
		if err != nil {
			return nil, nil, err
		}
		rep, err := scanrun.Run(ctx, args.options(), nil)
		if err != nil {
			return nil, nil, err
		}
		result, _, err := ai.Triage(ctx, provider, cfg.Model, rep, 40)
		if err != nil {
			return nil, nil, err
		}
		return jsonResult(result)
	})
}

func jsonResult(v any) (*mcp.CallToolResult, any, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(data)}},
	}, v, nil
}
