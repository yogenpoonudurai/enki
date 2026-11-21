// Package scanrun holds the shared scan orchestration used by the CLI, the
// dashboard, and the MCP server.
package scanrun

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/yogenpoonudurai/enki/internal/collector"
	"github.com/yogenpoonudurai/enki/internal/platform"
	"github.com/yogenpoonudurai/enki/internal/report"
	"github.com/yogenpoonudurai/enki/internal/rules"
	"github.com/yogenpoonudurai/enki/internal/scanner"
	"github.com/yogenpoonudurai/enki/internal/scanner/agentcfg"
	"github.com/yogenpoonudurai/enki/internal/scanner/aiendpoint"
	"github.com/yogenpoonudurai/enki/internal/scanner/mcp"
	"github.com/yogenpoonudurai/enki/internal/scanner/model"
	"github.com/yogenpoonudurai/enki/internal/scanner/sbom"
	"github.com/yogenpoonudurai/enki/internal/scanner/secrets"
	"github.com/yogenpoonudurai/enki/internal/version"
)

// Options configures a host scan.
type Options struct {
	Deps            string
	Paths           []string
	Depth           int
	IncludeDev      bool
	IncludeGlobal   bool
	ScanNodeModules bool
	OSPackages      bool
	ProbeRemote     bool
	Modules         []string
	IgnoreRules     []string
	Timeout         time.Duration
}

func (o Options) normalized() Options {
	if o.Deps == "" {
		o.Deps = "all"
	}
	if o.Depth <= 0 {
		o.Depth = 3
	}
	if o.Timeout <= 0 {
		o.Timeout = 2 * time.Minute
	}
	return o
}

// Run performs a full host scan and returns the assembled report.
func Run(parent context.Context, opts Options, onProgress func(scanner.Progress)) (*report.Report, error) {
	opts = opts.normalized()
	modules, err := buildModules(opts)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(parent, opts.Timeout)
	defer cancel()
	started := time.Now()

	sc := &scanner.Context{
		Ctx:         ctx,
		Now:         started,
		HomeDir:     homeDir(),
		WorkingDir:  workDir(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Hostname:    hostname(),
		Username:    username(),
		Elevated:    platform.Elevated(),
		ProbeRemote: opts.ProbeRemote,
		IgnoreRules: toSet(opts.IgnoreRules),
		OnProgress:  onProgress,
	}

	listeners, gaps := collector.Listeners()
	sc.Listeners = listeners
	sc.Gaps = append(sc.Gaps, gaps...)
	configs, gaps := collector.DiscoverConfigs(sc.HomeDir, sc.WorkingDir)
	sc.Configs = configs
	sc.Gaps = append(sc.Gaps, gaps...)

	results := (&scanner.Engine{Modules: modules}).Run(sc)
	return report.Build(version.Version, rules.Version, sc, results, started, ""), nil
}

func buildModules(o Options) ([]scanner.Module, error) {
	all := []scanner.Module{
		aiendpoint.New(),
		mcp.New(),
		agentcfg.New(),
		secrets.New(),
		model.New(),
		sbom.New(sbom.Options{
			Deps:            o.Deps,
			Roots:           o.Paths,
			Depth:           o.Depth,
			IncludeDev:      o.IncludeDev,
			IncludeGlobal:   o.IncludeGlobal,
			ScanNodeModules: o.ScanNodeModules,
			OSPackages:      o.OSPackages,
		}),
	}
	if len(o.Modules) == 0 {
		return all, nil
	}
	byName := make(map[string]scanner.Module, len(all))
	for _, m := range all {
		byName[m.Name()] = m
	}
	selected := make([]scanner.Module, 0, len(o.Modules))
	for _, name := range o.Modules {
		m, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown module %q (available: %v)", name, ModuleNames())
		}
		selected = append(selected, m)
	}
	return selected, nil
}

// ModuleNames lists the available scanner modules.
func ModuleNames() []string {
	mods := []scanner.Module{
		aiendpoint.New(), mcp.New(), agentcfg.New(), secrets.New(), model.New(),
		sbom.New(sbom.Options{}),
	}
	names := make([]string, 0, len(mods))
	for _, m := range mods {
		names = append(names, m.Name())
	}
	return names
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}

func workDir() string {
	if w, err := os.Getwd(); err == nil {
		return w
	}
	return "."
}

func hostname() string {
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "unknown"
}

func username() string {
	for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return "unknown"
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	set := make(map[string]bool, len(items))
	for _, it := range items {
		set[strings.ToUpper(strings.TrimSpace(it))] = true
	}
	return set
}
