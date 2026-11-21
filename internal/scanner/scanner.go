// Package scanner provides the module registry and parallel scan engine.
package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/yogenpoonudurai/enki/internal/collector"
	"github.com/yogenpoonudurai/enki/internal/finding"
)

type ProgressState string

const (
	StateRunning ProgressState = "running"
	StateDone    ProgressState = "done"
	StateError   ProgressState = "error"
)

// Progress is emitted by the engine as each module advances. Callbacks may be
// invoked concurrently from module goroutines.
type Progress struct {
	Module string        `json:"module"`
	State  ProgressState `json:"state"`
	Detail string        `json:"detail,omitempty"`
}

// Scope controls which surfaces a scan inspects.
type Scope string

const (
	ScopeProject Scope = "project"
	ScopeHost    Scope = "host"
	ScopeFull    Scope = "full"
)

func ParseScope(v string) (Scope, bool) {
	switch Scope(v) {
	case ScopeProject, ScopeHost, ScopeFull:
		return Scope(v), true
	}
	return "", false
}

func (s Scope) IncludesHost() bool    { return s != ScopeProject }
func (s Scope) IncludesProject() bool { return s != ScopeHost }

// CoverageGap marks a blind spot so reports never claim "clean" when blind.
type CoverageGap = collector.Gap

const (
	GapNotApplicable = collector.GapNotApplicable
	GapPermission    = collector.GapPermission
	GapUnsupported   = collector.GapUnsupported
	GapTruncated     = collector.GapTruncated
	GapNetwork       = collector.GapNetwork
	GapError         = collector.GapError
)

// Context carries gathered facts and scan configuration to every module.
type Context struct {
	Ctx         context.Context
	Now         time.Time
	HomeDir     string
	WorkingDir  string
	Scope       Scope
	OS          string
	Arch        string
	Hostname    string
	Username    string
	Elevated    bool
	ProbeRemote bool
	IgnoreRules map[string]bool
	SkipModules map[string]bool
	Listeners   []collector.Listener
	Configs     []collector.ConfigFile
	Gaps        []CoverageGap
	OnProgress  func(Progress)
}

func (c *Context) Emit(p Progress) {
	if c.OnProgress != nil {
		c.OnProgress(p)
	}
}

func (c *Context) Ignored(ruleID string) bool {
	return c.IgnoreRules != nil && c.IgnoreRules[ruleID]
}

// Module is one independent scanner (one check family).
type Module interface {
	Name() string
	Description() string
	Run(*Context) (findings []finding.Finding, gaps []CoverageGap, err error)
}

type ModuleResult struct {
	Module   string
	Findings []finding.Finding
	Gaps     []CoverageGap
	Err      error
	Skipped  bool
	Duration time.Duration
}

type Engine struct {
	Modules []Module
}

// Run executes all modules in parallel and returns results in registry order.
func (e *Engine) Run(sc *Context) []*ModuleResult {
	results := make([]*ModuleResult, len(e.Modules))
	var wg sync.WaitGroup
	for i, m := range e.Modules {
		wg.Add(1)
		go func(i int, m Module) {
			defer wg.Done()
			start := time.Now()
			sc.Emit(Progress{Module: m.Name(), State: StateRunning})
			if sc.SkipModules[m.Name()] {
				results[i] = &ModuleResult{Module: m.Name(), Skipped: true, Duration: time.Since(start)}
				sc.Emit(Progress{Module: m.Name(), State: StateDone, Detail: "not applicable in this scope"})
				return
			}
			fs, gaps, err := m.Run(sc)
			kept := fs[:0]
			for _, f := range fs {
				if !sc.Ignored(f.RuleID) {
					kept = append(kept, f)
				}
			}
			finding.Sort(kept)
			res := &ModuleResult{Module: m.Name(), Findings: kept, Gaps: gaps, Err: err, Duration: time.Since(start)}
			results[i] = res
			state := StateDone
			detail := ""
			if err != nil {
				state = StateError
				detail = err.Error()
			}
			sc.Emit(Progress{Module: m.Name(), State: state, Detail: detail})
		}(i, m)
	}
	wg.Wait()
	return results
}
