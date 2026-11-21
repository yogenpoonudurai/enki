// Package sbom discovers dependencies across package managers and checks them
// against OSV advisories, prioritized with CISA KEV and EPSS.
package sbom

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

const moduleName = "sbom"

const (
	maxPackages   = 10000
	maxAdvisories = 1500
	fetchWorkers  = 12
)

type advisoryHit struct {
	pkg Pkg
	id  string
}

type Module struct {
	opts   Options
	client Client
}

func New(opts Options) *Module { return &Module{opts: opts.normalized(), client: newClient()} }

// NewWithClient builds a module with an injected client (tests).
func NewWithClient(opts Options, c Client) *Module {
	return &Module{opts: opts.normalized(), client: c}
}

func (m *Module) Name() string { return moduleName }

func (m *Module) Description() string {
	return "Checks pinned dependencies (npm, PyPI, Go, Cargo, NuGet, OS packages) against OSV advisories"
}

func (m *Module) Run(sc *scanner.Context) ([]finding.Finding, []scanner.CoverageGap, error) {
	pkgs, gaps := Discover(sc.Ctx, m.opts, sc.WorkingDir)

	selected := make([]Pkg, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Ecosystem == "" || p.Ecosystem == "OS" {
			continue // inventory-only (unsupported distro)
		}
		if m.opts.Deps == "ai" && !isAIPackage(p.Ecosystem, p.Name) {
			continue
		}
		selected = append(selected, p)
	}
	if len(selected) == 0 {
		return nil, gaps, nil
	}
	if len(selected) > maxPackages {
		gaps = append(gaps, scanner.CoverageGap{
			Module: moduleName,
			Reason: fmt.Sprintf("%d packages omitted (limit %d per scan)", len(selected)-maxPackages, maxPackages),
		})
		selected = selected[:maxPackages]
	}

	sc.Emit(scanner.Progress{Module: moduleName, State: scanner.StateRunning, Detail: fmt.Sprintf("%d packages discovered", len(selected))})

	queries := make([]Query, len(selected))
	for i, p := range selected {
		queries[i] = Query{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem}
	}
	results, err := m.client.QueryBatch(sc.Ctx, queries)
	if err != nil {
		gaps = append(gaps, scanner.CoverageGap{
			Module: moduleName,
			Reason: "osv.dev unreachable; dependency vulnerability status is unknown (not clean): " + err.Error(),
		})
		return nil, gaps, nil
	}

	var hits []advisoryHit
	for i, ids := range results {
		if i >= len(selected) {
			break
		}
		for _, id := range ids {
			hits = append(hits, advisoryHit{pkg: selected[i], id: id})
		}
	}
	if len(hits) == 0 {
		sc.Emit(scanner.Progress{Module: moduleName, State: scanner.StateRunning,
			Detail: fmt.Sprintf("%d packages · no advisories", len(selected))})
		return nil, gaps, nil
	}

	uniqueIDs, allowed := m.advisoryIDSet(hits, &gaps)
	advByID, failed := m.fetchAdvisories(sc.Ctx, uniqueIDs)
	if failed > 0 {
		gaps = append(gaps, scanner.CoverageGap{
			Module: moduleName,
			Reason: fmt.Sprintf("%d advisory detail request(s) failed; those CVEs are unreported", failed),
		})
	}
	advList := make([]*Advisory, 0, len(advByID))
	for _, a := range advByID {
		advList = append(advList, a)
	}
	m.client.Enrich(sc.Ctx, advList)

	// The same vulnerability is published under several IDs (GHSA, PYSEC,
	// CVE...). Group by CVE alias and keep one merged advisory per group.
	byKey := map[string]*Advisory{}
	idToKey := map[string]string{}
	for _, a := range advList {
		k := groupKey(a)
		idToKey[a.ID] = k
		if rep, ok := byKey[k]; ok {
			mergeAdvisory(rep, a)
			continue
		}
		byKey[k] = a
	}

	var out []finding.Finding
	seen := map[string]bool{}
	pkgFixed := map[string]string{}
	for _, h := range hits {
		if !allowed[h.id] {
			continue
		}
		adv := byKey[idToKey[h.id]]
		if adv == nil {
			continue
		}
		if best := maxFixedVersion(adv.Fixed); best != "" {
			key := packageVersionKey(h.pkg)
			if compareVersions(best, pkgFixed[key]) > 0 {
				pkgFixed[key] = best
			}
		}
	}
	for _, h := range hits {
		if !allowed[h.id] {
			continue
		}
		adv := byKey[idToKey[h.id]]
		if adv == nil {
			continue
		}
		key := h.pkg.Ecosystem + "|" + strings.ToLower(h.pkg.Name) + "@" + h.pkg.Version + "|" + idToKey[h.id]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, advisoryFinding(h.pkg, adv, pkgFixed[packageVersionKey(h.pkg)]))
	}
	sc.Emit(scanner.Progress{Module: moduleName, State: scanner.StateRunning,
		Detail: fmt.Sprintf("%d packages · %d advisories", len(selected), len(byKey))})

	finding.Sort(out)
	return out, gaps, nil
}

// advisoryIDSet deduplicates advisory IDs, applies the volume cap and reports
// truncation explicitly.
func (m *Module) advisoryIDSet(hits []advisoryHit, gaps *[]scanner.CoverageGap) ([]string, map[string]bool) {
	seen := map[string]bool{}
	var ids []string
	for _, h := range hits {
		if !seen[h.id] {
			seen[h.id] = true
			ids = append(ids, h.id)
		}
	}
	sort.Strings(ids)
	allowed := make(map[string]bool, len(ids))
	limit := len(ids)
	if limit > maxAdvisories {
		*gaps = append(*gaps, scanner.CoverageGap{
			Module: moduleName,
			Reason: fmt.Sprintf("%d advisories omitted (limit %d per scan)", len(ids)-maxAdvisories, maxAdvisories),
		})
		limit = maxAdvisories
	}
	for _, id := range ids[:limit] {
		allowed[id] = true
	}
	return ids[:limit], allowed
}

func (m *Module) fetchAdvisories(ctx context.Context, ids []string) (map[string]*Advisory, int) {
	out := make(map[string]*Advisory, len(ids))
	var mu sync.Mutex
	var wg sync.WaitGroup
	failed := 0

	sem := make(chan struct{}, fetchWorkers)
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			adv, err := m.client.Advisory(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				return
			}
			out[id] = adv
		}(id)
	}
	wg.Wait()
	return out, failed
}

func groupKey(a *Advisory) string {
	for _, alias := range a.Aliases {
		if strings.HasPrefix(strings.ToUpper(alias), "CVE-") {
			return strings.ToUpper(alias)
		}
	}
	if strings.HasPrefix(strings.ToUpper(a.ID), "CVE-") {
		return strings.ToUpper(a.ID)
	}
	return a.ID
}

func mergeAdvisory(dst, src *Advisory) {
	if src.Severity.Order() > dst.Severity.Order() {
		dst.Severity = src.Severity
	}
	dst.KEV = dst.KEV || src.KEV
	if src.EPSS > dst.EPSS {
		dst.EPSS = src.EPSS
	}
	if dst.Summary == "" {
		dst.Summary = src.Summary
	}
	dst.Aliases = appendUnique(dst.Aliases, src.ID)
	for _, alias := range src.Aliases {
		dst.Aliases = appendUnique(dst.Aliases, alias)
	}
	for _, f := range src.Fixed {
		dst.Fixed = appendUnique(dst.Fixed, f)
	}
}

func appendUnique(list []string, v string) []string {
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
}

// printableFixed keeps version-like fixed entries and drops commit hashes.
func printableFixed(fixed []string) []string {
	var out []string
	for _, f := range fixed {
		if f != "" && f[0] >= '0' && f[0] <= '9' {
			out = appendUnique(out, f)
		}
	}
	return out
}

func finalSeverity(a *Advisory) finding.Severity {
	sev := a.Severity
	if sev == "" {
		sev = finding.SeverityMedium
	}
	if a.KEV && sev.Order() < finding.SeverityHigh.Order() {
		sev = finding.SeverityHigh
	}
	if a.EPSS >= 0.5 {
		sev = bump(sev)
	}
	if a.KEV && a.EPSS >= 0.9 && sev.Order() < finding.SeverityCritical.Order() {
		sev = finding.SeverityCritical
	}
	return sev
}

func bump(s finding.Severity) finding.Severity {
	switch s {
	case finding.SeverityInfo:
		return finding.SeverityLow
	case finding.SeverityLow:
		return finding.SeverityMedium
	case finding.SeverityMedium:
		return finding.SeverityHigh
	case finding.SeverityHigh:
		return finding.SeverityCritical
	}
	return s
}

func advisoryFinding(pkg Pkg, a *Advisory, bestFixed string) finding.Finding {
	sev := finalSeverity(a)
	fixed := printableFixed(a.Fixed)
	title := fmt.Sprintf("%s %s is affected by %s", pkg.Name, pkg.Version, a.ID)
	desc := a.Summary
	if desc == "" {
		desc = truncate(a.Details, 300)
	}
	if desc == "" {
		desc = "A known vulnerability affects this dependency version."
	}
	f := finding.New("SBOM-001", moduleName, title, desc, sev, finding.ConfidenceHigh, finding.Location{Path: pkg.Source})

	ev := []string{fmt.Sprintf("%s %s (%s)", pkg.Name, pkg.Version, pkg.Ecosystem), "advisory: " + a.ID}
	if len(a.Aliases) > 0 {
		ev = append(ev, "aliases: "+strings.Join(a.Aliases, ", "))
	}
	if bestFixed != "" {
		ev = append(ev, "fixed: "+bestFixed)
	} else if len(fixed) > 0 {
		ev = append(ev, "fixed: "+strings.Join(fixed, ", "))
	}
	if a.KEV {
		ev = append(ev, "CISA KEV")
	}
	if a.CVSS > 0 {
		ev = append(ev, fmt.Sprintf("CVSS %.1f", a.CVSS))
	}
	if a.EPSS > 0 {
		ev = append(ev, fmt.Sprintf("EPSS %.2f", a.EPSS))
	}
	f.Evidence = strings.Join(ev, " · ")
	f.References = a.Refs

	rm := &finding.Remediation{
		Class:    finding.ActionRisky,
		Summary:  fmt.Sprintf("Upgrade %s to a fixed release", pkg.Name),
		Guidance: "Review the advisory and upgrade, or apply the documented mitigation. Re-run enki after upgrading.",
	}
	if bestFixed != "" {
		rm.Summary = fmt.Sprintf("Upgrade %s to %s or later", pkg.Name, bestFixed)
		rm.Params = map[string]string{
			"path": pkg.Source, "package": pkg.Name,
			"current": pkg.Version, "fixed": bestFixed,
		}
		if manager, command, ok := upgradeCommand(pkg, bestFixed); ok {
			rm.Params["manager"] = manager
			rm.Command = command
			rm.Guidance = "Run the command with the project's package manager, review lockfile changes, then re-run enki."
		} else {
			rm.Guidance = "Upgrade via the platform package manager, review the changelog, then re-run enki."
		}
	}
	f.Remediation = rm
	f.Tags = []string{"sbom", "cve", "pkg:" + pkg.Name + "@" + pkg.Version, "advisory:" + a.ID}
	if pkg.Dev {
		f.Tags = append(f.Tags, "dev")
	}
	if pkg.Optional {
		f.Tags = append(f.Tags, "optional")
	}
	if a.KEV {
		f.Tags = append(f.Tags, "kev")
	}
	return f
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
