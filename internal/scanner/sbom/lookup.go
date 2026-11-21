package sbom

import (
	"context"
	"sort"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/scanner"
)

// LookupAdvisories queries OSV for an inventory and returns merged advisories
// keyed by PkgRef. Used by `enki sbom --vulns`.
func LookupAdvisories(ctx context.Context, c Client, pkgs []Pkg) (map[string][]*Advisory, []scanner.CoverageGap) {
	var gaps []scanner.CoverageGap

	var selected []Pkg
	var queries []Query
	for _, p := range pkgs {
		if p.Ecosystem == "" || p.Ecosystem == "OS" {
			continue
		}
		selected = append(selected, p)
		queries = append(queries, Query{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem})
	}
	if len(queries) == 0 {
		return nil, nil
	}

	results, err := c.QueryBatch(ctx, queries)
	if err != nil {
		gaps = append(gaps, scanner.CoverageGap{
			Module: moduleName,
			Reason: "osv.dev unreachable; vulnerability status unknown: " + err.Error(),
		})
		return nil, gaps
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
		return nil, gaps
	}

	seen := map[string]bool{}
	var ids []string
	for _, h := range hits {
		if !seen[h.id] {
			seen[h.id] = true
			ids = append(ids, h.id)
		}
	}
	sort.Strings(ids)
	if len(ids) > maxAdvisories {
		gaps = append(gaps, scanner.CoverageGap{
			Module: moduleName,
			Reason: "advisories omitted due to the per-run limit",
		})
		ids = ids[:maxAdvisories]
	}

	m := &Module{client: c, opts: DefaultOptions()}
	advByID, failed := m.fetchAdvisories(ctx, ids)
	if failed > 0 {
		gaps = append(gaps, scanner.CoverageGap{
			Module: moduleName,
			Reason: "some advisory detail requests failed; results are partial",
		})
	}
	advList := make([]*Advisory, 0, len(advByID))
	for _, a := range advByID {
		advList = append(advList, a)
	}
	m.client.Enrich(ctx, advList)

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

	out := map[string][]*Advisory{}
	seenPerPkg := map[string]map[string]bool{}
	for _, h := range hits {
		k := idToKey[h.id]
		adv := byKey[k]
		if adv == nil {
			continue
		}
		ref := PkgRef(h.pkg)
		if seenPerPkg[ref] == nil {
			seenPerPkg[ref] = map[string]bool{}
		}
		if seenPerPkg[ref][k] {
			continue
		}
		seenPerPkg[ref][k] = true
		out[ref] = append(out[ref], adv)
	}
	for ref := range out {
		sort.Slice(out[ref], func(i, j int) bool {
			return strings.ToUpper(out[ref][i].ID) < strings.ToUpper(out[ref][j].ID)
		})
	}
	return out, gaps
}
