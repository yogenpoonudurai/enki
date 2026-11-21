# Data sources: rules, CVEs, and enrichments

This page documents exactly where every finding comes from so you can verify
it. enki has no telemetry and no premium/vendor feeds in the open core.

| Source | Supplies | Refresh | Cache | Offline behavior |
|---|---|---|---|---|
| Built-in rules | All 23 security checks | Ships with the binary (`builtin-1`) | Embedded | Fully functional |
| OSV.dev (`api.osv.dev`) | CVE/advisory IDs, summaries, CVSS vectors, fixed versions, aliases | API queried per scan | 24 h per advisory | Uses cache; otherwise "unknown" gap |
| CISA KEV | Actively exploited CVE flag | API queried when advisories are fetched | 24 h (`kev.json`) | No stale fallback; severity boost is skipped |
| FIRST EPSS | Exploit-prediction score | Queried per scan for CVE aliases | Not cached | Score omitted; no failure |
| CVSS v3 | Numeric severity | Computed locally from the advisory vector | — | Deterministic |

## 1. Security rules (local, not downloaded)

Rules are deterministic code, not a remote list. The catalogue is
`internal/rules/catalog.go` (also rendered by `enki rules list` and documented
in [rules.md](rules.md)).

| Prefix | Module | Code |
|---|---|---|
| AEP | endpoint-exposure | `internal/scanner/aiendpoint` |
| MCP | mcp | `internal/scanner/mcp` |
| SEC | secrets | `internal/scanner/secrets` + `internal/secretlib` |
| AGT | agent-permissions | `internal/scanner/agentcfg` |
| MDL | model-artifacts | `internal/scanner/model` |
| SBOM | sbom | `internal/scanner/sbom` |

Verifiable facts:

- Rule IDs, modules, and declared severities: `enki rules list`,
  `enki rules validate`, `internal/rules/catalog.go`.
- Secret formats: provider token regexes in
  `internal/secretlib/secretlib.go`; matches are redacted in every output.
- Endpoint fingerprints (service names, ports, probe paths) live in
  `internal/scanner/aiendpoint/aiendpoint.go`.
- MCP/agent heuristics (unpinned runners, `bypassPermissions`, auto-run,
  sensitive paths) live in the `mcp` and `agentcfg` packages.

There is no automatic rule update and no remote rule feed. Changing a rule
requires a code change and tests (see `CONTRIBUTING.md`).

## 2. Vulnerability data

### What is sent

Only `name`, `version`, and ecosystem for pinned packages. enki never sends
file contents, secrets, usernames, or hostnames. Requests carry
`User-Agent: enki/0.1` (see `internal/scanner/sbom/osv.go`).

### OSV.dev

- Batch resolve: `POST https://api.osv.dev/v1/querybatch`
  (`queries[].package{name,ecosystem}` + `version`), chunks of **500**.
- Details: `GET https://api.osv.dev/v1/vulns/{id}` — summary, aliases,
  `severity[]` CVSS vectors, `affected[].ranges[].events[].fixed`, references.
- Fetch concurrency: **12** advisory requests; retries (3 attempts) on HTTP
  429/5xx with jittered backoff (`250ms·2^n + ≤250ms`).
- Cache: `$XDG_CACHE_HOME/enki/osv/vulns/<id>.json` (Linux;
  `~/Library/Caches/enki/osv` on macOS, `%LocalAppData%\enki\osv` on Windows),
  TTL **24 h**. Stale cache is used as a fallback when the network fails;
  otherwise the result is reported as a coverage gap, never "clean".
- Advisory sources aggregated by OSV: GitHub Advisory Database (GHSA),
  PyPA/PYSEC, npm, Go vulndb, RustSec, OSS-Fuzz, Debian/Ubuntu/Alpine/Rocky/
  Alma distro feeds.

Verify manually:

```bash
curl -s https://api.osv.dev/v1/querybatch \
  -H 'Content-Type: application/json' \
  -d '{"queries":[{"package":{"name":"torch","ecosystem":"PyPI"},"version":"2.0.1"}]}'

curl -s https://api.osv.dev/v1/vulns/GHSA-53q9-r3pm-6pq6
```

### CISA KEV

- Feed: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Fetched lazily when advisory details are needed.
- Cache: `.../enki/osv/kev.json` with `fetched_at` + CVE list, TTL **24 h**.
- If the feed is unavailable and no fresh cache exists, KEV boosting is simply
  absent (no false positive, no crash).
- An advisory matches KEV by its ID or any CVE alias.

### FIRST EPSS

- Endpoint: `https://api.first.org/data/v1/epss?cve=...` (batches of 100
  CVEs), only for advisories that have CVE aliases.
- Not cached; queried per scan. Failures are ignored and scores are omitted.

### Severity and prioritization

1. **CVSS v3.0/3.1** base score computed locally from the vector
   (`internal/scanner/sbom/severity.go`); score → severity by standard bands.
2. Otherwise the GHSA qualitative rating (`database_specific.severity`).
3. Otherwise **Medium** (distro advisories often have neither).
4. CISA KEV raises the result to at least **HIGH**.
5. EPSS ≥ 0.5 raises one level; KEV + EPSS ≥ 0.9 becomes **CRITICAL**.
6. CVSS v4-only advisories fall back to the GHSA rating (v4 is not computed).

### Deduplication and fixed versions

- Advisories are grouped by **CVE alias**; one merged result per vulnerability
  (highest severity, union of fixed versions, KEV/EPSS max).
- Fixed versions come from OSV `fixed` events; commit hashes are filtered out
  and the highest version-like entry is chosen with a local comparator
  (`internal/scanner/sbom/versions.go`).
- Upgrades are `GUIDANCE`/RISKY: enki prints a package-manager command but
  never runs it.

### Volume limits

| Limit | Value | On exceed |
|---|---|---|
| Packages checked per scan | 10,000 | Coverage gap |
| Advisories resolved per scan | 1,500 | Coverage gap |
| OSV queries per request | 500 | — |
| Advisory detail fetches | 12 concurrent | — |

### Ecosystem mapping

| Inventory source | Ecosystem sent to OSV |
|---|---|
| npm lockfiles | `npm` |
| requirements/pyproject/poetry/uv/Pipfile/pdm | `PyPI` |
| go.mod | `Go` |
| Cargo.lock | `crates.io` |
| packages.lock.json / project.assets.json | `NuGet` |
| dpkg (source package + source version, epoch preserved) | `Debian:<major>`, `Ubuntu:<ver>[:LTS]` |
| rpm (NAME + EVR) | `Rocky Linux:<major>`, `AlmaLinux:<major>` |
| apk (origin + version) | `Alpine:v<major.minor>` |

Unsupported distros (Fedora, Arch, CentOS Stream, RHEL stream-scoped) are
inventory-only with an explicit coverage gap; no CVE claims are made.

## 3. Refresh and cache operations

```bash
# See what would be sent / what was found
enki scan --json | jq '.findings[] | select(.rule_id=="SBOM-001")'

# Inspect the cache
ls -la "${XDG_CACHE_HOME:-$HOME/.cache}/enki/osv/"
jq -r '.fetched_at' "${XDG_CACHE_HOME:-$HOME/.cache}/enki/osv/kev.json"

# Force a refresh (delete the cache; next scan re-fetches)
rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}/enki/osv"
```

Notes:

- Rule packs do **not** refresh; they are compiled in (`builtin-1`).
- Advisory details and KEV are cached for 24 hours; EPSS is queried each run.
- Offline scans still work; missing data appears under "Coverage gaps" in the
  report and in the AI triage payload.

## 4. What enki does not use

No NVD mirror, no Snyk/GHSA enterprise API, no CWE database, no CIS benchmark
content, no commercial threat intelligence. Compliance mappings and premium
signed feeds are delivered by the separate hosted service; they are not part
of the open core.

## 5. Verify against the code

| Behavior | File |
|---|---|
| OSV endpoints, chunking, retries, cache | `internal/scanner/sbom/osv.go` |
| KEV/EPSS enrichment | `internal/scanner/sbom/osv.go` |
| CVSS computation, severity mapping | `internal/scanner/sbom/severity.go` |
| Dedupe, caps, findings | `internal/scanner/sbom/sbom.go` |
| Fixed-version selection, upgrade commands | `internal/scanner/sbom/versions.go` |
| Inventory parsers | `internal/scanner/sbom/{npm,python,golang,rust,nuget,ospkgs_linux}.go` |
| Rule catalogue | `internal/rules/catalog.go` |
