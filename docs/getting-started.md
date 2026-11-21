# Getting started with enki

enki audits the AI stack on a machine or project: exposed inference endpoints,
MCP server configuration, agent permissions, provider secrets, model
artifacts, and dependency vulnerabilities — then offers guarded, reversible
remediation.

Deterministic scanning is free forever and works offline (except OSV advisory
lookups). Everything in this guide is free; the only paid surfaces are hosted
AI triage beyond its free quota, team/org features, premium compliance packs,
and enterprise support. BYOK AI triage is free.

OS-specific install steps: [quickstart.md](quickstart.md).

## Requirements

- A prebuilt binary, or Go 1.27+ to build from source.
- Linux, macOS, or Windows (amd64/arm64).
- No root required for a first scan. Elevated privileges only improve process
  attribution and OS package visibility.
- Network access for CVE lookups (`api.osv.dev`, KEV/EPSS). Offline scans
  still work and report coverage gaps instead of "clean".

## Install

```bash
# from source
go install github.com/yogenpoonudurai/enki/cmd/enki@latest
go install github.com/yogenpoonudurai/enki/cmd/enki-mcp@latest    # MCP server for agents
go install github.com/yogenpoonudurai/enki/cmd/enki-cloud@latest  # hosted triage (optional)

# or from a checkout
make build            # bin/enki, bin/enki-mcp, bin/enki-cloud
```

## First scan

```bash
enki scan                 # human-readable output
enki scan --json          # machine-readable report
enki scan --fail-on none  # report everything, never fail
```

Exit codes: `0` clean/below threshold, `1` findings at or above `--fail-on`
(default `high`), `2` error. This makes `enki scan` usable in scripts:

```bash
enki scan --fail-on critical || echo "critical AI-stack findings present"
```

The interactive dashboard (`enki`, no arguments) scans immediately and offers
navigation, details, and the fix flow.

## Reading findings

Each finding has:

- **Rule ID** (stable, e.g. `AEP-001`, `MCP-001`, `SEC-001`, `SBOM-001`)
- **Severity** — CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Confidence** — how certain the signal is
- **Location** — file, line, or `address:port`
- **Evidence** — redacted proof (no raw secrets)
- **Remediation** — class and action, when available

Severity is advisory-driven for CVEs (CVSS v3, GHSA, KEV, EPSS). Coverage gaps
are listed separately: unknown is never reported as clean.

Full catalogue: [docs/rules.md](rules.md) or `enki rules list`.

## First fix

```bash
enki fix                  # dry run — always start here
```

Actions are classified:

| Class | Example | Behavior |
|---|---|---|
| SAFE | `chmod 0600` on a secret file | applied with `--apply` |
| MODERATE | remove `bypassPermissions` from settings | requires `--include-moderate` and confirmation |
| RISKY | firewall block, kill exposed service | printed as a command; never executed |
| GUIDANCE | upgrade a dependency, pin an MCP package, enable Jupyter auth | printed with a concrete command when known; enki never applies it |

```bash
enki fix --apply                              # safe actions only
enki fix --apply --include-moderate           # prompts before config edits
enki undo                                     # restore the last change (or: undo N)
```

Every applied change is backed up under the state directory, recorded in an
audit log, and can be reverted byte-for-byte. Files under `~/.ssh`, `~/.aws`,
`~/.gnupg`, and gcloud config are never auto-modified.

In the TUI: press `f`, then `1-9` to apply an action, `y` to confirm a config
edit, `a` for all SAFE actions, `u` to undo.

## Dependency scans

All dependencies are scanned by default:

```bash
enki scan --deps all               # npm, PyPI, Go, Cargo, NuGet, Linux OS
enki scan --deps ai                # only the AI catalog (quiet posture view)
enki scan --paths ../service --depth 4
enki scan --include-dev=false      # skip dev dependencies
enki scan --include-global         # include global npm packages
```

Supported formats and distro mapping: [docs/dependencies.md](dependencies.md).

## SBOM export

```bash
enki sbom -o bom.json              # CycloneDX 1.5, no network
enki sbom --vulns -o bom.json     # adds OSV advisories (network)
```

## AI triage (optional; BYOK is free)

The deterministic scanner is the source of truth. Triage only ranks and
explains existing findings; it cannot create findings or execute actions.
Using your own provider key (BYOK) is free forever — there is no hosted compute
and no quota. The hosted service is optional/paid after 3 lifetime runs.

```bash
enki scan --json > report.json

export DEEPSEEK_API_KEY=...        # or ENKI_AI_BASE_URL for a self-hosted model
enki triage report.json

# self-hosted OpenAI-compatible endpoint (vLLM, Ollama, LM Studio, Claude/GPT gateways)
export ENKI_AI_PROVIDER=openai
export ENKI_AI_BASE_URL=http://127.0.0.1:8000/v1
export ENKI_AI_KEY=optional
export ENKI_AI_MODEL=deepseek-v4
enki triage report.json
```

The payload is redacted: no file contents, no secrets, no absolute paths, and
instruction-like content is stripped. It also includes local **system
diagnostics** — OS/distro, service manager, available firewall and package
tools, privileges, container status, limitations, and scan coverage gaps — so
the model can tailor fix steps to this exact machine (for example, "use ufw,
requires sudo" on Ubuntu vs "use pfctl" on macOS). Advisory steps never
execute anything; the deterministic fix engine remains the only thing that
writes to disk.

Inspect the context locally:

```bash
enki doctor            # human-readable diagnostics
enki doctor --json     # the same data enki attaches to triage
```

Triage output includes `rubric_version`, `findings_sent`, and
`omitted`/`omitted_rules` when the report exceeds the payload limit, so you can
tell whether the model saw the whole picture. Cost is labelled metered
(DeepSeek) or unmetered/self-hosted. See [docs/ai-triage.md](ai-triage.md) for
the hosted service, quotas, and billing.

## Agent skills and MCP

```bash
# Claude Code
cp -r skills/enki ~/.claude/skills/enki

# Cursor
mkdir -p .cursor/skills && cp -r skills/enki .cursor/skills/enki
```

Local MCP server (`enki-mcp`, stdio): `enki_scan`, `enki_plan_fix`,
`enki_rules`, `enki_sbom`, `enki_explain_rule`, `enki_triage`.

Remote MCP (hosted triage): point a Streamable HTTP MCP client at
`https://<host>/mcp` with an `Authorization: Bearer enki_...` header.

## CI in one step

```yaml
- uses: actions/checkout@v4
- uses: yogenpoonudurai/enki@v0.4.0
  with:
    args: "--fail-on high --deps ai --modules mcp,secrets,agent-permissions"
```

Uploads `enki.sarif` and the ASCII report as artifacts; fails the job on
findings at/above the threshold. Full examples:
[docs/case-studies/ci-pr-gate.md](case-studies/ci-pr-gate.md).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Dashboard shows the small wordmark, not the artwork | Terminal is shorter than 27 rows; enlarge it, or run `enki banner` |
| "listeners could not be attributed" | Processes owned by other users; rerun with `sudo` for full coverage |
| "no supported OS package manager" | Distro without dpkg/rpm/apk, or unsupported by OSV; inventory-only |
| "OSV has no vulnerability data for …" | Unsupported distro (e.g. Fedora/Arch); OS packages are inventory-only |
| "osv.dev unreachable … unknown" | Network blocked; results are unknown, not clean. Allow `api.osv.dev`, or accept the gap |
| "package.json without a lockfile" | Version ranges cannot be resolved; add a lockfile |
| "go.sum without go.mod" | Selected module versions cannot be determined |
| `triage`: "no AI provider configured" | Set `DEEPSEEK_API_KEY` or `ENKI_AI_BASE_URL`/`ENKI_AI_KEY` |
| `fix` refuses a path | Symlink or sensitive root (`~/.ssh`, `~/.aws`, …); apply manually |
| Exit code 1 in CI unexpectedly | Lower the threshold (`--fail-on critical`) or suppress a reviewed rule with `--ignore-rule` |

Plain output without ANSI: set `CI=1` or `NO_COLOR=1`; the TUI is skipped in
non-interactive shells.

## Privacy and safety

- No telemetry; nothing leaves the machine unless you run `triage` or `sbom --vulns`.
- Secrets are redacted in every output.
- Probes are loopback-only by default; `--probe-remote` is active testing and
  requires authorization.
- Risky remediation is never executed automatically.

## Next steps

- [OS quickstart (macOS/Linux/Windows)](quickstart.md)
- [Rule catalogue](rules.md)
- [Data sources: rules, OSV, KEV, EPSS, caching](data-sources.md)
- [Dependency coverage](dependencies.md)
- [AI triage & hosted service](ai-triage.md)
- [Case studies](case-studies/README.md)
- [Marketing / product strategy](marketing.md)
