# enki — AI configuration and exposure scanner

enki is a single static binary that audits the AI configuration and exposure
surface of developer laptops and servers: exposed inference endpoints, MCP
server configuration, agent permissions, provider secrets, unsafe model
artifacts, and known vulnerabilities in AI and application dependencies. It
finds issues and can apply guarded, reversible fixes.

It is deliberately narrower than an AI security platform. It reads
configuration, process, file, and package metadata; it does not instrument
runtime behavior, inspect model weights, or prove that a risk is exploitable.

- Pure Go, no runtime dependencies: macOS · Linux · Windows (amd64/arm64)
- Deterministic scans; no account, telemetry, or LLM required
- Fixes are dry-run by default, backed up, and reversible with `enki undo`
- Reports: interactive TUI, plain text, JSON, SARIF 2.1.0, OCSF, CycloneDX 1.5

![enki demo](demo/demo.gif)

## Install

Verified release binaries are the recommended path; they have no runtime
dependencies. Checksum and cosign verification steps for macOS, Linux, and
Windows are in [docs/quickstart.md](docs/quickstart.md).

```sh
# from source, if you prefer (Go 1.27.0+)
go install github.com/yogenpoonudurai/enki/cmd/enki@latest
enki version
```

With `GOTOOLCHAIN=auto` (the default), an older `go` command can fetch the
required 1.27.0 toolchain automatically.

## 60-second golden path

Run from the project or machine you want to check:

```sh
enki scan --json > enki-report.json   # deterministic findings
enki report enki-report.json          # readable ASCII report
enki fix                              # preview the fix plan
enki fix --apply                      # apply SAFE fixes
enki undo                             # restore the last change
```

1. `scan` checks AI endpoints, MCP/agent configuration, secrets, model files,
   and dependency vulnerabilities.
2. `report` renders a readable report from the saved JSON artifact.
3. `fix` is a dry run; `fix --apply` applies only SAFE actions such as file
   permissions. Config edits require `--include-moderate`.
4. Every applied change is backed up and can be restored byte-for-byte.

Exit codes: `0` clean or below threshold, `1` findings at/above `--fail-on`
(default `high`), `2` error. Exit `1` is the CI gate, not a crash.

| Also useful | Purpose |
|---|---|
| `enki` | interactive dashboard on a terminal; plain scan when piped |
| `enki scan --sarif --fail-on high > enki.sarif` | SARIF for code scanning |
| `enki scan --deps all --os-packages` | broad dependency and OS package inventory |
| `enki sbom -o bom.json` | CycloneDX 1.5 SBOM |
| `enki doctor` | local system context used for tailored advice |
| `enki rules list` | built-in rule catalog |
| `enki triage enki-report.json` | optional AI ranking (BYOK) |

## What it checks

| Module | Examples |
|---|---|
| endpoint-exposure | Ollama on `0.0.0.0:11434`, permissive CORS, Gradio `--share`, tokenless Jupyter |
| mcp | unpinned `npx` servers, plaintext remote URLs, inline secrets, broad filesystem roots |
| secrets | provider keys in `.env`/config/history, permissive modes, Hugging Face tokens |
| agent-permissions | `bypassPermissions`, `Bash(*)`, auto-run, `~/.ssh` grants |
| model-artifacts | pickle/`torch.load`, `trust_remote_code`, weights fetched over HTTP |
| sbom | CVEs across npm, PyPI, Go, Cargo, NuGet, and Linux OS packages; AI catalog by default, `--deps all` for every package, prioritized with CISA KEV and EPSS |

23 rules across six modules. Full rule and data-source references:
[docs/rules.md](docs/rules.md), [docs/detection-benchmark.md](docs/detection-benchmark.md)
(positive/negative/adversarial fixtures per rule), and
[docs/data-sources.md](docs/data-sources.md).

## Scope and non-goals

- **Configuration and exposure, not runtime detection.** enki does not hook
  model calls, inspect prompts, or watch agent behavior at runtime.
- **No model inspection.** It never loads weights or evaluates a model; it
  reports file formats and code patterns, not payload behavior.
- **Not a full SCA or container scanner.** Dependency checks are limited to
  pinned versions found in discovered manifests and, by default, the AI
  package catalog. Use Trivy, Grype, or OSV-Scanner for broad CVE coverage.
- **No exploitation or network scanning.** Endpoint probes are read-only,
  loopback-first, and never send exploit payloads or scan public addresses.
- **Coverage is reported, not assumed.** Permissions, unsupported platforms,
  unresolved versions, and skipped scopes surface as coverage gaps; a clean
  result never means "everything was visible".
Endpoint probes are read-only and loopback-only by default; `--probe-remote`
extends them to RFC1918 listeners you own.

## Safe by design

- Secrets are redacted by default; enki never loads model files.
- `fix` is dry-run by default. SAFE actions apply with `--apply`; MODERATE
  config edits require `--include-moderate` and confirmation; RISKY actions
  (firewall) are printed, never executed.
- Every change is logged and backed up. Files under `~/.ssh`, `~/.aws`,
  `~/.gnupg`, and `~/.config/gcloud` are never auto-modified.
- AI triage is optional and consent-gated; the model never executes actions.

Details: [docs/ethics.md](docs/ethics.md).

## CI

Composite GitHub Action (uploads SARIF and the ASCII report, fails on findings
at/above the threshold):

```yaml
- uses: actions/checkout@v7
- uses: yogenpoonudurai/enki@v0.5.0   # use the current release tag
  with:
    args: "--scope project --deps ai --fail-on high"
```

Or run the CLI directly:

```sh
enki scan --scope project --deps ai --sarif --fail-on high > enki.sarif
```

`--scope project` checks the repository only. Runner-side scans cannot see a
developer laptop's listeners, user-level MCP servers, or shell history; run
`enki scan --scope host` locally for those. See
[docs/ci-quickstart.md](docs/ci-quickstart.md#what-ci-can-and-cannot-see).

PR-gate walkthrough: [docs/ci-quickstart.md](docs/ci-quickstart.md).

## Optional surfaces

- **AI triage (BYOK, free):** `enki triage enki-report.json`. Works with
  DeepSeek, OpenAI-compatible gateways, or a local model:
  `ENKI_AI_PROVIDER=ollama ENKI_AI_MODEL=qwen2.5:1.5b enki triage enki-report.json`.
  See [docs/ai-triage.md](docs/ai-triage.md).
- **Agent Skill and local MCP:** [skills/enki/SKILL.md](skills/enki/SKILL.md)
  and `enki-mcp` (stdio tools for Claude Code, Cursor, and other agents).
- **Hosted triage (paid, optional):** the open-source CLI includes the client
  for the separate hosted service: `enki triage --hosted --consent` and
  `enki account`. Configure `ENKI_CLOUD_URL` and `ENKI_CLOUD_TOKEN`. Details:
  [docs/premium.md](docs/premium.md).

All detection, local remediations, SBOM export, and BYOK triage are free and
open source. Local detection is never gated or metered. The hosted service
implementation, billing, and premium feeds are not part of this repository.

## Documentation

- [Quickstart for macOS, Linux, and Windows](docs/quickstart.md)
- [Getting started](docs/getting-started.md)
- [Rule catalog](docs/rules.md) · [Dependency coverage](docs/dependencies.md)
- [AI triage and redaction](docs/ai-triage.md)
- [CI quickstart](docs/ci-quickstart.md) · [Release verification](docs/release.md)
- [Detection benchmarks](docs/detection-benchmark.md) · [Real-world benchmark](docs/benchmark-real-world.md) · [Held-out live-OSV benchmark](docs/benchmark-heldout.md)
- [Open-core boundary](docs/open-core.md)
- [Case studies](docs/case-studies/laptop.md): laptop, GPU server, CI PR gate

## Development

Container-first; tests and smoke runs do not touch the host:

```sh
make test-container     # unit tests in the dev container
make smoke-container    # BYOK end-to-end with a local fake provider
make verify-docs-container  # execute the documented CLI commands in a container
make cross              # CGO-free builds for 3 OSes × 2 architectures
```

Requires Go 1.27.0+ for local builds. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

The core is Apache-2.0 and fully functional offline. The hosted service,
premium feeds, and the enki name and logo are separate: the service code is
proprietary and lives outside this repository, and the trademarks are covered
by [TRADEMARK.md](TRADEMARK.md). See the
[open-core boundary](docs/open-core.md) for what is public and what ships in
releases. Contribution rules:
[CONTRIBUTING.md](CONTRIBUTING.md) (DCO); vulnerability handling:
[SECURITY.md](SECURITY.md).
