# Launch kit

Ready-to-paste assets for the OSS launch. Strategy: `docs/marketing.md`.

## Demo

```bash
./demo/run.sh
```

Starts a fake Ollama-like server on `0.0.0.0:11434` (loopback only, killed on
exit) and shows enki reporting a CRITICAL exposure. Record 60 seconds of this
plus `enki` → `f` → `1` → `u` for the launch GIF.

## Show HN

**Title**
Show HN: enki – audit the AI stack running on your laptop

**Body**
Your laptop and servers now run an AI stack: local models, MCP servers, agent
tooling, a dozen SDKs. enki is a single-binary scanner for that layer.

It finds:
- Ollama/LM Studio/ComfyUI/Jupyter exposed to the network
- unpinned MCP server packages and inline provider keys
- agents running with bypassPermissions or unrestricted shell
- pickle weights, trust_remote_code, HTTP model downloads
- CVEs across npm, PyPI, Go, Cargo, NuGet, and Linux OS packages

It does deterministic scanning, not LLM guessing. Safe fixes apply with one
flag; config edits are backed up and reversible with `enki undo`. Outputs:
TUI, SARIF, OCSF, CycloneDX.

Apache-2.0, no telemetry: https://github.com/yogenpoonudurai/enki

## X / social

```
Your laptop runs an AI stack you've never audited.

enki — one binary.
Exposed Ollama. Unpinned MCP. Inline keys. bypassPermissions. Pickle weights.
CVEs across npm/PyPI/Go/Cargo/NuGet/OS.

Guarded fixes with undo. SARIF/OCSF/CycloneDX. Apache-2.0.
```

## Directory blurbs

Short (≤200 chars)
> Single-binary AI security posture scanner: exposed inference endpoints, MCP
> supply-chain risk, agent permissions, secrets, model artifacts, dependency
> CVEs. Guarded, reversible fixes. TUI + SARIF/OCSF/CycloneDX. Apache-2.0.

Long
> enki audits the AI stack on laptops and servers: it finds inference services
> bound to the network, risky MCP server configuration, agent permission
> sprawl, provider secrets, unsafe model artifacts, and dependency
> vulnerabilities across npm, PyPI, Go, Cargo, NuGet, and Linux packages. It
> applies safe remediations with backups and byte-identical undo, and exports
> SARIF, OCSF, and CycloneDX. It also ships as an Agent Skill and MCP server so
> coding agents can run it directly.

Channels: official MCP registry (preview), mcp.so, Smithery, Glama, Claude
Code / Cursor skill directories, awesome-ai-security lists.

## Pricing page copy

- **OSS — free forever.** Full scanner, TUI, skills, local MCP, SARIF/OCSF,
  CycloneDX, fix/undo.
- **Free hosted — 3 AI triages.** Consent-gated, redacted payload, 24 h
  retention.
- **Pro — $19/mo.** 300 triages, CI history, hosted MCP endpoint.
- **Team — $39/seat/mo.** 1,000 pooled credits, SSO, policy, 90-day history.
- **Enterprise — custom.** Self-hosted model gateway, DPA, premium signed
  feeds, support.

Boundary line: detection is free forever; intelligence, collaboration, and
compliance are paid.

## Pre-launch checklist

- [x] Apache-2.0 license
- [x] SECURITY.md and CONTRIBUTING.md
- [x] Deterministic scanner, TUI, SARIF/OCSF/CycloneDX
- [x] Guarded fix/undo with tests
- [x] Agent Skill + local MCP server
- [x] Hosted triage service with MCP Streamable HTTP
- [x] GitHub Action + repo CI
- [x] Reproducible demo script
- [x] Demo GIF, MP4, 1080p/60fps MP4, poster, and title cards (`demo/render_gif.py`)
- [x] Three case-study posts (laptop, GPU server, CI gate)
- [x] Getting-started guide (`docs/getting-started.md`)
- [x] OS-specific quickstart (`docs/quickstart.md`)
- [x] Signed releases configured (cosign keyless in `.github/workflows/release.yml`)
- [x] MCP registry metadata prepared (`server.json`, `docs/registry-submission.md`)
- [x] Waitlist landing page and API (`site/`, `POST /v1/waitlist`)
- [ ] Push the `v0.4.0` tag and verify the signed release
- [ ] Submit the server to MCP registries (needs accounts)
- [ ] Deploy the waitlist site (`site/README.md`)

## Launch-day posts

1. Show HN (above).
2. r/netsec + r/ai_security: focus on the exposed-Ollama demo.
3. X thread: five AI-stack misconfigurations, one screenshot each.
4. LinkedIn: the “plumbing of AI” angle for engineering managers.
5. AI newsletters / MCP community: the skill + MCP angle.
