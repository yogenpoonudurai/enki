# enki marketing strategy

Audience: the maintainers. This is the working strategy for taking enki from an
open-source scanner to a sustainable open-core product. It is intentionally
opinionated; adjust pricing after the beta.

## Bottom line

1. **Open source first.** Security tooling is adopted on inspectability and
   reproducibility. An Apache-2.0 core is a distribution requirement, not a
   concession.
2. **Free forever locally.** Never meter or gate `enki scan`, the TUI, skills,
   the local MCP server, or fix/undo. Charging for detection invites forks and
   destroys developer trust.
3. **Monetize intelligence, collaboration, and compliance** — hosted AI
   triage, team workflow, premium rule/compliance content, enterprise
   self-host + SLA.
4. **CI/CD is the growth engine, not the revenue engine.** The CLI/Action wins
   repos; team features and self-host win contracts.

## The opening

Every developer laptop and GPU server now runs an AI stack: local inference
servers, MCP servers, agent tooling, model downloads. Existing tools do not
audit that layer.

| Tool | Covers | Leaves open |
|---|---|---|
| Trivy / Grype | Containers, OS packages, CVEs | AI endpoints, MCP configs, agent permissions |
| Snyk / Socket | Dependency and PR security | Local AI-stack posture, model artifacts |
| Wiz / Aikido | Cloud/ASPM | Laptop-first CLI, reversible local fixes |
| CodeRabbit | AI code review | AI runtime/exposure posture |

enki's wedge: exposed inference endpoints, MCP supply chain, agent permission
sprawl, secrets and model artifacts, dependency CVEs — with deterministic,
reversible remediation. Buyer: AI-native startup / platform team. User:
individual developer. That mismatch shapes the funnel: developers install,
managers buy.

## Strategy: OSS → open-core freemium

| Stage | Timing | Goal | Free | Paid |
|---|---|---|---|---|
| 1. OSS launch | now | credibility, installs, contributors | full local scanner, TUI, SARIF/OCSF/CycloneDX, skills, local MCP, fix/undo | — |
| 2. Hosted beta | +1–2 months | demand validation, list building | 3 lifetime AI triages | — |
| 3. Pro | +3 months | first revenue | above | $19/mo: 300 triages, CI history, hosted MCP |
| 4. Team | +5–6 months | expansion | above | $39/seat/mo: SSO, policy, 1,000 pooled credits, 90-day history |
| 5. Enterprise | +9–12 months | contract revenue | above | self-host gateway, DPA, SLA, premium feeds (custom) |

**Published boundary:** detection is free forever; intelligence, collaboration,
and compliance are paid. Keep the hosted store, history, team policy, model
gateway, and premium rule feeds proprietary; keep every detection capability
in the open core.

Do not copy CodeRabbit literally: it gates hosted review capacity and features,
not its engine. enki's analogue is hosted triage credits, not `enki scan`.

## Why teams put it in CI/CD

- **MCP / agent config gate** — fail PRs adding unpinned `npx -y` servers,
  inline provider keys, broad filesystem grants, or `bypassPermissions`.
- **Secret gate** — provider keys in `.env`, configs, or history.
- **AI exposure gate** — nightly scan of GPU/CI servers for Ollama, Jupyter,
  ComfyUI, LM Studio bound to non-loopback addresses.
- **SBOM / CVE gate** — SARIF into code scanning, KEV/EPSS prioritization.
- **Compliance artifact** — CycloneDX SBOM plus ASCII report as evidence.

Why enki fits CI: one static binary, no account, no telemetry, deterministic
exit codes, `--fail-on`, offline-capable, no LLM in the gate, SARIF output.

Honest positioning: complement Trivy/Snyk; do not claim to replace them.

## Monetization

| Model | Price | Rationale | Risk |
|---|---|---|---|
| Hosted AI triage | $19/mo = 300 credits; overflow $0.02 or BYOK | High margin (~$0.0035–0.017 COGS per triage), natural free→paid trigger | Commodity LLM wrappers; mitigate with rubric quality + trust model |
| Premium rules & compliance | $99–499/org/mo | Content, not code; CIS/NIST/ISO/SOC2 mappings, curated AI rules | Requires a contribution pipeline |
| Team workflow | $29–49/seat/mo | Dashboard, history, policy, SSO, audit export | Buyers want seats only once teams adopt |
| Enterprise self-host | $10k–50k/yr | DPA, region-pinned inference, support; DeepSeek PRC terms make this necessary | Sales cycle |

Never: per-scan charges on the local CLI, ads, crippled free tiers.

**Unit economics:** 50-finding triage ≈ 15k input / 2k output tokens —
$0.0035 off-peak (flash, no thinking) to ~$0.017 peak with thinking. Budget
$0.01–0.02; one call per report; byte-stable rubric for cache pricing.

## 90-day go-to-market

**Weeks 1–4 — make the OSS launch undeniable**
- [x] Apache-2.0 LICENSE
- [x] Deterministic scanner, TUI, SARIF/OCSF/CycloneDX
- [x] Guarded fix/undo
- [x] Agent Skill + local MCP server + plugin manifests
- [x] GitHub Action + CI
- [x] SECURITY.md and CONTRIBUTING.md
- [ ] 60-second demo (GIF/video): exposed Ollama → CRITICAL → fix → undo
- [ ] Three case studies (local dev laptop, GPU server, CI PR gate)
- [ ] Signed reproducible releases (goreleaser + signing key)
- [ ] Publish MCP server metadata to the official registry (preview),
      mcp.so, Smithery, Glama

**Weeks 5–8 — launch**
- Show HN: “Your laptop runs an AI stack you’ve never audited.”
- r/netsec, AI engineering newsletters, MCP and Claude/Cursor communities
- Content flywheel: “10 MCP misconfigurations”, “How an exposed Ollama
  becomes data exfiltration”, “Auditing agent permissions”
- Targets: 500–1,500 GitHub stars, 3k–10k installs, 100+ CI repos

**Weeks 9–12 — hosted beta → first dollars**
- 3 lifetime triages, waitlist, consent screen, BYOK
- 10 design partners; Stripe checkout live
- Convert repos already using the Action into Team conversations
- Launch Pro when credit consumption and retention justify it

## Metrics

Leading: weekly active machines, CI repos, scan→fix ratio, hosted signups,
free→paid conversion, credits per account, 14-day return rate. Lagging: MRR,
seats, annual contracts. GitHub stars are vanity.

## Risks and moats

| Risk | Mitigation |
|---|---|
| Snyk/Trivy add AI-config rules | Ship the MCP/agent checks first; keep rule quality high |
| False positives destroy trust | Confidence levels, `--ignore-rule`, conservative CRITICAL criteria |
| DeepSeek data-residency objections | BYOK, self-host gateway, consent screen, no raw files |
| Forking the OSS core | Hosted value (history, collaboration, gateway, content) is not in the repo |
| Maintainer burn | Rule contribution format + review process (CONTRIBUTING.md) |
| Liability | “Not an audit” terms, deterministic exit codes, no autonomous fixes |

Moats, in order: trust/safety model, rule quality for the agent era,
agent-native distribution (skills/MCP), interop formats, and the paid
workflow layer.

## Repo assets supporting this strategy

`action.yml` · `skills/enki` · `.claude-plugin` · `.mcp.json` ·
`cmd/enki-mcp` · `cmd/enki-cloud` · `docs/ai-triage.md` · `Dockerfile` ·
`docker-compose.yml` · `SECURITY.md` · `CONTRIBUTING.md`

## Not doing (for now)

- Paywalling any local scan capability
- A hosted dashboard before beta demand is measured
- Enterprise features before Team revenue exists
- Training a proprietary model
