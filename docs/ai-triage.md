# AI triage: skills, MCP, and the hosted service

enki keeps a hard boundary between deterministic scanning and AI assistance.

- **Deterministic (always free, offline):** scanning, finding generation,
  severity, remediation planning, fix/undo, SARIF/OCSF/CycloneDX.
- **AI (optional, consent-gated):** ranking and explanation of existing
  findings only. The model cannot create findings, choose arbitrary commands,
  or execute anything.

BYOK triage (your provider key, called directly) is **free forever**. The
hosted service is the optional paid surface: 3 lifetime free triages, then
Pro/Team credits. It also provides the remote MCP endpoint and hosted
retention.

## Agent skills and MCP

- Skill: `skills/enki/SKILL.md` (Agent Skills standard, works in Claude Code and
  Cursor).
- MCP server: `cmd/enki-mcp` (stdio), tools: `enki_scan`, `enki_plan_fix`,
  `enki_rules`, `enki_sbom`, `enki_explain_rule`, `enki_triage`.
- Plugin manifests: `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `.mcp.json`.

Install for Claude Code (manual):

```bash
cp -r skills/enki ~/.claude/skills/enki
# or add this repository as a plugin marketplace:
# /plugin marketplace add <path-or-repo>
# /plugin install enki@enki-marketplace
```

Install for Cursor:

```bash
mkdir -p .cursor/skills && cp -r skills/enki .cursor/skills/enki
```

Point your MCP client at the binary:

```json
{"mcpServers": {"enki": {"command": "enki-mcp", "args": []}}}
```

### Remote MCP (hosted triage)

`enki-cloud` also serves the MCP **Streamable HTTP** transport at `/mcp`:

```json
{
  "mcpServers": {
    "enki-cloud": {
      "type": "http",
      "url": "https://cloud.example.com/mcp",
      "headers": {"Authorization": "Bearer enki_..."}
    }
  }
}
```

Remote tools: `enki_triage` (consent + quota, same policy as `/v1/triage`),
`enki_plan_fix`, `enki_rules`, `enki_explain_rule`, `enki_usage`. Scanning is
intentionally not exposed remotely — the hosted service cannot see the
caller's machine. Add `X-Enki-Provider-Key` to the connection headers to use
BYOK without consuming credits. The endpoint is stateless, requires the bearer
token on every request, and returns JSON responses.

## Local triage (BYO model)

```bash
enki scan --json > report.json

# DeepSeek
export DEEPSEEK_API_KEY=...
enki triage report.json

# Self-hosted OpenAI-compatible endpoint (vLLM serving DeepSeek V4 MIT weights,
# Ollama, LM Studio, or any /v1 server)
export ENKI_AI_PROVIDER=openai
export ENKI_AI_BASE_URL=http://127.0.0.1:8000/v1
export ENKI_AI_KEY=optional
export ENKI_AI_MODEL=deepseek-v4
enki triage report.json

# Local Ollama, no key required
ollama pull qwen2.5:1.5b
export ENKI_AI_PROVIDER=ollama
export ENKI_AI_MODEL=qwen2.5:1.5b
enki triage report.json
```

`make smoke-local-container` runs this path against Ollama inside the dev
container. On CPU, `qwen2.5:1.5b` is a good baseline: concise, four-of-four
coverage, and canonical `manual` actions. `qwen2.5:3b` gives fuller rationale
and ecosystem-specific steps (npm for JS, chmod for permissions) but may
propose non-canonical actions, which enki marks unverified. Small local models
follow the schema more loosely; `action_verified` reflects that.

`enki triage` prints validated JSON: a summary, ranked items with `priority`,
`why`, a recommended action, and `action_verified`. An action is verified only
when it matches one of enki's deterministic remediation actions (ignoring case)
or is the literal `manual`; the model never invents executable steps.
`--show-payload` prints the redacted payload sent to the provider.

On a terminal, triage renders a readable fix plan instead: ranked findings,
enki's authoritative remediation (an exact `chmod` command when enki can apply
it), AI-suggested steps, and an explicit `Action:` line — `verified enki
action`, `manual review`, or `NOT VERIFIED` (follow those steps manually; enki
will not run them). JSON remains the default when piped, so scripts and the
smoke tests are unaffected. Force either form with `--format text` or
`--format json`; `--show-payload` always uses JSON.

Apply verified fixes without copying commands:

```bash
enki triage --apply report.json                    # choose 1,3 / all / none
enki triage --apply --only SEC-001 report.json     # apply named rules only
enki triage --apply --yes report.json              # all, non-interactive
enki undo                                          # restore permissions/edits
```

With `--apply`, enki lists the verified fixes and asks which to run; Enter
applies none, `all` applies every one, and `1,3` or `1-3` selects individual
entries. `--only` selects by rule ID for scripts, and `--yes` explicitly
applies all without prompting.

`--apply` runs only enki's deterministic remediation for findings where the
model selected that exact action and validation marked it verified. The model
never supplies or executes a command. Safe permission changes and config edits
are backed up; every applied action can be reverted with `enki undo`.

### What is sent

Only `rule_id`, module, severity, confidence, sanitized title/evidence,
remediation class/summary/guidance/action, and the posture summary. The payload also
carries a **system context** (OS, arch, distro, service manager, firewall and
package tools, elevation, container status, capabilities, limitations) and the
report's **coverage gaps**, so the model can tailor advice to the machine and
say when the picture is incomplete. It never includes usernames, hostnames,
absolute paths, file contents, or secrets.

Model output is schema-validated: ranked items with priority, rationale,
`fix_steps` (max 4, sanitized), and a recommended action. An action is marked
verified only when it matches enki's deterministic remediation action or is
`manual`; anything else is labelled unverified. The model never executes
anything.

The payload carries `rubric_version` (reproducibility) and, when the report is
truncated, `omitted` plus `omitted_rules` counts. Results echo those fields plus
`findings_sent` and a `cost.metered` flag (false for unknown/self-hosted
models).

- removes absolute POSIX and Windows paths (`[path]`),
- strips control characters and backticks,
- redacts any credential-shaped string (`[redacted: credential material]`),
- replaces instruction-like content with `[redacted: instruction-like content]`,
- caps findings (40 by default) and field lengths.

Findings are wrapped in `<<<ENKI_DATA ... ENKI_DATA>>>` and the system prompt
treats that block as untrusted data.

## Hosted triage service (beta)

`cmd/enki-cloud` is the reference implementation of the paid path.

Configuration:

| Env | Required | Purpose |
|---|---|---|
| `ENKI_CLOUD_ADMIN_KEY` | yes | mints API tokens |
| `DEEPSEEK_API_KEY` | for server-key calls | default provider |
| `ENKI_AI_BASE_URL` / `ENKI_AI_MODEL` | optional | self-hosted gateway |
| `ENKI_STRIPE_WEBHOOK_SECRET` | for billing | Stripe webhook verification |
| `ENKI_STRIPE_SECRET_KEY` | for checkout | Stripe restricted key (checkout sessions) |
| `ENKI_STRIPE_PRICE_PRO` / `_TEAM` | for checkout | Stripe recurring price IDs |
| `ENKI_STRIPE_SUCCESS_URL` / `_CANCEL_URL` | for checkout | Redirect URLs |
| `ENKI_RETENTION_HOURS` | no (24) | audit/cache retention |
| `PORT` | no (8080) | listen port |

```bash
go build -o bin/enki-cloud ./cmd/enki-cloud
ENKI_CLOUD_ADMIN_KEY=admin-secret DEEPSEEK_API_KEY=... ./bin/enki-cloud

# mint a free token (3 lifetime triages)
curl -s -X POST localhost:8080/v1/admin/tokens \
  -H 'Authorization: Bearer admin-secret' \
  -d '{"plan":"free"}'

# triage an existing report (explicit consent is mandatory)
curl -s -X POST localhost:8080/v1/triage \
  -H 'Authorization: Bearer enki_...' \
  -H 'Content-Type: application/json' \
  -d "{\"consent\":true,\"report\":$(cat report.json)}"

# BYOK: caller's key, no quota consumed
curl -s -X POST localhost:8080/v1/triage \
  -H 'Authorization: Bearer enki_...' \
  -H 'X-Enki-Provider-Key: sk-...' \
  -H 'Content-Type: application/json' \
  -d "{\"consent\":true,\"report\":$(cat report.json)}"

curl -s localhost:8080/v1/usage -H 'Authorization: Bearer enki_...'
curl -s -X POST localhost:8080/v1/data/delete -H 'Authorization: Bearer enki_...'

# upgrade: create a Stripe Checkout session for this token
curl -s -X POST localhost:8080/v1/billing/checkout \
  -H 'Authorization: Bearer enki_...' \
  -d '{"plan":"pro"}'      # returns {"checkout_url":"https://checkout.stripe.com/...","session_id":"cs_..."}
```

Behavior:

- Free tokens: 3 lifetime triages. Pro/Team tokens: credit balances. Enterprise:
  unlimited. BYOK calls never consume quota.
- Identical reports are cached for the retention window; cache hits consume no
  credits.
- The REST `/v1/triage` and the MCP `enki_triage` tool share one pipeline and
  policy (cache, quota, refund on provider failure, audit).
- Consent flag required on every call; 401 without a token; 402 when the quota
  is exhausted (MCP returns a tool error).
- Audit events record token, plan, action, finding count, and cost only — never
  finding content or evidence.
- `StartPurge` (hourly in `main`) deletes audit events and cached results older
  than the retention window; `/v1/data/delete` removes a token's audit trail.
- Stripe webhooks (`checkout.session.completed`, `invoice.paid`,
  `customer.subscription.*`) verify `Stripe-Signature` (HMAC-SHA256, 5-minute
  tolerance) and update plan/credits from event metadata (`token_id`, `plan`,
  `credits`). `POST /v1/billing/checkout` creates the subscription checkout
  session and stamps `client_reference_id`/`metadata.token_id` so the webhook
  can match the account.

## Deployment

```bash
ENKI_CLOUD_ADMIN_KEY=admin-secret DEEPSEEK_API_KEY=... docker compose up --build
```

`Dockerfile` builds a static `enki-cloud` on distroless (non-root). Mount a
real database before production: replace `MemoryStore` (tokens/audit/cache) —
the interface is small and intentionally swappable.

## CI

Use the composite action from this repository:

```yaml
- uses: actions/checkout@v4
- uses: yogenpoonudurai/enki@v0.4.0
  with:
    args: "--fail-on high"
```

It installs enki with the runner's Go toolchain, emits `enki.sarif` plus
`enki-report.txt`, uploads them as an artifact, and fails the job when findings
meet the threshold (exit code 1). Runtime errors (exit code 2) always fail.

## Plans (recommended)

| Plan | Price | Triages |
|---|---|---|
| OSS | free | unlimited local, BYO key |
| Free hosted | free | 3 lifetime |
| Pro | $19/mo | 300 credits/mo |
| Team | $39/seat/mo | 1,000 pooled credits, SSO |
| Enterprise | custom | self-host gateway, DPA, premium feeds |

Cost per 50-finding triage is roughly $0.0035-$0.017 depending on model and
peak pricing; `enki triage` reports the metered cost.

## Enterprise / self-hosting

- Run `enki-cloud` with `ENKI_AI_BASE_URL` pointing at a vLLM/OpenAI-compatible
  endpoint inside your network. DeepSeek V4 weights are MIT-licensed and
  self-hostable; Claude/GPT endpoints work the same way.
- The DeepSeek hosted API stores data in the PRC under Chinese law and has no
  DPA/zero-retention option surfaced. Do not send customer findings to it
  without consent; prefer self-hosted inference for paid/enterprise tiers.
- Storage in the beta is in-memory; replace `MemoryStore` with Postgres for
  production (interface is small: tokens, audit, cache, purge).

## Non-goals

Autonomous fixes, tool execution by the model, training a proprietary model,
and gating any local scanning capability.
