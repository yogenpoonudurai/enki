# AI triage: local BYOK, skills, and MCP

enki keeps a hard boundary between deterministic scanning and AI assistance.

- **Deterministic (offline):** scanning, finding generation, severity,
  remediation planning, fix/undo, SARIF/OCSF/CycloneDX.
- **AI (optional, consent-gated):** ranking and explanation of existing
  findings only. The model cannot create findings, choose arbitrary commands,
  or execute anything.

Triage uses your own provider key (BYOK) and calls the provider directly. There
is no hosted compute, account, or quota. A local model works without any key.
An optional paid hosted mode uses the same locally redacted payload; see
[premium.md](premium.md).

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
are backed up and journaled; every applied action can be reverted with
`enki undo` unless the file changed after the fix.

## What is sent

Only `rule_id`, module, severity, confidence, category, basis, sanitized
title/evidence, remediation class/summary/guidance/action, and the posture
summary. The payload also carries a **system context** (OS, arch, distro,
service manager, firewall and package tools, elevation, container status,
capabilities, limitations) and the report's **coverage gaps**, so the model can
tailor advice to the machine and say when the picture is incomplete. It never
includes usernames, hostnames, absolute paths, file contents, or secrets.

Model output is schema-validated: ranked items with priority, rationale,
`fix_steps` (max 4, sanitized), and a recommended action. An action is marked
verified only when it matches enki's deterministic remediation action or is
`manual`; anything else is labelled unverified. The model never executes
anything.

The payload carries `rubric_version` (reproducibility) and, when the report is
truncated, `omitted` plus `omitted_rules` counts. Results echo those fields plus
`findings_sent` and a `cost.metered` flag (false for unknown/self-hosted
models).

Redaction:

- removes absolute POSIX and Windows paths (`[path]`),
- strips control characters and backticks,
- redacts any credential-shaped string (`[redacted: credential material]`),
- replaces instruction-like content with `[redacted: instruction-like content]`,
- caps findings (40 by default) and field lengths.

Findings are wrapped in `<<<ENKI_DATA ... ENKI_DATA>>>` and the system prompt
treats that block as untrusted data. Consent is explicit: triage never runs as
part of a scan or fix.

## Non-goals

Autonomous fixes, tool execution by the model, training a proprietary model,
and gating any local scanning capability.
