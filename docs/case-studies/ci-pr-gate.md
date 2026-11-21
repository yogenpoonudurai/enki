# Case study: a CI PR gate for AI-tooling configuration

*Illustrative scenario. The workflow YAML below is complete and runnable once
the repository org/name is adjusted.*

## The setup

An AI application repository where developers regularly change:

- `.mcp.json` / `.cursor/mcp.json` (MCP servers for the coding agent)
- `.claude/settings.json` (agent permissions)
- `.env` files (provider keys)
- `package-lock.json` and `requirements.txt`

Reviewers cannot be expected to spot an unpinned MCP package or a pasted API
key in a diff. The goal is a **fast, deterministic PR gate**, not a full
security program in one job.

## The gate

```yaml
# .github/workflows/enki.yml
name: enki
on:
  pull_request:
permissions:
  contents: read

jobs:
  ai-config:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: yogenpoonudurai/enki@v0.5.0
        with:
          # Offline-fast checks only: no OSV network dependency.
          args: "--fail-on high --deps ai --modules mcp,secrets,agent-permissions"
      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: enki-report
          path: enki.sarif
```

A nightly job handles the network-dependent part:

```yaml
# .github/workflows/enki-nightly.yml
name: enki-nightly
on:
  schedule: [{cron: "17 3 * * *"}]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  full:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/cache@v6
        with:
          path: ~/.cache/enki
          key: enki-osv-${{ hashFiles('**/package-lock.json', '**/requirements*.txt') }}
      - uses: yogenpoonudurai/enki@v0.5.0
        with:
          args: "--fail-on critical --deps all"
```

If GitHub code scanning is enabled for the repository, add the SARIF upload:

```yaml
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: enki.sarif
```

(Code scanning is free for public repositories; private repositories need the
appropriate GitHub security product. The artifact upload works everywhere.)

## What a failing PR looks like

A contributor adds a convenient MCP server:

```diff
 {
   "mcpServers": {
+    "browser": {
+      "command": "npx",
+      "args": ["-y", "@some-org/browser-mcp"],
+      "env": {"BROWSER_API_KEY": "sk-live-..."}
+    }
   }
 }
```

The gate fails with two findings:

```
HIGH  MCP-001  Unpinned MCP server package "@some-org/browser-mcp"
      fix (moderate): Pin "@some-org/browser-mcp" to an exact version
HIGH  MCP-003  MCP server "browser" embeds a credential
      evidence: env BROWSER_API_KEY = sk-l…9f2a (fingerprint …)
```

The reviewer asks for a pinned version and an injected secret; the contributor
updates the config and rotates the key. The job goes green. The full report is
attached as an artifact for the security team.

## Policy choices that keep the gate useful

- **Threshold**: PRs fail on `--fail-on high`; the nightly job fails on
  `critical` only, so advisory noise does not page anyone at 3 a.m.
- **Scope**: PR jobs use `--deps ai` and the offline modules; full dependency
  and OS-package scans run nightly. Gate time stays in seconds.
- **Suppressions**: `--ignore-rule RULE-ID` for accepted risks, with the reason
  in the PR description. Do not suppress whole modules.
- **No LLM in the gate**: AI triage is a separate, opt-in workflow. CI must be
  reproducible and must not send findings anywhere by default.
- **Network**: the full scan calls `api.osv.dev` (and KEV/EPSS). If egress is
  restricted, allow those endpoints or keep the offline module set in PRs.

## Why not just Trivy/Snyk?

Keep them — for containers and dependencies they are excellent. This gate
covers the layer they do not: MCP supply chain, agent permission flags, and
provider secrets in AI-tooling configuration. The jobs compose cleanly; enki
does not replace the existing scanner.

## Results

- Risky agent/MCP configuration is caught in review, where it is cheap to fix.
- Secrets never reach the default branch — and never reach an LLM.
- The nightly job gives a dated SBOM and a CVE trend without changing the PR
  experience.
- Findings, fixes, and suppressions are explicit, reviewable, and reversible.

## Reproduce it

Add the two workflows to a test repository and open a PR that adds an unpinned
MCP server. The `ai-config` job fails; pin the package and it passes. Locally:

```bash
enki scan --deps ai --modules mcp,secrets,agent-permissions --fail-on high; echo $?
```
