# MCP registry submissions

> **Deferred.** Hosted MCP registry submission is not part of the default
> release while the hosted surface is deferred. This guide is retained for
> maintainers.

`server.json` at the repository root describes the **hosted** MCP endpoint. It
is metadata only — update the two placeholders before publishing:

1. `name` — must match your GitHub account/org: `io.github.<user>/enki`.
2. `remotes[0].url` — a public HTTPS Streamable HTTP endpoint
   (`https://<host>/mcp`). The hosted service requires a bearer token for tool
   calls; the registry itself only verifies namespace ownership.

The `description` field is limited to 100 characters by the registry.

## Official MCP Registry (preview)

```bash
# install (macOS/Linux, amd64/arm64)
curl -L "https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" \
  | tar xz mcp-publisher && sudo mv mcp-publisher /usr/local/bin/

mcp-publisher validate        # validates server.json
mcp-publisher login github    # device flow; uses your GitHub identity
mcp-publisher publish
```

Verify:

```bash
curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.yogenpoonudurai/enki"
```

Notes:

- Publishing does not happen via a PR to the registry repository; use the CLI.
- With GitHub auth the name must start with `io.github.<your-username>/`.
- Registry is in preview; data resets are possible.

## Other directories

| Directory | How |
|---|---|
| mcp.so | Submit via the “Submit server” form on mcp.so; use the short description below. |
| Smithery | Add the server on smithery.ai (remote HTTP endpoint + auth description). |
| Glama | Submit through the Glama MCP directory form. |
| Claude Code plugins | Repository already contains `.claude-plugin/plugin.json` and `marketplace.json`; users add it with `/plugin marketplace add <repo>` then `/plugin install enki@enki-marketplace`. |
| Cursor | Ship `skills/enki` via `~/.cursor/skills` or `.cursor/skills`; configure the remote MCP endpoint in `.cursor/mcp.json`. |

## Copy blocks

Short (≤200 chars):

> AI configuration and exposure scanning for laptops and GPU servers: exposed inference endpoints,
> MCP supply-chain risk, agent permissions, secrets, model artifacts, and CVE
> scanning — with reversible fixes.

Long:

> enki audits the AI stack on developer machines and servers. It finds inference
> services bound to the network, risky MCP server configuration, agent
> permission sprawl, provider secrets, unsafe model artifacts, and dependency
> vulnerabilities across npm, PyPI, Go, Cargo, NuGet, and Linux packages. Safe
> fixes apply with backups; every change is reversible with `enki undo`.
> Outputs include SARIF, OCSF, and CycloneDX. Hosted MCP exposes redacted,
> consent-gated AI triage.

## Preflight checklist

- [ ] `/mcp` is reachable over HTTPS from the public internet.
- [ ] Auth requirements documented (bearer token for hosted tools).
- [x] `server.json` name matches the publishing GitHub namespace.
- [x] Version matches the release tag.
- [x] `mcp-publisher validate` passes (v1.8.10, validated 2026-11-21).
- [x] Demo GIF and getting-started link are live.
