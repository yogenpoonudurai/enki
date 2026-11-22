# MCP registry submissions

`server.json` at the repository root is metadata for the local **stdio** MCP
server (`enki-mcp`). It deliberately carries no remote registry entry: hosted
MCP is a separate paid surface published from a private repository, not from
the open core. `enki-mcp --http` is a self-host option for your own LAN or
tailnet (see [getting-started.md](getting-started.md)), not a hosted endpoint,
and must not be registered as a remote server.

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
- The registry expects a distribution (a package or a remote). This metadata
  entry is published only when a packaged stdio distribution is available; do
  not point it at the paid hosted endpoint.
- Registry is in preview; data resets are possible.

## Other directories

| Directory | How |
|---|---|
| mcp.so | Submit via the “Submit server” form on mcp.so; use the short description below. |
| Smithery | Add the local stdio server on smithery.ai. |
| Glama | Submit through the Glama MCP directory form. |
| Claude Code plugins | Repository already contains `.claude-plugin/plugin.json` and `marketplace.json`; users add it with `/plugin marketplace add <repo>` then `/plugin install enki@enki-marketplace`. |
| Cursor | Ship `skills/enki` via `~/.cursor/skills` or `.cursor/skills`; configure `enki-mcp` as a local stdio server. |

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
> Outputs include SARIF, OCSF, and CycloneDX.

## Preflight checklist

- [x] `server.json` name matches the publishing GitHub namespace.
- [x] Version matches the release tag.
- [x] No remote endpoint is published from this repository.
- [ ] `mcp-publisher validate` passes for the current schema.
- [x] Demo GIF and getting-started link are live.
