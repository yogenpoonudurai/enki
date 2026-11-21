# enki rule reference (condensed)

| Rule | Module | Severity | Checks |
|---|---|---|---|
| AEP-001 | endpoint-exposure | CRITICAL/HIGH | AI service reachable on a network address |
| AEP-002 | endpoint-exposure | MEDIUM | Loopback service reflects arbitrary CORS origins |
| AEP-003 | endpoint-exposure | HIGH | Gradio `--share` public tunnel |
| AEP-004 | endpoint-exposure | HIGH | Jupyter API without a token |
| MCP-001 | mcp | HIGH | Unpinned npx/uvx MCP package |
| MCP-002 | mcp | MEDIUM | Remote MCP over plaintext HTTP |
| MCP-003 | mcp | HIGH | Credential embedded in MCP env/headers |
| MCP-004 | mcp | MEDIUM | MCP server granted a filesystem root/home |
| MCP-005 | mcp | INFO | MCP server exposes shell/exec |
| MCP-006 | mcp | MEDIUM | MCP config world-readable |
| SEC-001 | secrets | HIGH/CRITICAL | Provider key in plaintext file (CRITICAL if git-tracked) |
| SEC-002 | secrets | MEDIUM/HIGH | Provider key in shell history |
| SEC-003 | secrets | MEDIUM | Secret file readable by other users |
| SEC-004 | secrets | MEDIUM | Hugging Face token in plaintext |
| AGT-001 | agent-permissions | HIGH | bypassPermissions / dangerously-skip-permissions |
| AGT-002 | agent-permissions | MEDIUM | Unrestricted shell in allow-list |
| AGT-003 | agent-permissions | MEDIUM | Auto-run/auto-approve enabled |
| AGT-004 | agent-permissions | HIGH | Allow-list grants ~/.ssh, ~/.aws, GPG |
| MDL-001 | model-artifacts | MEDIUM | Pickle-based weight files |
| MDL-002 | model-artifacts | HIGH | trust_remote_code enabled |
| MDL-003 | model-artifacts | MEDIUM | torch.load without weights_only |
| MDL-004 | model-artifacts | MEDIUM | Weights downloaded over HTTP |
| SBOM-001 | sbom | advisory | Pinned dependency affected by an OSV advisory |

Severity: CRITICAL > HIGH > MEDIUM > LOW > INFO. KEV raises to at least HIGH;
EPSS ≥ 0.5 raises one level.

Remediation classes: SAFE (permissions, auto-applicable), MODERATE (config
edits, confirmed), RISKY (printed commands only). All applied changes are
backed up and reversible with `enki undo`.

The authoritative list is also available via `enki rules list`.
