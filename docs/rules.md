# Rule reference

Rule IDs are stable and intended for suppression (`--ignore-rule`), CI
thresholds, and SIEM correlation.

## AEP — endpoint exposure (`endpoint-exposure`)

| ID | Severity | Check |
|---|---|---|
| AEP-001 | CRITICAL / HIGH | AI service (Ollama, LM Studio, ComfyUI, A1111, vLLM, LocalAI, Open WebUI, Kobold, Jupyter, llama.cpp) bound to a non-loopback address; CRITICAL when the unauthenticated fingerprint confirms the service |
| AEP-002 | MEDIUM | Loopback service reflects arbitrary origins in `Access-Control-Allow-Origin` (DNS-rebinding/exfil risk) |
| AEP-003 | HIGH | Gradio started with `--share` or `GRADIO_SHARE` (public tunnel) |
| AEP-004 | HIGH | Jupyter API answers without a token |

## MCP — Model Context Protocol configs (`mcp`)

| ID | Severity | Check |
|---|---|---|
| MCP-001 | HIGH | `npx`/`uvx` server runs an unpinned package (no exact version) |
| MCP-002 | MEDIUM | Remote MCP endpoint over plaintext `http://` |
| MCP-003 | HIGH | Credential embedded in server `env` or headers |
| MCP-004 | MEDIUM | Filesystem root, home directory, or drive root granted |
| MCP-005 | INFO | Server exposes shell/exec functionality |
| MCP-006 | MEDIUM | MCP config is world-readable |

## SEC — secrets (`secrets`)

| ID | Severity | Check |
|---|---|---|
| SEC-001 | HIGH / CRITICAL | Provider key in config/.env/credential file; CRITICAL when tracked by git |
| SEC-002 | MEDIUM / HIGH | Provider key in shell history; HIGH when the history file is group/world readable |
| SEC-003 | MEDIUM | Secret-bearing file readable by other users |
| SEC-004 | MEDIUM | Hugging Face token file in plaintext |

## AGT — agent permissions (`agent-permissions`)

| ID | Severity | Check |
|---|---|---|
| AGT-001 | HIGH | `bypassPermissions`, `dangerouslySkipPermissions`, or `--dangerously-skip-permissions` in a shell profile |
| AGT-002 | MEDIUM | Allow-list grants an unrestricted shell (`Bash(*)`, `shell`, ...) |
| AGT-003 | MEDIUM | Auto-run / auto-approve enabled |
| AGT-004 | HIGH | Allow-list grants access to `~/.ssh`, `~/.aws`, GPG, or gcloud credentials |

## MDL — model artifacts (`model-artifacts`)

| ID | Severity | Check |
|---|---|---|
| MDL-001 | MEDIUM | Pickle-based weight files (`.pt`, `.pkl`, …) |
| MDL-002 | HIGH | `trust_remote_code=True` |
| MDL-003 | MEDIUM | `torch.load` without `weights_only=True` |
| MDL-004 | MEDIUM | Model weights fetched over plain HTTP |

## SBOM — dependency CVEs (`sbom`)

| ID | Severity | Check |
|---|---|---|
| SBOM-001 | advisory-driven | Pinned dependency affected by an OSV advisory across npm, PyPI, Go, Cargo, NuGet, and Linux OS packages; severity from CVSS v3/GHSA, raised by CISA KEV and EPSS, grouped by CVE |
