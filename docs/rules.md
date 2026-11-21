# Rule reference

Rule IDs are stable and intended for suppression (`--ignore-rule`), CI
thresholds, and SIEM correlation.

Every finding carries four independent signals:

- **Severity** — urgency for triage and the CI threshold.
- **Category** — `exposure`, `vulnerability`, `unsafe-config`, or `hygiene`.
- **Basis** — `confirmed` (observed evidence), `conditional` (risk depends on
  an external event such as a compromised dependency), or `presence` (the
  artifact or setting exists, but that alone does not prove compromise).
- **Confidence** — how sure the detector is that the observation is real.

Detection quality is tracked per rule in
[detection-benchmark.md](detection-benchmark.md), with positive, negative, and
adversarial fixtures and a CI regression gate.

A HIGH finding is not automatically a confirmed vulnerability. For example, an
unpinned MCP package is conditional supply-chain uncertainty, and the presence
of pickle weights is hygiene until an untrusted file is actually loaded.

## AEP — endpoint exposure (`endpoint-exposure`)

| ID | Severity | Category | Basis | Check |
|---|---|---|---|---|
| AEP-001 | CRITICAL / HIGH | exposure | conditional | AI service (Ollama, LM Studio, ComfyUI, A1111, vLLM, LocalAI, Open WebUI, Kobold, Jupyter, llama.cpp) bound to a non-loopback address; CRITICAL when the unauthenticated fingerprint confirms the service |
| AEP-002 | MEDIUM | exposure | confirmed | Loopback service reflects arbitrary origins in `Access-Control-Allow-Origin` (DNS-rebinding/exfil risk) |
| AEP-003 | HIGH | exposure | confirmed | Gradio started with `--share` or `GRADIO_SHARE` (public tunnel) |
| AEP-004 | HIGH | exposure | confirmed | Jupyter API answers without a token |

## MCP — Model Context Protocol configs (`mcp`)

| ID | Severity | Category | Basis | Check |
|---|---|---|---|---|
| MCP-001 | MEDIUM | unsafe-config | conditional | `npx`/`uvx` server runs an unpinned package (no exact version); the next start may resolve a different release |
| MCP-002 | MEDIUM | unsafe-config | confirmed | Remote MCP endpoint over plaintext `http://` |
| MCP-003 | HIGH | exposure | confirmed | Credential embedded in server `env` or headers |
| MCP-004 | MEDIUM | unsafe-config | confirmed | Filesystem root, home directory, or drive root granted |
| MCP-005 | INFO | hygiene | presence | Server exposes shell/exec functionality |
| MCP-006 | MEDIUM | hygiene | confirmed | MCP config is world-readable |

## SEC — secrets (`secrets`)

| ID | Severity | Category | Basis | Check |
|---|---|---|---|---|
| SEC-001 | HIGH / CRITICAL | vulnerability | confirmed | Provider key in config/.env/credential file; CRITICAL when tracked by git |
| SEC-002 | MEDIUM / HIGH | vulnerability | confirmed | Provider key in shell history; HIGH when the history file is group/world readable |
| SEC-003 | MEDIUM | hygiene | confirmed | Secret-bearing file readable by other users |
| SEC-004 | MEDIUM | vulnerability | confirmed | Hugging Face token file in plaintext |

## AGT — agent permissions (`agent-permissions`)

| ID | Severity | Category | Basis | Check |
|---|---|---|---|---|
| AGT-001 | HIGH | unsafe-config | confirmed | `bypassPermissions`, `dangerouslySkipPermissions`, or `--dangerously-skip-permissions` in a shell profile |
| AGT-002 | MEDIUM | unsafe-config | confirmed | Allow-list grants an unrestricted shell (`Bash(*)`, `shell`, ...) |
| AGT-003 | MEDIUM | unsafe-config | confirmed | Auto-run / auto-approve enabled |
| AGT-004 | HIGH | unsafe-config | confirmed | Allow-list grants access to `~/.ssh`, `~/.aws`, GPG, or gcloud credentials |

## MDL — model artifacts (`model-artifacts`)

| ID | Severity | Category | Basis | Check |
|---|---|---|---|---|
| MDL-001 | LOW | hygiene | presence | Pickle-based weight files (`.pt`, `.pkl`, …); presence alone is not evidence of an untrusted or modified artifact |
| MDL-002 | HIGH | unsafe-config | conditional | `trust_remote_code=True`; risk materializes if the model repository is compromised or swapped |
| MDL-003 | MEDIUM | unsafe-config | conditional | `torch.load` without `weights_only=True` on releases before PyTorch 2.6 |
| MDL-004 | MEDIUM | unsafe-config | confirmed | Model weights fetched over plain HTTP |

## SBOM — dependency CVEs (`sbom`)

| ID | Severity | Category | Basis | Check |
|---|---|---|---|---|
| SBOM-001 | advisory-driven | vulnerability | confirmed | Pinned dependency affected by an OSV advisory across npm, PyPI, Go, Cargo, NuGet, and Linux OS packages; severity from CVSS v3/GHSA, raised by CISA KEV and EPSS, grouped by CVE |
