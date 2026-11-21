# Real-world detection benchmark

Generated from `internal/bench/testdata/realworld.json` plus the controlled fixtures in `internal/bench/testdata/cases.json`. Do not edit by hand; run `make bench-real-world-update`.

> **Preliminary:** this is a curated, non-random corpus. Use per-rule numbers as directional evidence, not ecosystem-wide accuracy.

## Method

- **Public-source cases** are pinned files from public repositories, fetched at a specific commit and verified by SHA256. They are not redistributed in this repository.
- **Controlled cases** are the controlled offline fixtures. Endpoint, secret-positive, and host cases are controlled so the benchmark never handles live credentials or exposed services.
- **SBOM cases** use real npm registry lockfiles; advisory data for lodash 4.17.20 is pinned in the harness so results are reproducible.
- Each label is an expected finding count for a rule in a case. TP = min(expected, actual), FP = extra actual findings, FN = missing expected findings. Only rules listed in the case's `evaluate` list are scored.
- Metrics are per-rule case precision and recall. They are **not** a random sample of the ecosystem and do not do location-level matching.

## Corpus

- Controlled cases: **93** across 23 rules
- Public-source cases: **16**
- Public sources (pinned commit, SHA256 verified at runtime):

| Case | Source | Path | Evaluated rules | Notes |
|---|---|---|---|---|
| public-agent-eigenflux-bypass | [phronesis-io/eigenflux](https://github.com/phronesis-io/eigenflux)@`89204174` | `.claude/settings.json` | AGT-001, AGT-002 | Real settings with bypassPermissions and Bash(*) |
| public-agent-keepalive-bypass | [finedaybreak/keepalive-for-react](https://github.com/finedaybreak/keepalive-for-react)@`4c239246` | `.claude/settings.json` | AGT-001, AGT-002 | Real settings with bypassPermissions and no unrestricted shell grant |
| public-mcp-atlassian-https | [atlassian/atlassian-mcp-server](https://github.com/atlassian/atlassian-mcp-server)@`352a02b0` | `mcp.json` | MCP-002 | Remote MCP endpoint uses HTTPS |
| public-mcp-beautifulrust-https | [morganlinton/BeautifulRust](https://github.com/morganlinton/BeautifulRust)@`b9718436` | `mcp.json` | MCP-002 | Remote MCP endpoint uses HTTPS |
| public-mcp-dramaclaw-local-uv | [dramaclaw/dramaclaw](https://github.com/dramaclaw/dramaclaw)@`d00aad53` | `.mcp.json` | MCP-001 | Real config with no floating npx/uvx package |
| public-mcp-ibm-mixed-packages | [IBM/mcp](https://github.com/IBM/mcp)@`a6b8c9c8` | `mcp.json` | MCP-001, MCP-003 | Nine floating npx/uvx specs; placeholder env values must not be reported as credentials |
| public-mcp-sanity-https | [sanity-io/agent-toolkit](https://github.com/sanity-io/agent-toolkit)@`828641ff` | `mcp.json` | MCP-002 | Remote MCP endpoint uses HTTPS |
| public-mcp-timescale-https | [timescale/pg-aiguide](https://github.com/timescale/pg-aiguide)@`1aef6e45` | `mcp.json` | MCP-002 | Remote MCP endpoint uses HTTPS |
| public-mcp-wp-calypso-unpinned | [Automattic/wp-calypso](https://github.com/Automattic/wp-calypso)@`4b645094` | `.mcp.json` | MCP-001 | Real .mcp.json with an unpinned npx invocation |
| public-model-fluxgym-remote-code | [cocktailpeanut/fluxgym](https://github.com/cocktailpeanut/fluxgym)@`06670734` | `app.py` | MDL-002 | Real app.py with trust_remote_code=True |
| public-model-lgm-remote-code | [3DTopia/LGM](https://github.com/3DTopia/LGM)@`fe8d12cf` | `app.py` | MDL-002, MDL-003 | Real app.py with trust_remote_code=True and torch.load |
| public-model-srgan-torch-load | [aitorzip/PyTorch-SRGAN](https://github.com/aitorzip/PyTorch-SRGAN)@`5377e3cb` | `train` | MDL-003 | Real training script with torch.load |
| public-sbom-lodash-4.17.20 | npm registry (generated lockfile) | `` | SBOM-001 | Real npm lockfile with a pinned vulnerable lodash |
| public-sbom-lodash-4.17.21 | npm registry (generated lockfile) | `` | SBOM-001 | Real npm lockfile at the fixed lodash version |
| public-secrets-llmdebug-placeholders | [mohsen1/llm-debugger-vscode-extension](https://github.com/mohsen1/llm-debugger-vscode-extension)@`17522a38` | `api.env.example` | SEC-001, SEC-003 | Public env example; placeholders must not be reported as secrets |
| public-secrets-tambo-placeholders | [tambo-ai/tambo](https://github.com/tambo-ai/tambo)@`6e2c1bff` | `docker.env.example` | SEC-001, SEC-003 | Public env example; placeholder/configuration values must not be reported as secrets |

## Per-rule results (controlled + public)

| Rule | Module | Public pos/neg | Controlled pos/neg | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AEP-001 | endpoint-exposure | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AEP-002 | endpoint-exposure | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AEP-003 | endpoint-exposure | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AEP-004 | endpoint-exposure | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MCP-001 | mcp | 2/1 | 1/3 | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MCP-002 | mcp | 0/4 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MCP-003 | mcp | 0/1 | 1/4 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MCP-004 | mcp | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MCP-005 | mcp | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MCP-006 | mcp | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| SEC-001 | secrets | 0/2 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| SEC-002 | secrets | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| SEC-003 | secrets | 0/2 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| SEC-004 | secrets | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AGT-001 | agent-permissions | 2/0 | 1/3 | 3 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AGT-002 | agent-permissions | 1/1 | 1/3 | 2 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AGT-003 | agent-permissions | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AGT-004 | agent-permissions | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MDL-001 | model-artifacts | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MDL-002 | model-artifacts | 2/0 | 1/3 | 3 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MDL-003 | model-artifacts | 2/0 | 1/3 | 3 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MDL-004 | model-artifacts | 0/0 | 1/3 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| SBOM-001 | sbom | 1/1 | 1/3 | 2 | 0 | 0 | 100.0% | 100.0% | 100.0% |

## Public-source results only

| Rule | Pos/neg cases | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| MCP-001 | 2/1 | 10 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MCP-002 | 0/4 | 0 | 0 | 0 | — | — | — |
| MCP-003 | 0/1 | 0 | 0 | 0 | — | — | — |
| SEC-001 | 0/2 | 0 | 0 | 0 | — | — | — |
| SEC-003 | 0/2 | 0 | 0 | 0 | — | — | — |
| AGT-001 | 2/0 | 2 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AGT-002 | 1/1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MDL-002 | 2/0 | 2 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MDL-003 | 2/0 | 2 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| SBOM-001 | 1/1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |

## Findings from this corpus

- The IBM public MCP config exposed an MCP-003 false positive on placeholder values such as `YOUR_API_KEY` and `<APIKEY>`. The detector now ignores placeholder-shaped values, and `mcp-003-negative-long-placeholder` is a regression fixture. The results above reflect the fixed detector.
- The public cases add real repository evidence for MCP-001/002, AGT-001/002, MDL-002/003, SEC-001/003 negatives, and SBOM-001; other rules remain controlled.

## Limitations

- The corpus is curated, not a random sample; results are not a claim about ecosystem-wide prevalence.
- Scoring is count-based per case; it does not yet verify exact line/location matching.
- Public-source cases cover MCP, agent permissions, model code, secret-file negatives, and SBOM. Host exposure, secret positives, and some config rules remain controlled.
- SBOM results use a pinned advisory fixture, not live OSV data; rerun against live OSV separately for current advisory coverage.
- Public files can change upstream; the harness pins commits and verifies SHA256, and fails rather than silently using different content.

## Reproduce

```bash
make bench-real-world
make bench-real-world-update   # refresh baseline + this document
```

Baseline: `internal/bench/testdata/realworld-baseline.json`.
