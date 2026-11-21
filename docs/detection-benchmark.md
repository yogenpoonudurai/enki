# Detection benchmark

Generated from `internal/bench/testdata/cases.json`. Do not edit by hand; run `make bench-update`.

93 offline fixtures across 23 rules. Positive fixtures must produce the rule under test; negative and adversarial fixtures must not produce that rule (or any explicitly forbidden rule).

| Rule | Module | Positive | Negative | Adversarial |
|---|---|---:|---:|---:|
| AEP-001 | endpoint-exposure | 1 | 2 | 1 |
| AEP-002 | endpoint-exposure | 1 | 2 | 1 |
| AEP-003 | endpoint-exposure | 1 | 2 | 1 |
| AEP-004 | endpoint-exposure | 1 | 2 | 1 |
| AGT-001 | agent-permissions | 1 | 2 | 1 |
| AGT-002 | agent-permissions | 1 | 2 | 1 |
| AGT-003 | agent-permissions | 1 | 2 | 1 |
| AGT-004 | agent-permissions | 1 | 2 | 1 |
| MCP-001 | mcp | 1 | 2 | 1 |
| MCP-002 | mcp | 1 | 2 | 1 |
| MCP-003 | mcp | 1 | 3 | 1 |
| MCP-004 | mcp | 1 | 2 | 1 |
| MCP-005 | mcp | 1 | 2 | 1 |
| MCP-006 | mcp | 1 | 2 | 1 |
| MDL-001 | model-artifacts | 1 | 2 | 1 |
| MDL-002 | model-artifacts | 1 | 2 | 1 |
| MDL-003 | model-artifacts | 1 | 2 | 1 |
| MDL-004 | model-artifacts | 1 | 2 | 1 |
| SBOM-001 | sbom | 1 | 2 | 1 |
| SEC-001 | secrets | 1 | 2 | 1 |
| SEC-002 | secrets | 1 | 2 | 1 |
| SEC-003 | secrets | 1 | 2 | 1 |
| SEC-004 | secrets | 1 | 2 | 1 |

## Scope

The corpus covers deterministic detectors offline. Network listeners are simulated with loopback HTTP servers; OSV is replaced with a deterministic fake client. It does not measure real-world prevalence, only rule behavior on known fixtures.
