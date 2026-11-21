# Held-out real-world detection benchmark (live OSV)

Generated on **2026-11-21** from `internal/bench/testdata/heldout.json` with live OSV advisory data. Do not edit by hand; run `make bench-heldout-update`.

> **Held out:** these cases were sourced and labeled after detector tuning and were not used to change detection rules. Results are published as measured, including any false positives and false negatives.

## Method

- The corpus contains at least 100 public-source cases from pinned public repositories plus public npm registry lockfiles.
- Labels are produced by an independent corpus builder, not by enki's detectors. MCP/agent/model/env labels use explicit ground-truth parsers; SBOM labels use live OSV queries.
- Public files are fetched at pinned commits and verified by SHA256; they are not redistributed.
- Secret-like files and positive secret cases are excluded from the public corpus to avoid handling live credentials; secret detection remains covered by controlled fixtures.
- Scoring is per-rule case precision/recall. SBOM-001 uses presence (any advisory vs none); other rules use expected/actual finding counts.

## Corpus composition

| Module | Cases |
|---|---:|
| mcp | 17 |
| secrets | 15 |
| agent-permissions | 20 |
| model-artifacts | 40 |
| sbom | 20 |

Total held-out cases: **112**. Source manifest: `internal/bench/testdata/heldout.json`.

## Per-rule results

| Rule | Module | Pos/neg | TP | FP | FN | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| AEP-001 | endpoint-exposure | 0/0 | 0 | 0 | 0 | — | — | — |
| AEP-002 | endpoint-exposure | 0/0 | 0 | 0 | 0 | — | — | — |
| AEP-003 | endpoint-exposure | 0/0 | 0 | 0 | 0 | — | — | — |
| AEP-004 | endpoint-exposure | 0/0 | 0 | 0 | 0 | — | — | — |
| MCP-001 | mcp | 6/11 | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MCP-002 | mcp | 0/17 | 0 | 0 | 0 | — | — | — |
| MCP-003 | mcp | 0/17 | 0 | 0 | 0 | — | — | — |
| MCP-004 | mcp | 0/17 | 0 | 0 | 0 | — | — | — |
| MCP-005 | mcp | 0/17 | 0 | 0 | 0 | — | — | — |
| MCP-006 | mcp | 0/0 | 0 | 0 | 0 | — | — | — |
| SEC-001 | secrets | 0/15 | 0 | 0 | 0 | — | — | — |
| SEC-002 | secrets | 0/0 | 0 | 0 | 0 | — | — | — |
| SEC-003 | secrets | 0/15 | 0 | 0 | 0 | — | — | — |
| SEC-004 | secrets | 0/0 | 0 | 0 | 0 | — | — | — |
| AGT-001 | agent-permissions | 10/10 | 10 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AGT-002 | agent-permissions | 3/17 | 3 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AGT-003 | agent-permissions | 0/20 | 0 | 0 | 0 | — | — | — |
| AGT-004 | agent-permissions | 0/20 | 0 | 0 | 0 | — | — | — |
| MDL-001 | model-artifacts | 0/0 | 0 | 0 | 0 | — | — | — |
| MDL-002 | model-artifacts | 20/20 | 20 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MDL-003 | model-artifacts | 22/18 | 22 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MDL-004 | model-artifacts | 0/40 | 0 | 0 | 0 | — | — | — |
| SBOM-001 | sbom | 16/4 | 16 | 0 | 0 | 100.0% | 100.0% | 100.0% |

## Label corrections during the held-out build

- `uv run` was initially treated as an unpinned `uvx` launch; the rule scope is npx/uvx, so that label was removed.
- AGT and MDL findings are emitted once per config/file; labels now use the same finding granularity (for example, multiple Bash entries or torch.load calls count as one finding).
- These corrections were made only in the independent corpus labeler. No detector code was changed based on held-out results.
- The corpus is disjoint from the development public cases, including the lodash SBOM pairs used there.

## Case-level mismatches

No expected/actual count mismatches in this run.

## Limitations

- The corpus is selected from public search results and may not be representative of the ecosystem; it is a held-out set, not a random sample.
- Labels are produced by independent parsers and OSV; parser ambiguities and upstream updates can create label noise.
- Scoring is count-based for most rules and presence-based for SBOM; exact location matching is not implemented.
- Host exposure and positive secret cases remain controlled; this report does not measure runtime exposure in the wild.
- Live OSV results are a snapshot and can change as advisories are published or withdrawn.

## Reproduce

```bash
make bench-heldout
make bench-heldout-update
```

Baseline: `internal/bench/testdata/heldout-baseline.json`.
