# Held-out benchmark against the v0.5.1 release binary

> **Target:** the actual `v0.5.1` release binary (`0.5.1`, commit `87cd9f6`), not the source tree. 
> Release: [v0.5.1](https://github.com/yogenpoonudurai/enki/releases/tag/v0.5.1) · Source-tree report: [benchmark-heldout-v0.5.1.md](benchmark-heldout-v0.5.1.md).
> Extracted from `enki_0.5.1_linux_amd64.tar.gz`; the archive checksum, cosign signature, and provenance were verified before this run. The harness never imports enki scanner code.

## Method

- Each case is materialized into a temporary project directory and scanned by invoking `enki scan --scope project --json` as a subprocess.
- The harness scores only the rules listed in each case's `evaluate` list, using the same independent labels and presence semantics as the source-tree held-out report.
- SBOM cases use the binary's live OSV client. Host exposure and positive secret cases remain controlled and are not part of this held-out corpus.
- No enki source package is imported; the release binary is the only scanner under test.

## Corpus

- Held-out cases: **111**

## Per-rule results

| Rule | Pos/neg | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| AGT-001 | 10/10 | 10 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AGT-002 | 3/17 | 3 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| AGT-003 | 0/20 | 0 | 0 | 0 | — | — | — |
| AGT-004 | 0/20 | 0 | 0 | 0 | — | — | — |
| MCP-001 | 6/11 | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MCP-002 | 0/17 | 0 | 0 | 0 | — | — | — |
| MCP-003 | 0/17 | 0 | 0 | 0 | — | — | — |
| MCP-004 | 0/17 | 0 | 0 | 0 | — | — | — |
| MCP-005 | 0/17 | 0 | 0 | 0 | — | — | — |
| MDL-002 | 20/20 | 20 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MDL-003 | 22/18 | 22 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| MDL-004 | 0/40 | 0 | 0 | 0 | — | — | — |
| SBOM-001 | 16/4 | 16 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| SEC-001 | 0/14 | 0 | 0 | 0 | — | — | — |
| SEC-003 | 0/14 | 0 | 0 | 0 | — | — | — |

## Source-tree comparison

Per-rule TP/FP/FN are identical to the source-tree v0.5.1 run.

## Case-level mismatches

No expected/actual count mismatches in this run.

## Limitations

- The corpus is a curated held-out sample, not a random ecosystem sample.
- The release binary is Linux amd64; this run measures that artifact, not every platform.
- Live OSV is a snapshot and can change after the run.
- Scoring is count/presence-based per case; exact location matching is not implemented.

## Reproduce

```bash
gh release download v0.5.1 -p enki_0.5.1_linux_amd64.tar.gz
tar xzf enki_0.5.1_linux_amd64.tar.gz
scripts/bench-release-binary.py --binary ./enki --repo-root . \
  --out-md /tmp/bench.md --out-json /tmp/bench.json
```
