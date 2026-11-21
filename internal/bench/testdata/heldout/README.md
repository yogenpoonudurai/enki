# Held-out benchmark corpus

`heldout.json` is a blind, held-out corpus of public-source cases. It is
disjoint from the development public cases in `../realworld.json`.

- Public MCP/agent/model/env files are fetched at pinned commits and verified
  by SHA256; they are not redistributed.
- SBOM cases are real npm registry lockfiles generated with `npm install
  --package-lock-only`; labels come from live OSV queries at build time.
- Labels are produced by `scripts/build-heldout-corpus.py`, which uses
  independent parsers and OSV, not enki's detectors.
- Files containing high-confidence live secrets are excluded. Positive secret
  cases remain in the controlled fixture set.

Regenerate labels with:

```bash
make bench-heldout-update
```
