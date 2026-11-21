# Contributing to enki

Thanks for helping improve enki. This project optimizes for deterministic
findings, reversible remediation, and a fully functional open-source core.

## Development setup

```bash
go version          # Go 1.27.0+
make build          # bin/enki, bin/enki-mcp
make test
make vet
make cross          # linux/darwin/windows × amd64/arm64
```

### Containerized tests (recommended)

Do not run smoke tests against your production machine. Use the dev container
or the container targets — both Docker and Podman are supported:

```bash
make test-container     # unit tests inside the container
make smoke-container    # BYOK end-to-end against a local fake provider
make verify-docs-container  # run every command documented in README/quickstart
make shell-container    # interactive shell in the image
```

Triage against a real local model instead (no API key, unmetered):

```bash
podman run -d --name enki-ollama -p 127.0.0.1:11434:11434 \
  -v enki-ollama-models:/root/.ollama ollama/ollama
podman exec enki-ollama ollama pull qwen2.5:1.5b
make smoke-local-container
```

Override `LOCAL_AI_BASE_URL` / `LOCAL_AI_MODEL` for llama.cpp, vLLM, or LM
Studio. On Docker Desktop use `LOCAL_AI_NETWORK=bridge` and
`LOCAL_AI_BASE_URL=http://host.docker.internal:11434/v1`.

Or open the repository in VS Code/Qoder with the devcontainer
(`.devcontainer/`). The image includes Go 1.27, Python (with Pillow for the
demo renderer), curl, jq, and make. Podman users need
`--userns=keep-id` (already set in `devcontainer.json`); Docker users should
remove that `runArgs` entry.

Requirements for changes:

- `gofmt` clean, `go vet` clean, `go test ./...` green.
- `make bench-detect` green (the detection benchmark is part of CI).
- No new network calls in scan modules without an explicit opt-in and a
  documented coverage gap on failure.
- No telemetry, no hidden uploads, no secrets in logs or test fixtures.
- Findings must remain deterministic; AI must never be in the detection path.

## Scope discipline and feature freeze

enki is pre-1.0 and optimizes for demonstrated detection quality, not surface
area. Until repeated real-world usage and published benchmark results justify
expansion:

- Do not add new modules, dashboards, hosted services, integrations, or output
  formats without maintainer agreement.
- Do not expand a module's claim beyond what its fixtures and documentation
  demonstrate.
- Every new surface must document what it inspects, what it skips, and how
  failures appear as coverage gaps.
- Release notes must state any scope change and the reason for it.

Remediation hardening and the detection benchmark are the prerequisites for
expanding a detector or interface. If a proposal cannot meet the evidence bar
below, it should wait.

## Adding a rule

1. Pick the module that owns the check (`internal/scanner/<module>`).
2. Implement the check and emit `finding.New(ruleID, ...)` with severity,
   confidence, redacted evidence, and (when safe) a typed remediation:
   `Action: chmod_private` or `remove_json_key`, plus `Params`.
3. Register the rule in `internal/rules/catalog.go` with a category
   (`exposure`, `vulnerability`, `unsafe-config`, `hygiene`) and a basis
   (`confirmed`, `conditional`, `presence`). Document it in `docs/rules.md`.
4. Add at least one positive, two negative, and one adversarial fixture to
   `internal/bench/testdata/cases.json`. Negative and adversarial cases must
   not trigger the rule. Run `make bench-detect`; if the fixtures are
   intentional, run `make bench-update` to refresh the baseline and
   `docs/detection-benchmark.md`.
   If the rule can be exercised on public data, add a pinned public-source case
   to `internal/bench/testdata/realworld.json` with its commit and SHA256.
   Run `make bench-real-world` manually (it fetches pinned public files and is
   not part of PR CI); refresh it with `make bench-real-world-update`.
   The blind held-out corpus is `internal/bench/testdata/heldout.json`; run it
   with live OSV via `make bench-heldout-update`. Do not tune detectors on
   held-out results before publishing them.
5. Add a unit test for module-specific behavior. For remediation, verify `fix`
   then `undo` restores the file byte-for-byte and never touches sensitive
   paths.
6. Update `skills/enki/references/rules.md` so agents know the rule.

The benchmark test fails when any catalog rule has fewer than
1 positive / 2 negative / 1 adversarial fixture, so a rule cannot merge
without evidence.

Rules must be:

- **Deterministic** — same inputs, same finding.
- **Low-noise** — require corroborating signals for HIGH/CRITICAL; use
  confidence levels rather than guessing.
- **Calibrated** — do not describe a presence or conditional signal as a
  confirmed compromise.
- **Safe** — never execute destructive actions; remediation is dry-run by
  default and backed up.
- **Explainable** — evidence must let a user verify the finding without
  re-running the tool.

## AI triage contributions

`internal/ai` only ranks and explains existing findings. Changes there must
keep the redaction contract (no paths, secrets, file contents) and the
schema-validated, tool-less output. Actions recommended by the model must map
to enki's deterministic remediation actions or be marked unverified.

## Commit sign-off (DCO)

By contributing, you certify that you wrote the change or have the right to
submit it under the project license. Include a `Signed-off-by:` line in your
commit (`git commit -s`).

## License

Contributions are accepted under Apache-2.0. The hosted service and premium
feeds are a separate private product: they are not in this repository (see
[docs/open-core.md](docs/open-core.md)), and
community contributions are not accepted for them. Contributing a detection
rule does not change the open-source scope.
