# Contributing to enki

Thanks for helping improve enki. This project optimizes for deterministic
findings, reversible remediation, and a fully functional open-source core.

## Development setup

```bash
go version          # Go 1.27+
make build          # bin/enki, bin/enki-mcp, bin/enki-cloud
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
- No new network calls in scan modules without an explicit opt-in and a
  documented coverage gap on failure.
- No telemetry, no hidden uploads, no secrets in logs or test fixtures.
- Findings must remain deterministic; AI must never be in the detection path.

## Adding a rule

1. Pick the module that owns the check (`internal/scanner/<module>`).
2. Implement the check and emit `finding.New(ruleID, ...)` with severity,
   confidence, redacted evidence, and (when safe) a typed remediation:
   `Action: chmod_private` or `remove_json_key`, plus `Params`.
3. Register the rule in `internal/rules/catalog.go` and document it in
   `docs/rules.md`.
4. Add a fixture-based test. For remediation, verify `fix` then `undo`
   restores the file byte-for-byte and never touches sensitive paths.
5. Update `skills/enki/references/rules.md` so agents know the rule.

Rules must be:

- **Deterministic** — same inputs, same finding.
- **Low-noise** — require corroborating signals for HIGH/CRITICAL; use
  confidence levels rather than guessing.
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

Contributions are accepted under Apache-2.0. Hosted services and premium rule
feeds are separate products; contributing a detection rule does not change the
open-source scope.
