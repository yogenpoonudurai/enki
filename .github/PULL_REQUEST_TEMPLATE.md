## Summary

What changes, and why?

## Scope check

- [ ] This change belongs in the open-source core (detection, reporting,
      remediation, CLI/MCP, docs, CI).
- [ ] It does not add hosted-service or premium code; see
      [docs/open-core.md](../docs/open-core.md) for the boundary. That code
      lives in a separate private repository.
- [ ] New findings keep the determinism and evidence bar in `CONTRIBUTING.md`.

## Verification

- [ ] `gofmt` clean, `go vet ./...`, `go test ./...`, `make cross`
- [ ] New or changed rules have positive, negative, and adversarial fixtures
- [ ] Docs updated for user-visible behavior
- [ ] No secrets, tokens, or machine paths in fixtures, logs, or screenshots

## Sign-off

- [ ] Commits include `Signed-off-by:` (`git commit -s`) per the DCO
