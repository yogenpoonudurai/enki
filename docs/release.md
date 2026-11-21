# Releases and verification

Releases are built by goreleaser from a tag, with keyless cosign signing (no
long-lived private key). The workflow is `.github/workflows/release.yml`.

## Cut a release

```bash
git tag v0.4.0
git push origin v0.4.0
```

The workflow:

1. builds `enki`, `enki-mcp`, and `enki-cloud` (see `.goreleaser.yaml`);
2. produces archives and `checksums.txt`;
3. signs `checksums.txt` with cosign keyless (GitHub OIDC), emitting
   `checksums.txt.sig` and `checksums.txt.pem`;
4. publishes a GitHub Release.

`make build` remains the local development path: it uses the exact tag when
present, otherwise `0.4.0-dev`.

## Verify a download

```bash
# 1. verify the checksum file's signature
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/yogenpoonudurai/enki/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# 2. verify the archive matches the signed checksum
sha256sum -c checksums.txt --ignore-missing
```

The certificate identity pins the signing workflow and tag; the OIDC issuer
proves it ran in GitHub Actions. If verification fails, do not install the
artifact.

## Manual local build

```bash
make build                 # all three binaries, version from tag or 0.4.0-dev
make cross                 # linux/darwin/windows × amd64/arm64 (+ cloud on linux)
```

Reproducibility: builds use `-trimpath` and `CGO_ENABLED=0`; `SOURCE_DATE_EPOCH`
is not yet pinned, so bytes may differ across toolchains even though inputs are
identical.

## Release checklist

- [ ] Update `server.json` version and the MCP registry entry.
- [ ] `go test ./...` and `make cross` green.
- [ ] Tag pushed; workflow succeeded; signature assets present.
- [ ] `cosign verify-blob` passes from a clean machine.
- [ ] Release notes list breaking changes and new rules.
