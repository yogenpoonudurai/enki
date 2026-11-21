# Releases and verification

Releases are built by goreleaser from a tag, with keyless cosign signing (no
long-lived private key). The workflow is `.github/workflows/release.yml`.

## Cut a release

```bash
git tag v0.5.2
git push origin v0.5.2
```

The workflow:

1. generates the CycloneDX SBOM (`enki.sbom.cdx.json`) before building;
2. builds `enki` and `enki-mcp` (see `.goreleaser.yaml`);
3. produces archives and `checksums.txt`;
4. signs `checksums.txt` with cosign keyless (GitHub OIDC), emitting
   `checksums.txt.sig` and `checksums.txt.pem`;
5. publishes an immutable GitHub Release containing the archives, signatures,
   and SBOM (`release.extra_files` in `.goreleaser.yaml`);
6. verifies the release asset allowlist;
7. attests build provenance for the archives, checksums, signatures, and SBOM.

Immutable releases reject assets added after publication, which is why the
SBOM is generated before goreleaser and included at creation. Prerelease tags
are marked as prereleases automatically.

`make build` remains the local development path: it uses the exact tag when
present, otherwise `0.5.2-dev`.

## Scope policy

The archives contain `enki` and `enki-mcp`. The hosted service is maintained
in a separate private repository and published on its own release channel; it
is never built, signed, or published by this workflow. New detectors or
surfaces must follow the evidence bar in
[CONTRIBUTING.md](../CONTRIBUTING.md#scope-discipline-and-feature-freeze).

## Release assets

The allowlist is enforced by `scripts/check-release-assets.sh` and permits only:

- `enki_<version>_<os>_<arch>.tar.gz` / `.zip`
- `checksums.txt`, `checksums.txt.sig`, `checksums.txt.pem`
- `enki.sbom.cdx.json`

Hosted service binaries are never published here. Legacy `enki-cloud` assets
were removed from `v0.3.0` and `v0.4.0`; see [open-core.md](open-core.md).

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

# 3. verify GitHub build provenance
gh attestation verify enki_<version>_linux_amd64.tar.gz \
  --repo yogenpoonudurai/enki
```

The certificate identity pins the signing workflow and tag; the OIDC issuer
proves it ran in GitHub Actions. The attestation binds the artifact digest to
the release workflow run. If any verification fails, do not install the
artifact.

## Manual local build

```bash
make build                 # enki and enki-mcp, version from tag or 0.5.2-dev
make cross                 # linux/darwin/windows × amd64/arm64
```

Reproducibility: builds use `-trimpath` and `CGO_ENABLED=0`; `SOURCE_DATE_EPOCH`
is not yet pinned, so bytes may differ across toolchains even though inputs are
identical.

## Release checklist

- [ ] Update `server.json` version and the MCP registry entry.
- [ ] `go test ./...` and `make cross` green.
- [ ] Tag pushed; workflow succeeded; signature and SBOM assets present.
- [ ] `scripts/check-release-assets.sh <tag>` passes.
- [ ] `cosign verify-blob` passes from a clean machine.
- [ ] `gh attestation verify <archive> --repo yogenpoonudurai/enki` passes.
- [ ] Release notes list breaking changes and new rules.
