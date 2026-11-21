# Open-core boundary

enki is open core. The public repository is the Apache-2.0 scanner and its
integration surface. The hosted service and premium delivery features live in a
separate private repository and are not part of the default release.

## Public repository (Apache-2.0)

- CLI, TUI, scan modules, rule catalog, and detection benchmark
- Local remediation (`fix`/`undo`) and its state journal
- Local MCP server, agent skill, and plugin manifests
- SBOM export, JSON, SARIF, OCSF, and plain/ASCII reports
- The hosted **client seam**:
  - `internal/hosted` (HTTP client for the hosted triage API)
  - `cmd/enki/account.go` (`enki account`)
  - `docs/premium.md` (public contract and plan overview)
- Documentation, legal pages, governance, and community files

The client seam exists so the open-source CLI can use the paid service. It does
not include service implementation, billing, storage, or entitlement logic.

## Private repository

- Hosted triage service and API implementation
- Store, billing, Stripe integration, and quota enforcement
- Hosted MCP endpoint, team policy, SSO, audit export, and scan history
- Premium feeds and hosted deployment/operations

The private service consumes the same public client contract. Changes to the
contract should remain backward compatible across at least one minor release.
Breaking changes require a new API version.

## Release artifacts

The public release workflow publishes only:

- `enki_<version>_<os>_<arch>.tar.gz` / `.zip`
- `checksums.txt`, `checksums.txt.sig`, `checksums.txt.pem`
- `enki.sbom.cdx.json`

Hosted service binaries are never built, signed, or uploaded by this
repository. `scripts/check-public-boundary.sh` guards the tree and
`scripts/check-release-assets.sh` guards each release. Releases from before
PR #21 may have included legacy `enki-cloud` assets; those assets were removed
on 2026-11-22. The source from those commits remains in public Git history
under Apache-2.0, and removing code from the current tree does not retract
copies already distributed.

## Contributions

- Do not add hosted service, billing, entitlement, or premium-feed
  implementation to this repository.
- Client-seam changes are welcome; call out any contract or compatibility
  impact in the pull request.
- Detection changes must follow the evidence bar in
  [CONTRIBUTING.md](../CONTRIBUTING.md#scope-discipline-and-feature-freeze).

## Security

Report vulnerabilities through the private advisory channel described in
[SECURITY.md](../SECURITY.md). Do not open a public issue for a security
problem.
