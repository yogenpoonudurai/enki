# Governance

## Model

enki is maintainer-led. The maintainer holds final decision authority (a
benevolent dictator model) and is accountable for the scope, quality, release,
and security of the open-source project.

## Roles

- **Maintainer** — reviews and merges changes, cuts releases, owns security
  response, and decides scope. Current maintainer: @yogenpoonudurai.
- **Contributor** — anyone who opens an issue, improves docs, reports a bug, or
  submits a pull request under the DCO.

Additional maintainers may be added by the current maintainer when a
contributor has demonstrated sustained, high-quality work and good judgment.
The private hosted-service repository is not part of this governance; access to
it is granted separately and is not implied by maintainer status here.

## Decisions

- Bug fixes, documentation, and new detectors that meet the evidence bar in
  [CONTRIBUTING.md](CONTRIBUTING.md) proceed by lazy consensus: a pull request
  with passing CI and no unresolved objection from the maintainer.
- Changes that expand scope, add a module, change output contracts, or affect
  the paid boundary require an issue first and explicit maintainer approval.
- Security decisions follow [SECURITY.md](SECURITY.md) and may be handled
  privately.
- The maintainer may decline changes that conflict with the project's stated
  non-goals, even when they are well implemented.

## Releases

Releases are tagged from `main`, built by goreleaser, and signed with cosign
keyless. The process and verification steps are in
[docs/release.md](docs/release.md). The hosted service is released separately
from a private repository.

## Open-core boundary

The open-source project is Apache-2.0 and fully functional offline. The hosted
service, premium feeds, and team/compliance features are a separate paid
product. They are not part of this repository, community contributions are not
accepted for them, and their existence does not gate any local detection or
remediation feature.

## Changes to this document

Changes are proposed by pull request and approved by the maintainer.
