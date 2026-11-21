# Security policy

enki is a security tool, so we hold it to the standards it checks for.

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub Security Advisories
(“Report a vulnerability” on the repository Security tab). Do not open a public
issue for security problems.

Include: affected version, platform, reproduction steps, and impact. We aim to
acknowledge within 72 hours, provide a triage decision within 7 days, and
coordinate disclosure within 90 days.

## Supported versions

Security fixes are provided for the latest minor release line. Development
snapshots (`0.5.0-dev`) are unsupported.

## Scope

In scope: the CLI, TUI, MCP server (`enki-mcp`), skills/plugin packaging,
remediation engine, and release artifacts. The hosted service is a separate
product; reports about it go through the same private advisory channel and are
handled by the same maintainers.

Out of scope: findings about the user's machine that enki correctly reports;
misconfiguration of third-party model providers; attacks requiring the
ability to modify enki's binary or its state directory.

## Design commitments

- No telemetry by default; nothing is sent anywhere without an explicit
  command and consent flag.
- Secrets are redacted in every output; reports never contain raw credentials.
- AI triage payloads exclude file contents, absolute paths, and secrets.
- The model can only rank and explain; it cannot execute fixes.
- Remediation is dry-run by default, backed up, audited, and reversible.
- Probing is loopback-only by default; `--probe-remote` is active testing.

## Release integrity

Release artifacts are built with `CGO_ENABLED=0` via goreleaser from tagged
commits. `checksums.txt` is signed with cosign keyless (GitHub OIDC) and
published with each release; verification steps are in
[docs/release.md](docs/release.md).
