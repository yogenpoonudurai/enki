# Hosted triage and paid editions

The enki scanner is Apache-2.0 and fully functional offline. The hosted
service is a separate paid product: it runs outside this repository, and its
code, store, billing, and premium feeds are not shipped in the open-source
binary.

**Local detection is never gated.** Scanning, findings, remediation, fix/undo,
SBOM export, reports, local MCP, and BYOK triage are free with no account, no
quota, and no telemetry.

## Editions

| Edition | Included |
|---|---|
| Open source | Full scanner, TUI, fix/undo, SBOM, reports, local MCP, skills, BYOK triage. Apache-2.0. |
| Pro | 300 hosted triages per month, CI history, hosted MCP endpoint. |
| Team | 1,000 pooled credits, SSO, team policy, 90-day history. |
| Enterprise | Self-hosted model gateway, DPA, SLA, premium feeds. |

Pricing is planned and subject to change. This page is the canonical editions
and pricing reference for the public repository.

## Hosted triage

The CLI builds the same redacted payload used for BYOK and uploads only that
payload. The service returns a validated ranking and your plan/allowance.

```sh
export ENKI_CLOUD_URL="https://<your-hosted-endpoint>"
export ENKI_CLOUD_TOKEN="enki_..."

enki account                                   # plan and remaining triages
enki triage --hosted --consent enki-report.json
```

- `--consent` is required: it confirms that a redacted findings payload may be
  sent to the hosted service.
- `--show-payload` prints exactly what is uploaded. The payload contains
  finding metadata, coverage gaps, and this machine's diagnostics; file
  contents, absolute paths, and secrets are redacted before upload.
- `--key sk-...` forwards your own provider key (`X-Enki-Provider-Key`) and
  does not consume hosted credits.
- `--hosted-url` overrides `ENKI_CLOUD_URL` for one command.

The full report is never uploaded. The old server-side redaction path is gone:
if the payload is not safe to send, it is not sent.

## Entitlements

Paid access is enforced by the hosted service, not by license files in the
binary:

- The service authenticates the token and returns the plan, remaining
  allowance, and organization.
- Credits and quotas are consumed server-side; a 402 response carries the
  upgrade hint and current usage.
- The client never displays the provider cost of server-key calls.
- There are no offline license keys and no local feature flags to bypass.

Hosted MCP, scan history, team policy, SSO, audit export, and premium data
feeds are delivered by the service. They are not present in the open-source
tree.

## Data handling

- Upload is opt-in per command via `--consent`; nothing is sent by scanning,
  reporting, fixing, SBOM generation, or local MCP.
- Only the redacted payload is transmitted, over HTTPS, to the configured
  endpoint.
- The service keeps the payload for a bounded retention window (24 hours by
  default) and stores audit metadata (token, plan, action, finding count, and
  cost) without finding content.
- A token's stored data can be removed through the service's deletion
  endpoint.
- Billing is processed by Stripe. BYOK keys are forwarded per request, not
  stored as account credentials.

See [legal/privacy.md](legal/privacy.md) and [legal/terms.md](legal/terms.md).
Those drafts are not legal advice and require review before taking payment.

## Support and security

- Questions and billing: open an issue in the public repository or use the
  support address on the service site.
- Vulnerabilities: [Security policy](../SECURITY.md). Do not open a public
  issue for a security problem.
