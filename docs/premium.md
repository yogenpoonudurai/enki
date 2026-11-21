# Hosted service

Hosted triage, hosted MCP, scan history, team policy, and SSO are a separate
paid product. The open-source CLI includes the client; local scanning,
remediation, SBOM export, local MCP, and BYOK triage are never gated.

```sh
export ENKI_CLOUD_URL="https://<your-hosted-endpoint>"
export ENKI_CLOUD_TOKEN="enki_..."
enki triage --hosted --consent report.json
enki account
```

`--consent` is required, and only the locally redacted payload is uploaded.
`--key sk-...` forwards your own provider key without spending credits.

Plans, pricing, and hosted data-handling details are published with the
service. Legal terms: [legal/terms.md](legal/terms.md); privacy:
[legal/privacy.md](legal/privacy.md).

The service implementation, billing, store, and premium feeds are not part of
this repository.
