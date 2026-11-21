# Privacy policy — hosted service

> **Draft — not legal advice.** Replace placeholders and have counsel review
> before use. Effective: [EFFECTIVE DATE].

This policy describes how [LEGAL ENTITY] (“we”) processes personal data for the
hosted enki service (the “Service”). The open-source scanner runs locally and
sends no telemetry.

## 1. Controller and contact

Controller: [LEGAL ENTITY], [ADDRESS]. Contact: [CONTACT EMAIL].

## 2. Data we process

- **Account and token metadata** — token identifier, plan, organization,
  remaining allowance, creation time.
- **Billing data** — handled by Stripe; we receive subscription status,
  customer identifiers, and invoice status, not full payment-card numbers.
- **Hosted triage payload** — only when a user runs `enki triage --hosted`
  with `--consent`. The payload is built locally and contains redacted finding
  metadata, coverage gaps, and machine diagnostics (OS, tools, privileges,
  container status). File contents, absolute paths, and secrets are redacted
  before upload.
- **Audit metadata** — token, plan, action, finding count, model cost, and
  timestamp. Audit events do not contain finding content.
- **Support communications** — what you send us when you ask for help.
- **Service logs** — request metadata needed to operate and secure the Service.

## 3. What we do not collect

- No telemetry from scans, reports, fixes, SBOM generation, or local MCP.
- No local files, shell history, or machine identifiers unless they appear in
  the redacted payload you explicitly consent to upload.
- No model-provider keys as account credentials. A BYOK key is forwarded per
  request and is not stored as part of your account.

## 4. Purposes and legal bases

We process data to provide the Service (contract), secure it and prevent abuse
(legitimate interests), comply with law (legal obligation), and communicate
with you (contract or consent). Where consent is required, you can withdraw it
by not sending further requests.

## 5. Retention

- Triage payloads: 24 hours by default, or the retention window configured for
  the deployment.
- Audit metadata: [RETENTION].
- Billing records: as required by tax and accounting law.
- Support messages: as long as needed to resolve the request.

## 6. Subprocessors

| Provider | Purpose |
|---|---|
| Stripe | Billing and subscription management |
| [LLM PROVIDER] | Model inference for hosted triage |
| [HOSTING PROVIDER] | Infrastructure and storage |

A current list is available on request. Where data is transferred outside your
region, we rely on appropriate safeguards such as standard contractual clauses.

## 7. Security

We use encryption in transit, token authentication, least-privilege access, and
bounded retention. No system is perfectly secure; report suspected issues per
[SECURITY.md](../../SECURITY.md).

## 8. Your rights

Depending on your jurisdiction, you may request access, correction, deletion,
restriction, portability, or object to processing, and lodge a complaint with a
supervisory authority. Use [CONTACT EMAIL] or the Service's deletion endpoint.
We may need to verify your identity.

## 9. Children

The Service is not directed to children under 16.

## 10. Changes

We will post updates with a new effective date and, for material changes,
provide reasonable notice.

## 11. Contact

[CONTACT EMAIL]
