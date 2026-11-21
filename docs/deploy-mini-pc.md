> **Deferred surface.** The hosted service is not part of the default release
> or public install path. This guide is retained for maintainers working on it.

# Deploy enki-cloud / hosted triage on a mini PC

This is optional. The CI gate runs entirely on GitHub runners; the mini PC is
for **hosted AI triage, the remote MCP endpoint, and the waitlist**.

## What runs where

| Component | Where |
|---|---|
| `enki scan` / fixes / SBOM / skills | Developer machines + CI runners |
| `enki-cloud` (triage API + `/mcp` + waitlist) | Mini PC |
| Model (Ollama / vLLM / DeepSeek API) | Mini PC (recommended) or external API |
| CI triage calls | GitHub runner → public HTTPS → mini PC |

## 1. Prepare the host

- Docker + Docker Compose.
- A domain (optional but recommended) pointing at the mini PC for TLS.
- Firewall: allow 443 only; keep 8080 on loopback.
- Do not expose the admin key or provider key to clients.

## 2. Start the service

```bash
cd scanner
export ENKI_CLOUD_ADMIN_KEY="$(openssl rand -hex 32)"
export DEEPSEEK_API_KEY="..."            # or leave empty for self-hosted only
export ENKI_AI_PROVIDER=openai
export ENKI_AI_BASE_URL="http://host.docker.internal:11434/v1"  # Ollama example
export ENKI_AI_MODEL="llama3.2"
export ENKI_RETENTION_HOURS=24

docker compose up -d --build
curl -s localhost:8080/healthz
```

Prefer a self-hosted model (Ollama, vLLM with DeepSeek V4 MIT weights) so
findings never leave your network. DeepSeek's hosted API stores data in the
PRC; only use it with explicit consent.

## 3. Put HTTPS in front

Use Caddy (automatic TLS) on the same host:

```caddyfile
cloud.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Or Tailscale Funnel if you do not want a public IP. MCP clients and the
registry require a public `https://…/mcp` URL.

## 4. Mint tokens and test

```bash
# free token (3 lifetime triages)
curl -s -X POST https://cloud.example.com/v1/admin/tokens \
  -H "Authorization: Bearer $ENKI_CLOUD_ADMIN_KEY" \
  -d '{"plan":"free"}'

# triage an existing report (consent required)
curl -s -X POST https://cloud.example.com/v1/triage \
  -H "Authorization: Bearer enki_..." \
  -H "Content-Type: application/json" \
  -d "{\"consent\":true,\"report\":$(cat report.json)}"

# usage / data deletion
curl -s https://cloud.example.com/v1/usage -H "Authorization: Bearer enki_..."
curl -s -X POST https://cloud.example.com/v1/data/delete -H "Authorization: Bearer enki_..."
```

Remote MCP endpoint for agents: `https://cloud.example.com/mcp` with
`Authorization: Bearer enki_...` and optional `X-Enki-Provider-Key` (BYOK, no
credits consumed). Update `server.json` with this URL before registry
submission.

## 5. Waitlist (deferred)

The public waitlist form was removed from `site/` while hosted surfaces are
deferred. The cloud store still implements `/v1/waitlist` for maintainer
testing; do not re-add a public form or endpoint promotion without approval.

## 6. CI triage (optional)

Keep the blocking gate offline. For advisory triage from CI, call the API with
a token stored in GitHub secrets:

```yaml
- run: enki scan --json --fail-on none > report.json
- run: |
    jq -n --slurpfile r report.json '{consent:true, report:$r[0]}' > body.json
    curl -s https://cloud.example.com/v1/triage \
      -H "Authorization: Bearer ${{ secrets.ENKI_CLOUD_TOKEN }}" \
      -H "Content-Type: application/json" \
      --data-binary @body.json
```

## 7. Security checklist

- [ ] HTTPS only; 8080 bound to loopback.
- [ ] Admin key and provider keys in a secret store, not in the image.
- [ ] Tokens have the minimum plan/credits; rotate on offboarding.
- [ ] Retention matches policy (default 24 h); `/v1/data/delete` documented.
- [ ] Logs contain no finding payloads or secrets.
- [ ] Rate limiting at the proxy (Caddy/Traefik) before public signups.
- [ ] Backups: the beta store is in-memory; move to Postgres before relying on
      history/tokens across restarts.
- [ ] Update regularly: image rebuild + `docker compose up -d`.

## 8. What still needs work before a real beta

- Postgres-backed tokens/audit/cache (survives restarts).
- Proxy-level rate limiting and abuse detection.
- A dashboard for usage/credits (Stripe checkout API is already implemented).
- Uptime monitoring and log retention.
