# Probing ethics and safety

enki is designed to answer "is my own machine's AI stack exposed?" — not to
scan networks.

Hard rules implemented in the endpoint module:

1. **Loopback first.** Services bound to loopback or wildcard addresses are
   probed via `127.0.0.1`. Services bound to a specific address are probed only
   with `--probe-remote`, and only for RFC1918/loopback/link-local addresses.
   Public addresses are never probed.
2. **Read-only.** The scanner issues a single `GET` per fingerprint path and
   inspects response headers/bodies. It never authenticates, never writes, and
   never sends exploit payloads.
3. **Bounded.** 2 second timeout per request, redirects disabled, response
   bodies capped at 64 KiB, bounded concurrency.
4. **Identifiable.** Requests carry `User-Agent: enki/0.1 (AI-SPM scanner)`.
5. **Conservative severity.** A CRITICAL exposure requires a positive service
   fingerprint **and** a successful unauthenticated response. Process-only
   matches are downgraded and marked with lower confidence.

If you run enki in an environment where active testing requires authorization,
treat `--probe-remote` as active testing and obtain approval first.

## Remediation safety

- Dry-run by default; no changes without `--apply`.
- SAFE: `chmod 0600` on secret-bearing files (owner-only).
- MODERATE: comment-preserving removal of dangerous settings
  (`permissions.defaultMode`, `dangerouslySkipPermissions`); backup + atomic
  write + parse-back validation.
- RISKY: firewall commands are printed, never executed by enki.
- Undo: every change is recorded in `$XDG_STATE_HOME/enki/state.jsonl` and the
  backup lives in `$XDG_STATE_HOME/enki/backups/`.
