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
4. **Identifiable.** Requests carry `User-Agent: enki/0.1 (AI configuration/exposure scanner)`.
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

Fixes are guarded by content fingerprints captured at scan time. A fix refuses
to run when the target file changed after the scan, so a stale report cannot
overwrite newer edits. Paths are symlink-resolved and refused when they land in
`~/.ssh`, `~/.aws`, `~/.gnupg`, or `~/.config/gcloud`; file ownership and mode
are preserved.

Every mutation is journaled before it starts and committed after it succeeds.
An interrupted operation is reconciled on the next run, and concurrent
`enki fix`/`enki undo` processes serialize on a state-directory lock.

- Undo: every change is recorded in `$XDG_STATE_HOME/enki/state.jsonl` and the
  backup lives in `$XDG_STATE_HOME/enki/backups/` (directory `0700`, backups
  `0600`). Undo refuses to overwrite a file edited after the fix; use
  `enki undo --force` only when you intend to discard those newer edits.
