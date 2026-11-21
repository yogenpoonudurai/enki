# Add enki to a GitHub CI pipeline

The scanner runs on the GitHub runner. No server, account, or mini PC is
required for the gate itself.

## 0. Publish enki (once)

The composite action lives in the enki repository, so GitHub runners must be
able to fetch it:

1. Push this repository to GitHub (public is simplest).
2. Tag a release so the action is pinned and signed:
   ```bash
   git tag v0.3.0
   git push origin v0.3.0
   ```
   `.github/workflows/release.yml` builds and signs the binaries.

If you cannot publish yet, reference a branch or commit instead of a tag:
`uses: <owner>/enki@main` (less reproducible — pin a SHA for stability).

## 1. Add the workflow to your application repo

Copy [`docs/examples/enki-workflow.yml`](examples/enki-workflow.yml) to
`.github/workflows/enki.yml` and replace `<owner>`.

The fast PR gate uses only offline modules — no OSV network dependency:

```yaml
- uses: <owner>/enki@v0.3.0
  with:
    args: "--fail-on high --deps ai --modules mcp,secrets,agent-permissions"
```

What it provides:

- fails the job (exit 1) when findings meet the threshold; runtime errors
  (exit 2) always fail
- uploads `enki.sarif` and `enki-report.txt` as artifacts
- needs no secrets and sends nothing off the runner

## 2. Optional: SARIF in code scanning

Add after the enki step if the repo has code scanning enabled (free for public
repos; private repos need GitHub Code Security):

```yaml
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: enki.sarif
```

The artifact upload works regardless.

## 3. Nightly full scan

Dependency and Linux package checks call `api.osv.dev`, KEV, and EPSS. Run them
on a schedule, not on every PR:

```yaml
on:
  schedule: [{cron: "17 3 * * *"}]
  workflow_dispatch:
```

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.cache/enki
    key: enki-osv-${{ hashFiles('**/package-lock.json', '**/requirements*.txt') }}

- uses: <owner>/enki@v0.3.0
  with:
    args: "--fail-on critical --deps all"
```

The cache keeps OSV advisory details fresh within the 24 h TTL while cutting
API traffic.

## 4. Start conservative, then tighten

Suggested progression:

1. `--fail-on critical --modules mcp,secrets,agent-permissions` (noisy legacy repos)
2. `--fail-on high` for the AI/MCP/secret gate
3. `--deps all --fail-on high` in the nightly job
4. Suppress reviewed findings with `--ignore-rule RULE-ID` and a reason in the
   PR description; never suppress whole modules

Exit codes: `0` clean/below threshold, `1` threshold met, `2` error.

## 5. Private repositories

- The action repo must be readable by the runner (public, or same org with
  Actions access enabled).
- Alternatively install from a release asset or `go install` in a step:
  ```yaml
  - run: go install github.com/<owner>/enki/cmd/enki@v0.3.0
  - run: enki scan --sarif --report enki-report.txt --fail-on high > enki.sarif
  ```

## 6. Optional: AI triage in CI

Triage is not needed for the gate. If you want it:

- **Hosted service on your mini PC** (see
  [`deploy-mini-pc.md`](deploy-mini-pc.md)): call `POST /v1/triage` with a
  bearer token and the scan JSON, or use the remote MCP endpoint.
  GitHub-hosted runners need public HTTPS or a tunnel.
- **BYOK**: run `enki triage report.json` with `ENKI_AI_PROVIDER`,
  `ENKI_AI_BASE_URL`, and `ENKI_AI_KEY` from GitHub secrets. Prefer a
  self-hosted model gateway on the mini PC so findings never leave your
  network (requires a tunnel/VPN reachable from the runner).

Keep triage out of the blocking gate: it is advisory and adds latency/cost.

## Troubleshooting

| Symptom | Cause |
|---|---|
| "Resource not accessible by integration" on SARIF upload | Code scanning not enabled for the repo |
| Action cannot be found | Action repo private / tag missing |
| "osv.dev unreachable … unknown" | Runner egress blocked; allow `api.osv.dev`, `www.cisa.gov`, `api.first.org`, or keep the offline module set |
| Findings on legacy code | Start at `--fail-on critical`, then ratchet |
| Exit code 1 on a clean-looking PR | Lower the threshold or suppress the specific reviewed rule |
