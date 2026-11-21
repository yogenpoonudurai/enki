# Case study: a GPU inference server

*Illustrative scenario. Commands are real; adjust paths and units to your
deployment.*

## The setup

A platform team runs one Ubuntu 22.04 GPU host:

- vLLM on `:8000` behind a planned reverse proxy (not yet deployed)
- Ollama on `:11434` for quick experiments
- Jupyter on `:8888` for notebook access
- Python and system packages installed over months of iteration
- operators with SSH access; no central vulnerability feed

The host is reachable only on a private subnet — but "private" spans several
teams, laptops, and CI runners.

## First scan, honestly

```bash
sudo enki scan --deps all --json > gpu-scan.json
```

`sudo` matters: without it, listeners and processes owned by other users show
up as coverage gaps rather than attributions.

Representative findings:

```
CRITICAL AEP-001  vLLM exposed on 0.0.0.0:8000
CRITICAL AEP-001  Ollama exposed on 0.0.0.0:11434
HIGH     AEP-004  Jupyter API reachable without a token
MEDIUM   AEP-002  Local AI service reflects arbitrary CORS origins
HIGH     SBOM-001 torch 2.0.1 affected by GHSA-53q9-r3pm-6pq6 (CVE-2025-32434)
HIGH     SBOM-001 langchain 0.1.0 affected by GHSA-3644-q5cj-c5c7
MEDIUM   SBOM-001 40+ OS package advisories mapped to Debian:12
```

Two things stand out. First, "it's only on the private network" is doing a lot
of work: inference endpoints without auth are an internal lateral-movement
target, not just an internet one. Second, the Python environment accumulated
CVEs that the container scanner never saw because these services run directly
on the host.

## Responding without breaking inference

The remediation plan is deliberately explicit:

```bash
enki fix
```

```
[1] RISKY  Bind vLLM to 127.0.0.1 or block inbound TCP/8000
           run: sudo ufw deny 8000/tcp
[2] RISKY  Bind Ollama to 127.0.0.1 or block inbound TCP/11434
           run: sudo ufw deny 11434/tcp
[3] RISKY  Enable Jupyter token authentication or bind to 127.0.0.1
```

enki never applies these itself. The team's change process:

1. **Change request** referencing the finding IDs and the exact command.
2. **Rebind first** (preferred over firewall): set `--host 127.0.0.1` in the
   systemd unit, enable the authenticated reverse proxy, reload.
3. **Firewall only as a backstop**, applied during a maintenance window, with a
   rollback (`ufw delete deny 11434/tcp`).
4. **Rotate** any keys that lived in `.env` files on the host.
5. **Upgrade** the flagged packages; re-run the scan to confirm.

After the rebind, re-running the scan shows the endpoint findings gone, while
the dependency findings remain until upgrades land — exactly the separation of
concerns you want during a change window.

## Continuous operation

Nightly timer (systemd):

```ini
# /etc/systemd/system/enki-scan.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/enki scan --deps all --json --fail-on none \
  --report /var/log/enki/report.txt > /var/log/enki/report.json
```

```ini
# /etc/systemd/system/enki-scan.timer
[Timer]
OnCalendar=*-*-* 03:00
Persistent=true

[Install]
WantedBy=timers.target
```

SIEM handoff — emit OCSF Detection Findings and ship to the collector:

```bash
enki scan --ocsf > /var/log/enki/findings.ocsf.json
```

SBOM retention (CycloneDX) for audits:

```bash
enki sbom -o /var/lib/enki/sbom-$(date +%F).cdx.json
```

`--probe-remote` is **not** used here: the host scans from inside, and remote
probing is active testing that needs authorization. The team documents
coverage gaps (unsupported distro, unprivileged attribution) rather than
treating them as clean.

## What changed

- Inference services bind to loopback and sit behind an authenticated gateway.
- Jupyter requires a token.
- The dependency upgrade path is now a recurring task with a feed, not a
  once-a-year project.
- The SIEM receives structured findings; the ASCII report is attached to
  change tickets.
- Nobody has to run a kernel agent or open an outbound control-plane connection.

## Takeaway

For servers, the value is not a prettier vulnerability list — it is a
deterministic, explainable gate plus a remediation workflow that fits change
control. enki reports exactly what it verified, what it could not see, and which
actions require a human.
