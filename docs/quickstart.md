# Quickstart: enki on macOS, Linux, and Windows

This guide gets you from zero to a scan, a readable report, and a reversible fix.
Everything below is free: deterministic scanning, the TUI, fixes/undo, SBOM,
local MCP, and AI triage with your own key (BYOK). No account or hosted service
is required.

## Install

Pick your platform. `VERSION` below is the release you are installing; replace
it with the current tag if a newer release exists.

### macOS (Apple Silicon or Intel, macOS 11+)

```bash
VERSION=0.3.0
BASE="https://github.com/yogenpoonudurai/enki/releases/download/v${VERSION}"

# Apple Silicon; use darwin_amd64 for Intel
curl -fLO "$BASE/enki_${VERSION}_darwin_arm64.tar.gz"
curl -fLO "$BASE/checksums.txt"
grep "enki_${VERSION}_darwin_arm64.tar.gz\$" checksums.txt > enki.sha256
shasum -a 256 -c enki.sha256

tar xzf "enki_${VERSION}_darwin_arm64.tar.gz"
mkdir -p ~/.local/bin
mv enki enki-mcp ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.zshrc to persist
enki version
```

The binary is not notarized. If Gatekeeper blocks it, open System Settings →
Privacy & Security → “Open Anyway”, or (only after the checksum passes)
`xattr -d com.apple.quarantine ~/.local/bin/enki`.

### Linux (amd64 or arm64)

```bash
VERSION=0.3.0
BASE="https://github.com/yogenpoonudurai/enki/releases/download/v${VERSION}"

# amd64; use linux_arm64 for ARM
curl -fLO "$BASE/enki_${VERSION}_linux_amd64.tar.gz"
curl -fLO "$BASE/checksums.txt"
grep "enki_${VERSION}_linux_amd64.tar.gz\$" checksums.txt > enki.sha256
sha256sum -c enki.sha256

tar xzf "enki_${VERSION}_linux_amd64.tar.gz"
mkdir -p ~/.local/bin
mv enki enki-mcp ~/.local/bin/
export PATH="$HOME/.local/bin:$PATH"   # add to ~/.bashrc or ~/.zshrc
enki version
```

`sudo` is only needed for full process attribution and OS package CVEs.
Unsupported distros (Arch, Fedora, CentOS Stream) report an explicit coverage
gap instead of claiming “clean”.

### Windows (10 1809+ / 11, amd64 or arm64)

Use Windows Terminal for the TUI. In PowerShell:

```powershell
$Version = "0.3.0"
$Base = "https://github.com/yogenpoonudurai/enki/releases/download/v$Version"

Invoke-WebRequest "$Base/enki_${Version}_windows_amd64.zip" -OutFile enki.zip
Invoke-WebRequest "$Base/checksums.txt" -OutFile checksums.txt
(Get-FileHash .\enki.zip -Algorithm SHA256).Hash
Select-String -Path .\checksums.txt -Pattern "enki_${Version}_windows_amd64"
# compare the two hashes, then:
Expand-Archive .\enki.zip -DestinationPath .\enki
Unblock-File .\enki\enki.exe
Unblock-File .\enki\enki-mcp.exe
New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\enki\bin" | Out-Null
Move-Item .\enki\enki.exe, .\enki\enki-mcp.exe "$env:LOCALAPPDATA\enki\bin\"
setx PATH "$env:PATH;$env:LOCALAPPDATA\enki\bin"
```

Open a new terminal and run `enki version`.

### Any platform with Go 1.27+

```bash
go install github.com/yogenpoonudurai/enki/cmd/enki@latest
# optional local MCP server:
go install github.com/yogenpoonudurai/enki/cmd/enki-mcp@latest
```

To track the latest `main` instead of a release:

```bash
git clone https://github.com/yogenpoonudurai/enki.git
cd enki
make build
export PATH="$PWD/bin:$PATH"
enki version
```

## Golden path

Run these from the project or machine you want to check:

```bash
enki scan --json > enki-report.json   # deterministic findings
enki report enki-report.json          # readable ASCII report
enki fix                              # preview the fix plan
enki fix --apply                      # apply SAFE fixes
enki undo                             # restore the last change
```

- `enki` alone opens the interactive dashboard when run in a terminal; when
  piped, it prints the plain scan.
- Exit codes: `0` clean/below threshold, `1` findings at/above `--fail-on`
  (default `high`), `2` error. Exit `1` is the CI gate, not a crash.
- `fix` is a dry run. `fix --apply` applies only SAFE actions (file
  permissions); config edits require `--include-moderate` and confirmation.
- Every applied change is backed up under the user state directory and can be
  reverted with `enki undo` (or `enki undo N`).

A finding includes rule ID, severity, confidence, location, redacted evidence,
and remediation. A coverage gap means “unknown”, never “clean”.

## CI

```bash
enki scan --sarif --fail-on high > enki.sarif
```

The composite GitHub Action uploads SARIF and the ASCII report:

```yaml
- uses: actions/checkout@v4
- uses: yogenpoonudurai/enki@v0.3.0   # use the current release tag
  with:
    args: "--fail-on high"
```

See [ci-quickstart.md](ci-quickstart.md) for a complete workflow.

## Optional: AI triage with your own key (BYOK)

BYOK is free; enki calls your provider directly. The payload is redacted and
the model can only rank existing findings.

```bash
enki scan --json --fail-on none > report.json

# DeepSeek
export DEEPSEEK_API_KEY=...
enki triage report.json

# Local OpenAI-compatible model (no key required)
ENKI_AI_PROVIDER=ollama ENKI_AI_MODEL=qwen2.5:1.5b \
  enki triage report.json
```

Windows PowerShell:

```powershell
enki scan --json --fail-on none > report.json
$env:DEEPSEEK_API_KEY = "..."
enki triage report.json
```

Advanced triage (readable fix plan, choosing verified fixes to apply) is
documented in [ai-triage.md](ai-triage.md).

## Other checks

```bash
enki sbom -o bom.json     # CycloneDX 1.5 dependency inventory
enki doctor               # OS, privileges, firewall/package tools
enki rules list           # built-in rule catalog
```

Local agent integration (MCP server and skill) is optional and documented in
[ai-triage.md](ai-triage.md); hosted/remote MCP is a paid surface.

## Verify the download

```bash
# Linux (macOS: shasum, Windows: Get-FileHash)
grep "enki_${VERSION}_linux_amd64.tar.gz\$" checksums.txt > enki.sha256
sha256sum -c enki.sha256

# optional: verify the signed checksums
VERSION=0.3.0
BASE="https://github.com/yogenpoonudurai/enki/releases/download/v${VERSION}"
curl -fLO "$BASE/checksums.txt.pem"
curl -fLO "$BASE/checksums.txt.sig"
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/yogenpoonudurai/enki/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `command not found` | Add the install directory to `PATH`, open a new shell |
| macOS “cannot be opened” | Privacy & Security → Open Anyway after checksum verification |
| Windows SmartScreen | `Unblock-File` on the executables, or run from Windows Terminal |
| TUI shows the small wordmark | Enlarge the terminal window |
| Braille shows as boxes | Use Windows Terminal or a braille-capable font |
| Listeners could not be attributed | Rerun with `sudo`/Administrator for full coverage |
| `osv.dev unreachable … unknown` | Allow `api.osv.dev`, `www.cisa.gov`, `api.first.org`, or accept the gap |
| No OS package CVEs on Arch/Fedora | Unsupported by OSV; inventory-only gap |

## Free vs paid

Free forever: all 23 checks, TUI, plain/JSON/SARIF/OCSF reports, fix/undo,
SBOM, local MCP, and BYOK triage. Paid/hosted: triage beyond the free quota,
remote MCP, scan history/dashboard, SSO/policy/audit export, premium
rule/compliance packs, fleet/MDM, and enterprise self-host support. Details:
[ai-triage.md](ai-triage.md) and [marketing.md](marketing.md).

Full data sources: [data-sources.md](data-sources.md).
