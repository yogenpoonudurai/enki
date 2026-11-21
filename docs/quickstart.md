# Quickstart: free enki on macOS, Linux, and Windows

Everything in this guide is **free**: scanning, the TUI, fixes/undo, SBOM,
SARIF/OCSF/CycloneDX, agent skills, the local MCP server, and AI triage with
your own key (BYOK). No account, server, telemetry, or paid tier is required.

The only paid surfaces are hosted AI triage beyond the free quota, team/org
features, premium rule/compliance packs, and enterprise self-host support —
see [Free vs paid](#free-vs-paid).

## What you get

The CLI archive contains two binaries:

- `enki` — scanner + TUI + fix/undo + reports
- `enki-mcp` — local MCP server for Claude Code, Cursor, and other agents

`enki-cloud` is a separate optional service and is **not** needed here.

## macOS (Apple Silicon or Intel; macOS 11+)

1. Download the matching release (`arm64` = Apple Silicon, `amd64` = Intel):

   ```bash
   cd ~/Downloads
   curl -LO https://github.com/yogenpoonudurai/enki/releases/download/v0.3.0/enki_0.3.0_darwin_arm64.tar.gz
   # Intel:
   # curl -LO https://github.com/yogenpoonudurai/enki/releases/download/v0.3.0/enki_0.3.0_darwin_amd64.tar.gz

   curl -LO https://github.com/yogenpoonudurai/enki/releases/download/v0.3.0/checksums.txt
   shasum -a 256 -c checksums.txt --ignore-missing
   ```

2. Extract and install:

   ```bash
   tar xzf enki_0.3.0_darwin_arm64.tar.gz
   mkdir -p ~/.local/bin
   mv enki enki-mcp ~/.local/bin/
   export PATH="$HOME/.local/bin:$PATH"   # add to ~/.zshrc to persist
   ```

3. Gatekeeper: the binary is not notarized. If macOS blocks it, open
   System Settings → Privacy & Security → “Open Anyway”, or (only if the
   checksum above verified) `xattr -d com.apple.quarantine ~/.local/bin/enki`.
   Release checksums are cosign-signed (see [Verify](#verify-the-download)).

4. Verify:

   ```bash
   enki version
   enki scan
   ```

Alternative: `go install github.com/yogenpoonudurai/enki/cmd/enki@v0.3.0`
(also `cmd/enki-mcp`). Requires Go 1.27+.

## Linux (amd64 or arm64)

Static binary; no distro packages or runtime dependencies.

1. Download and verify:

   ```bash
   curl -LO https://github.com/yogenpoonudurai/enki/releases/download/v0.3.0/enki_0.3.0_linux_amd64.tar.gz
   # arm64:
   # curl -LO https://github.com/yogenpoonudurai/enki/releases/download/v0.3.0/enki_0.3.0_linux_arm64.tar.gz

   curl -LO https://github.com/yogenpoonudurai/enki/releases/download/v0.3.0/checksums.txt
   sha256sum -c checksums.txt --ignore-missing
   ```

2. Install:

   ```bash
   tar xzf enki_0.3.0_linux_amd64.tar.gz
   mkdir -p ~/.local/bin
   mv enki enki-mcp ~/.local/bin/
   export PATH="$HOME/.local/bin:$PATH"   # add to ~/.bashrc or ~/.zshrc
   ```

3. Verify:

   ```bash
   enki version && enki scan
   ```

Notes: `sudo` is only needed for full process attribution and OS package CVEs.
Unsupported distros (Arch, Fedora, CentOS Stream) show an explicit coverage gap
instead of claiming “clean”.

## Windows (10 1809+ / 11, amd64 or arm64)

Use **Windows Terminal** for the TUI (ANSI + braille support).

1. Download and verify in PowerShell:

   ```powershell
   cd $env:USERPROFILE\Downloads
   Invoke-WebRequest -Uri "https://github.com/yogenpoonudurai/enki/releases/download/v0.3.0/enki_0.3.0_windows_amd64.zip" -OutFile enki.zip
   Invoke-WebRequest -Uri "https://github.com/yogenpoonudurai/enki/releases/download/v0.3.0/checksums.txt" -OutFile checksums.txt

   Get-FileHash .\enki.zip -Algorithm SHA256
   Select-String -Path .\checksums.txt -Pattern "enki_0.3.0_windows_amd64"
   # compare the two hashes
   ```

   arm64: use `enki_0.3.0_windows_arm64.zip`.

2. Extract, unblock, and install:

   ```powershell
   Expand-Archive .\enki.zip -DestinationPath .\enki
   Unblock-File .\enki\enki.exe
   Unblock-File .\enki\enki-mcp.exe

   New-Item -ItemType Directory -Force "$env:LOCALAPPDATA\enki\bin" | Out-Null
   Move-Item .\enki\enki.exe, .\enki\enki-mcp.exe "$env:LOCALAPPDATA\enki\bin\"
   setx PATH "$env:PATH;$env:LOCALAPPDATA\enki\bin"
   ```

3. Open a new terminal and verify:

   ```powershell
   enki version
   enki scan
   ```

Alternative: `go install github.com/yogenpoonudurai/enki/cmd/enki@v0.3.0`.

## First scan

```bash
enki scan                 # plain output, exit 1 if findings >= high
enki scan --json          # machine-readable
enki                      # interactive dashboard (needs a real terminal)
```

Exit codes: `0` clean/below threshold, `1` threshold met, `2` error. Use
`--fail-on` to tune (`critical|high|medium|low|info|none`).

Read a finding: rule ID, severity, confidence, location, redacted evidence,
and remediation. Coverage gaps mean “unknown”, never “clean”.

## Fix and undo (free)

```bash
enki fix                         # dry run
enki fix --apply                 # SAFE actions (permissions)
enki fix --apply --include-moderate   # config edits, asks before each
enki undo                        # byte-identical restore
```

In the TUI: `f` → `1-9` to apply, `y` to confirm a config edit, `a` for safe
actions, `u` to undo. RISKY actions (firewall) are printed, never executed.

## SBOM (free)

```bash
enki sbom -o bom.json            # CycloneDX 1.5
enki sbom --vulns                # adds OSV advisories (network)
```

## Free AI triage with your own key (BYOK)

BYOK is free forever — it uses your provider key, so there is no hosted cost.

macOS/Linux:

```bash
enki scan --json > report.json

export DEEPSEEK_API_KEY=...
# or any OpenAI-compatible endpoint:
export ENKI_AI_PROVIDER=openai
export ENKI_AI_BASE_URL=http://127.0.0.1:8000/v1
export ENKI_AI_KEY=optional
export ENKI_AI_MODEL=deepseek-v4

enki triage report.json
```

Windows PowerShell:

```powershell
enki scan --json > report.json
$env:DEEPSEEK_API_KEY = "..."
# or:
$env:ENKI_AI_PROVIDER = "openai"
$env:ENKI_AI_BASE_URL = "http://127.0.0.1:8000/v1"
$env:ENKI_AI_KEY = "optional"
$env:ENKI_AI_MODEL = "deepseek-v4"
enki triage report.json
```

The payload is redacted (no paths, secrets, or file contents) and includes
local system diagnostics so fix steps fit the machine. Suggestions are
advisory; the deterministic fix engine is the only thing that writes.

## Agent integration (free)

Local MCP server (stdio) — add to your client config:

```json
{"mcpServers": {"enki": {"command": "enki-mcp", "args": []}}}
```

Skill install locations:

| Client | macOS/Linux | Windows |
|---|---|---|
| Claude Code | `~/.claude/skills/enki` | `%USERPROFILE%\.claude\skills\enki` |
| Cursor | `.cursor/skills/enki` (project) | `.cursor\skills\enki` |

Remote MCP (`/mcp`) belongs to the optional hosted service; it is not part of
the free local tool.

## Verify the download

```bash
# checksum (all platforms; use Get-FileHash on Windows)
sha256sum -c checksums.txt --ignore-missing

# optional: verify the signed checksums (needs cosign)
cosign verify-blob checksums.txt \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp '^https://github\.com/yogenpoonudurai/enki/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `command not found` | Add the install dir to `PATH`, open a new shell |
| macOS “cannot be opened” | Privacy & Security → Open Anyway (after checksum verification) |
| Windows SmartScreen | `Unblock-File` on the `.exe`, or run from Windows Terminal |
| TUI shows the small wordmark instead of artwork | Terminal shorter than 27 rows; enlarge the window |
| Braille looks like boxes | Use Windows Terminal / a font with braille support |
| “listeners could not be attributed” | Rerun with `sudo`/Administrator for full coverage |
| “osv.dev unreachable … unknown” | Allow `api.osv.dev`, `www.cisa.gov`, `api.first.org`, or accept the gap |
| No OS package CVEs on Arch/Fedora | Unsupported by OSV; inventory-only gap |

## Free vs paid

| Capability | Free |
|---|---|
| All 23 checks, TUI, JSON/SARIF/OCSF, ASCII report | ✅ |
| fix/undo, backups, audit log | ✅ |
| SBOM + CycloneDX export | ✅ |
| Agent Skill + local MCP server | ✅ |
| AI triage with your own key (BYOK) | ✅ |
| Basic GitHub Action (SARIF + threshold) | ✅ |

| Capability | Paid / hosted |
|---|---|
| Hosted AI triage beyond 3 lifetime free runs | Pro $19/mo (300 credits), Team $39/seat |
| Remote MCP endpoint, dashboard, scan history | Pro/Team |
| SSO, policy, audit export, pooled credits | Team |
| Premium rule & compliance packs, fleet/MDM, self-host + DPA | Enterprise |

BYOK stays free on purpose: it costs us nothing to operate and removes the
“my findings left my network” objection. We charge for hosted compute,
collaboration, and compliance — never for detecting issues on your machine.

Full data-source details: [data-sources.md](data-sources.md).
