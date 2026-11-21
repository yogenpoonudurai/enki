# Dependency coverage

enki inventories dependencies from lockfiles (preferred), manifests, optional
fallbacks, and the Linux package database, then queries OSV per exact
version. Unknown status (network failure, unsupported distro, lockfile-less
ranges) is reported as a coverage gap, never as "clean".

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--deps all\|ai` | `all` | `ai` limits scanning to the AI package catalog |
| `--paths` | cwd | additional project roots (repeatable) |
| `--depth` | 3 | manifest discovery walk depth |
| `--include-dev` | true | include dev dependencies (tagged otherwise) |
| `--include-global` | false | `npm ls -g --depth=0` inventory |
| `--scan-node-modules` | false | lockfile-less fallback |
| `--os-packages` | true | Linux distro package inventory |

`enki sbom [flags] [-o file] [--vulns]` exports the same inventory as a
CycloneDX 1.5 BOM; `--vulns` adds OSV advisories (network required).

## Ecosystem mapping (Linux)

| Distro | OSV ecosystem | Source of truth |
|---|---|---|
| Debian | `Debian:<major>` | `dpkg-query` source package + source version (epoch preserved) |
| Ubuntu | `Ubuntu:<version>[:LTS]` | same |
| Alpine | `Alpine:v<major.minor>` | `/lib/apk/db/installed` origin field |
| Rocky Linux | `Rocky Linux:<major>` | `rpm -qa` NAME + EVR |
| AlmaLinux | `AlmaLinux:<major>` | same |
| RHEL | — (deferred; stream-scoped ecosystems) | inventory-only + gap |
| Fedora / Arch / CentOS Stream | unsupported by OSV | inventory-only + gap |

## Severity

1. CVSS v3.0/3.1 base score computed from the advisory vector.
2. GHSA qualitative rating (`database_specific.severity`).
3. Medium when neither exists (common for distro advisories).

CISA KEV forces at least HIGH; EPSS ≥ 0.5 raises one level; KEV plus
EPSS ≥ 0.9 becomes CRITICAL.

## Remediation

SBOM findings are `GUIDANCE`/RISKY actions: enki reports the highest fixed
version from the advisory and (where the ecosystem allows it) a package-manager
command, but never runs it.

| Ecosystem | Command shape |
|---|---|
| PyPI | `python3 -m pip install --upgrade "pkg>=X"` |
| npm | `npm install pkg@X` |
| Go | `go get pkg@X` |
| crates.io | `cargo update -p pkg --precise X` |
| NuGet | `dotnet add package Pkg --version X` |
| Debian/Ubuntu | `sudo apt-get install --only-upgrade pkg` |
| Alpine | `sudo apk upgrade pkg` |
| Rocky/Alma | `sudo dnf upgrade pkg` |

Firewall remediation is diagnostics-aware: enki picks `ufw`, `nft`,
`firewalld`, `iptables`, `pfctl`, or `netsh` based on the host and states when
sudo/administrator is required. Rebinding the service to loopback is always
preferred over a firewall rule.

## Volume and safety

- Packages are capped per run (10 000) and advisories at 1 500, with explicit
  gaps when truncation happens.
- Advisory details are fetched with a 12-way pool and jittered backoff; a 24 h
  disk cache reduces repeat traffic.
- enki never executes package managers other than read-only inventory
  commands (`dpkg-query -W`, `rpm -qa`, file reads) and `npm ls -g` when
  explicitly enabled.

## Known limitations

- Maven/Gradle dependency resolution is not implemented (requires a build).
- `go.sum` without `go.mod` cannot identify selected versions.
- Lockfile-less npm projects are unresolved unless `--scan-node-modules` is
  used.
- RHEL support needs stream-scoped ecosystems and is deferred.
