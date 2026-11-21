#!/usr/bin/env bash
# Execute the CLI commands documented in README.md and docs/quickstart.md.
# Runs against a temporary fixture; never touches the real HOME or project.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DIR")"
BIN="${ENKI_BIN:-$ROOT/bin/enki}"
WORK="$(mktemp -d)"
HOME_DIR="$WORK/home"
PROJ="$WORK/project"
FIXDIR="$WORK/fix"
mkdir -p "$HOME_DIR" "$PROJ" "$FIXDIR" "$WORK/release"

cleanup() {
  [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || (cd "$ROOT" && make build >/dev/null)

cat > "$PROJ/.mcp.json" <<'JSON'
{"mcpServers":{"demo":{"command":"npx","args":["-y","unpinned-mcp-server"]}}}
JSON
cat > "$PROJ/.env" <<'ENV'
OPENAI_API_KEY=sk-test-docsonlynoproductionabcdefghijklmnopqrstuvwxyz
ENV
chmod 0644 "$PROJ/.env"

cat > "$FIXDIR/.env" <<'ENV'
OPENAI_API_KEY=sk-test-docsonlynoproductionabcdefghijklmnopqrstuvwxyz
ENV
chmod 0644 "$FIXDIR/.env"

env_run() {
  HOME="$HOME_DIR" XDG_CONFIG_HOME="$HOME_DIR/.config" XDG_STATE_HOME="$HOME_DIR/.state" CI=1 "$@"
}

ok() { printf 'ok   %s\n' "$*"; }

# --- enki version -----------------------------------------------------------
env_run "$BIN" version > "$WORK/version.txt"
grep -qi "enki" "$WORK/version.txt"
ok "enki version"

# --- enki scan --json (exit 1 is the documented gate) -----------------------
set +e
(cd "$PROJ" && env_run "$BIN" scan --json > "$WORK/report.json" 2> "$WORK/scan.err")
scan_status=$?
set -e
[ "$scan_status" -eq 0 ] || [ "$scan_status" -eq 1 ]
python3 - "$WORK/report.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
assert r["findings"], "fixture produced no findings"
print("ok   enki scan --json (%d findings, gate exit 1)" % len(r["findings"]))
PY

# --- enki (piped/non-TTY fallback) ------------------------------------------
set +e
(cd "$PROJ" && env_run "$BIN" > "$WORK/plain.txt" 2>/dev/null)
set -e
grep -qi "enki\|SEC-\|MCP-\|SBOM-" "$WORK/plain.txt"
ok "enki (non-TTY plain scan)"

# --- enki report ------------------------------------------------------------
env_run "$BIN" report "$WORK/report.json" > "$WORK/ascii.txt"
grep -q "AI SECURITY POSTURE REPORT" "$WORK/ascii.txt"
ok "enki report"

# --- enki scan --sarif ------------------------------------------------------
set +e
(cd "$PROJ" && env_run "$BIN" scan --sarif --fail-on high > "$WORK/report.sarif" 2>/dev/null)
set -e
python3 - "$WORK/report.sarif" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["version"] == "2.1.0" and s["runs"], "invalid SARIF"
print("ok   enki scan --sarif --fail-on high")
PY

# --- enki scan --deps ai ----------------------------------------------------
set +e
(cd "$PROJ" && env_run "$BIN" scan --deps ai --fail-on none > "$WORK/deps.txt" 2>/dev/null)
set -e
grep -qi "enki\|SEC-\|MCP-\|SBOM-" "$WORK/deps.txt"
ok "enki scan --deps ai"

# --- enki fix / fix --apply / undo -----------------------------------------
(cd "$FIXDIR" && env_run "$BIN" fix > "$WORK/fix-dry.txt")
grep -q "FIX PLAN\|No automated\|GUIDANCE\|SEC-001" "$WORK/fix-dry.txt"
ok "enki fix (dry run)"

(cd "$FIXDIR" && env_run "$BIN" fix --apply > "$WORK/fix-apply.txt")
grep -q "APPLIED" "$WORK/fix-apply.txt"
[ "$(stat -c %a "$FIXDIR/.env")" = "600" ]
ok "enki fix --apply (mode 0600)"

(cd "$FIXDIR" && env_run "$BIN" undo > "$WORK/undo.txt")
grep -q "UNDO" "$WORK/undo.txt"
[ "$(stat -c %a "$FIXDIR/.env")" = "644" ]
ok "enki undo (mode restored 0644)"

(cd "$FIXDIR" && env_run "$BIN" undo 1 > "$WORK/undo-n.txt")
grep -q "Nothing to undo" "$WORK/undo-n.txt"
ok "enki undo N (count form)"

# --- enki sbom --------------------------------------------------------------
(cd "$PROJ" && env_run "$BIN" sbom -o "$WORK/bom.json" 2>/dev/null)
python3 - "$WORK/bom.json" <<'PY'
import json, sys
b = json.load(open(sys.argv[1]))
assert b["bomFormat"] == "CycloneDX"
print("ok   enki sbom -o bom.json")
PY

# --- enki doctor / rules ----------------------------------------------------
env_run "$BIN" doctor > "$WORK/doctor.txt"
grep -q "^os:" "$WORK/doctor.txt"
ok "enki doctor"

env_run "$BIN" rules list > "$WORK/rules.txt"
grep -q "AEP-001" "$WORK/rules.txt"
ok "enki rules list"

env_run "$BIN" rules validate > "$WORK/rules-validate.txt"
grep -q "rules valid" "$WORK/rules-validate.txt"
ok "enki rules validate"

# Focused fixture report so triage sees the MCP/secret findings, not OS CVEs.
(cd "$PROJ" && env_run "$BIN" scan --modules mcp,secrets --deps ai \
  --os-packages=false --json --fail-on none > "$WORK/fixture-report.json")
env_run "$BIN" report "$WORK/fixture-report.json" > "$WORK/fixture-ascii.txt"
grep -q "SEC-001" "$WORK/fixture-ascii.txt"
ok "enki report (fixture findings)"

# --- enki triage (documented BYOK path, fake local provider) ----------------
ENKI_FAKE_BYOK_LOG="$WORK/fake.log" python3 "$DIR/fake_byok.py" 18999 >/dev/null 2>&1 &
SRV=$!
for _ in $(seq 1 50); do
  curl -fsS http://127.0.0.1:18999/healthz >/dev/null 2>&1 && break
  sleep 0.1
done
env_run env \
  ENKI_AI_PROVIDER=openai \
  ENKI_AI_BASE_URL=http://127.0.0.1:18999/v1 \
  ENKI_AI_KEY=dummy-key \
  ENKI_AI_MODEL=fake-byok-model \
  "$BIN" triage "$WORK/fixture-report.json" > "$WORK/triage.json" 2>/dev/null
python3 - "$WORK/triage.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))["result"]
assert r["summary"] and r["findings_sent"] >= 1
assert r["top"], "triage returned no validated items"
assert not r["cost"]["metered"]
print("ok   enki triage report.json (local BYOK path)")
PY

# --- Linux release archive from the quickstart ------------------------------
VERSION=0.3.0
BASE="https://github.com/yogenpoonudurai/enki/releases/download/v${VERSION}"
(
  cd "$WORK/release"
  curl -fsSLO "$BASE/enki_${VERSION}_linux_amd64.tar.gz"
  curl -fsSLO "$BASE/checksums.txt"
  grep "enki_${VERSION}_linux_amd64.tar.gz\$" checksums.txt > enki.sha256
  sha256sum -c enki.sha256 >/dev/null
  tar xzf "enki_${VERSION}_linux_amd64.tar.gz"
  test -x ./enki
  test -x ./enki-mcp
  ./enki version >/dev/null
)
ok "quickstart Linux archive + checksum"

# --- go install @latest -----------------------------------------------------
(
  export GOBIN="$WORK/gobin"
  go install github.com/yogenpoonudurai/enki/cmd/enki@latest
  go install github.com/yogenpoonudurai/enki/cmd/enki-mcp@latest
  "$WORK/gobin/enki" version >/dev/null
  test -x "$WORK/gobin/enki-mcp"
)
ok "go install ...@latest (CLI + MCP)"

echo "docs verification: PASS"
