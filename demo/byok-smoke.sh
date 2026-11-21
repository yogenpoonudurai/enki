#!/usr/bin/env bash
# End-to-end BYOK test without a real provider key.
# Creates a fixture project, scans it, runs `enki triage` against a local fake
# OpenAI-compatible endpoint, and asserts redaction + validated output.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DIR")"
BIN="${ENKI_BIN:-$ROOT/bin/enki}"
PORT="${ENKI_FAKE_BYOK_PORT:-18999}"
WORK="$(mktemp -d)"
HOME_DIR="$WORK/home"
PROJ="$WORK/project"
LOG="$WORK/request.json"
mkdir -p "$HOME_DIR" "$PROJ"

cleanup() {
  [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || (cd "$ROOT" && make build >/dev/null)

FAKE_KEY="sk-test-byok-abcdefghijklmnopqrstuvwxyz123"
cat > "$PROJ/.mcp.json" <<JSON
{"mcpServers":{"demo":{"command":"npx","args":["-y","unpinned-mcp-server"]}}}
JSON
cat > "$PROJ/.env" <<EOF
OPENAI_API_KEY=$FAKE_KEY
EOF
chmod 0644 "$PROJ/.env"

echo "== scan fixture =="
(cd "$PROJ" && HOME="$HOME_DIR" XDG_CONFIG_HOME="$HOME_DIR/.config" CI=1 \
  "$BIN" scan --modules mcp,secrets --deps ai --os-packages=false \
  --json --fail-on none > "$WORK/report.json")
python3 - "$WORK/report.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print("findings:", len(r["findings"]), "rules:", sorted({f["rule_id"] for f in r["findings"]}))
PY

echo "== start fake provider =="
ENKI_FAKE_BYOK_LOG="$LOG" python3 "$DIR/fake_byok.py" "$PORT" &
SRV=$!
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.1
done

echo "== enki triage (BYOK) =="
ENKI_AI_PROVIDER=openai \
ENKI_AI_BASE_URL="http://127.0.0.1:$PORT/v1" \
ENKI_AI_KEY="dummy-key" \
ENKI_AI_MODEL="fake-byok-model" \
  "$BIN" triage "$WORK/report.json" > "$WORK/triage.json" 2> "$WORK/triage.err"
cat "$WORK/triage.err"

python3 - "$WORK/report.json" "$WORK/triage.json" "$LOG" "$FAKE_KEY" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
triage = json.load(open(sys.argv[2]))
log = json.load(open(sys.argv[3]))
fake_key = sys.argv[4]

res = triage["result"]
assert res["summary"], "missing summary"
assert res["findings_sent"] >= 1, "no findings sent"
assert res["cost"]["metered"] is False, "fake model should be unmetered"
assert res["top"], "no validated triage items"
assert any(item["action_verified"] for item in res["top"]), "no verified actions"

payload = log["payload"]
assert payload.get("system", {}).get("os"), "system context missing"
assert payload.get("findings"), "payload findings missing"
raw = json.dumps(log)
assert fake_key not in raw, "raw secret leaked into payload"
assert "system context" in res["summary"].lower() or "triage" in res["summary"].lower()
print("triage items:", [(i["rule_id"], i["recommended_action"], i["action_verified"]) for i in res["top"]])
print("system:", payload["system"]["os"], payload["system"].get("service_manager"),
      payload["system"].get("firewall_tools"))
print("redaction: raw key absent from payload; system context present")
PY

echo "== apply verified fix =="
HOME="$HOME_DIR" ENKI_AI_PROVIDER=openai \
ENKI_AI_BASE_URL="http://127.0.0.1:$PORT/v1" \
ENKI_AI_KEY="dummy-key" \
ENKI_AI_MODEL="fake-byok-model" \
  "$BIN" triage --apply --only SEC-001 --format json "$WORK/report.json" > "$WORK/applied.json"
python3 - "$WORK/applied.json" "$PROJ/.env" <<'PY'
import json, os, stat, sys
out = json.load(open(sys.argv[1]))
applied = out.get("applied") or []
assert applied, "no apply results"
assert any(r["applied"] for r in applied), "no verified fix applied"
mode = stat.S_IMODE(os.stat(sys.argv[2]).st_mode)
assert mode == 0o600, "mode after apply = %o" % mode
print("applied:", [(r["action"]["rule_id"], r["applied"]) for r in applied], "mode", oct(mode))
PY
HOME="$HOME_DIR" "$BIN" undo >/dev/null
python3 - "$PROJ/.env" <<'PY'
import os, stat, sys
mode = stat.S_IMODE(os.stat(sys.argv[1]).st_mode)
assert mode == 0o644, "mode after undo = %o" % mode
print("undo: mode restored to", oct(mode))
PY

echo "BYOK smoke: PASS"
