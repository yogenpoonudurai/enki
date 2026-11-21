#!/usr/bin/env bash
# Triage smoke test against a local OpenAI-compatible server.
# Works with Ollama (default), llama.cpp server, vLLM, LM Studio, etc.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DIR")"
BIN="${ENKI_BIN:-$ROOT/bin/enki}"
BASE_URL="${ENKI_AI_BASE_URL:-http://127.0.0.1:11434/v1}"
MODEL="${ENKI_AI_MODEL:-qwen2.5:1.5b}"
WORK="$(mktemp -d)"
HOME_DIR="$WORK/home"
PROJ="$WORK/project"
mkdir -p "$HOME_DIR" "$PROJ"

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

[ -x "$BIN" ] || (cd "$ROOT" && make build >/dev/null)

cat > "$PROJ/.mcp.json" <<'JSON'
{"mcpServers":{"demo":{"command":"npx","args":["-y","unpinned-mcp-server"]}}}
JSON
cat > "$PROJ/.env" <<'EOF'
OPENAI_API_KEY=sk-test-localonlyabcdefghijklmnopqrstuvwxyz123
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

echo "== triage with $MODEL at $BASE_URL =="
HOME="$HOME_DIR" XDG_CONFIG_HOME="$HOME_DIR/.config" \
ENKI_AI_PROVIDER=ollama \
ENKI_AI_BASE_URL="$BASE_URL" \
ENKI_AI_MODEL="$MODEL" \
  "$BIN" triage "$WORK/report.json" > "$WORK/triage.json" 2> "$WORK/triage.err"
cat "$WORK/triage.err"

python3 - "$WORK/triage.json" <<'PY'
import json, sys
res = json.load(open(sys.argv[1]))["result"]
assert res["summary"], "missing summary"
assert res["findings_sent"] >= 1, "no findings sent"
assert res["top"], "model returned no validated triage items"
assert res["cost"]["metered"] is False, "local model should be unmetered"
print("model:", res["cost"]["model"], "unmetered",
      "· %d in / %d out" % (res["cost"]["input_tokens"], res["cost"]["output_tokens"]))
for item in res["top"]:
    print(" ", item["rule_id"], "->", item["recommended_action"] or "(none)",
          "verified" if item["action_verified"] else "unverified", "|", item["why"][:100])
    for step in item["fix_steps"]:
        print("    -", step)
print("local BYOK: PASS")
PY
