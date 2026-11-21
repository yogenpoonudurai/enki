#!/usr/bin/env bash
# Reproducible 60-second demo: a local AI service exposed on 0.0.0.0.
# Safe: the fake server only listens on this machine and is killed on exit.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DIR")"
PORT="${ENKI_DEMO_PORT:-11434}"
BIN="${ENKI_BIN:-$ROOT/bin/enki}"

if [ ! -x "$BIN" ]; then
  (cd "$ROOT" && make build >/dev/null)
fi

python3 "$DIR/exposed_ollama.py" "$PORT" &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT

for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$PORT/api/tags" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

echo "enki demo — a local Ollama-like server is listening on 0.0.0.0:${PORT}"
echo
"$BIN" scan --modules endpoint-exposure --fail-on none
echo
echo "Try the interactive dashboard for the fix flow:  ${BIN}  → press f → 1"
