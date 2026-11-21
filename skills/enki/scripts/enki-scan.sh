#!/usr/bin/env sh
# Portable enki scan wrapper for agent skills.
set -eu

if [ -n "${ENKI_BIN:-}" ]; then
  BIN="$ENKI_BIN"
elif command -v enki >/dev/null 2>&1; then
  BIN=enki
elif command -v enki-mcp >/dev/null 2>&1; then
  BIN=enki
else
  echo "enki not found on PATH (install: go install github.com/yogenpoonudurai/enki/cmd/enki@latest)" >&2
  exit 127
fi

exec "$BIN" scan --json --fail-on none "$@"
