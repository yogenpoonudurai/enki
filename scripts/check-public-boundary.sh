#!/usr/bin/env bash
set -euo pipefail

# Fails when premium/hosted service implementation or release artifacts are
# present in the public repository. The hosted client seam is allowed.
cd "$(dirname "$0")/.."

fail=0
check_absent() {
  local path="$1"
  if [ -e "$path" ]; then
    echo "::error::premium implementation present in public repo: $path" >&2
    fail=1
  fi
}

check_absent "cmd/enki-cloud"
check_absent "internal/cloud"

for file in .goreleaser.yaml Makefile; do
  if [ -f "$file" ] && grep -nE 'enki-cloud|cmd/enki-cloud|internal/cloud' "$file"; then
    echo "::error::$file references premium server code or artifacts" >&2
    fail=1
  fi
done

if grep -RInE 'enki-cloud|cmd/enki-cloud|internal/cloud' .github/workflows; then
  echo "::error::workflow references premium server code or artifacts" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "public boundary check failed" >&2
  exit 1
fi

echo "public boundary check passed: no hosted service implementation or cloud release artifacts"
echo "public seam allowed: internal/hosted, cmd/enki/account.go, docs/premium.md"
