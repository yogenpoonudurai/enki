#!/usr/bin/env bash
set -euo pipefail

# Verifies that a GitHub Release contains only public, allowlisted artifacts.
# Usage: scripts/check-release-assets.sh <tag>
tag="${1:?usage: check-release-assets.sh <tag>}"

if ! command -v gh >/dev/null 2>&1; then
  echo "::error::gh CLI is required" >&2
  exit 1
fi

allowed='^(enki_[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?_(linux|darwin|windows)_(amd64|arm64)\.(tar\.gz|zip)|checksums\.txt(\.sig|\.pem)?|enki\.sbom\.cdx\.json)$'

fail=0
while IFS= read -r asset; do
  [ -z "$asset" ] && continue
  if [[ "$asset" =~ $allowed ]]; then
    echo "allowed: $asset"
  else
    echo "::error::unexpected release asset: $asset" >&2
    fail=1
  fi
done < <(gh release view "$tag" --json assets --jq '.assets[].name')

if [ "$fail" -ne 0 ]; then
  echo "release asset allowlist failed for $tag" >&2
  exit 1
fi

echo "release asset allowlist passed for $tag"
