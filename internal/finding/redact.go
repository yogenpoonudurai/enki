package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// RedactSecret returns a display-safe form of a secret: the first four
// characters (usually a recognizable prefix such as "sk-p") plus the last
// four, separated by an ellipsis. Short values are fully masked.
func RedactSecret(v string) string {
	if len(v) <= 8 {
		return "****"
	}
	return v[:4] + "…" + v[len(v)-4:]
}

// SecretFingerprint returns a stable, non-reversible 8-hex-character
// identifier for a secret value, suitable for reports and deduplication.
func SecretFingerprint(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:8]
}

// MaskPaths collapses long paths for display while keeping the basename.
func MaskPaths(p string) string {
	if len(p) <= 48 {
		return p
	}
	parts := strings.Split(p, "/")
	if len(parts) < 2 {
		return p
	}
	return "…/" + strings.Join(parts[len(parts)-2:], "/")
}
