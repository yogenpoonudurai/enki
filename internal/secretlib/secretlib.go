// Package secretlib holds the credential pattern catalog shared by the MCP,
// secrets, and correlation checks. It never logs or returns unredacted values
// to callers other than the immediate finding construction site.
package secretlib

import (
	"regexp"
	"strings"
)

type Pattern struct {
	ID   string
	Name string
	RE   *regexp.Regexp
}

// Patterns are ordered from most specific to least specific.
var Patterns = []Pattern{
	{ID: "anthropic", Name: "Anthropic API key", RE: regexp.MustCompile(`sk-ant-(?:api|admin)?[A-Za-z0-9_-]{20,}`)},
	{ID: "openai", Name: "OpenAI API key", RE: regexp.MustCompile(`sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`)},
	{ID: "huggingface", Name: "Hugging Face token", RE: regexp.MustCompile(`hf_[A-Za-z0-9]{30,}`)},
	{ID: "aws", Name: "AWS access key ID", RE: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{ID: "google", Name: "Google API key", RE: regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{ID: "github", Name: "GitHub token", RE: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
}

var genericAssignment = regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{24,})["']?`)

var placeholderMarkers = []string{
	"example", "your_", "your-", "changeme", "change-me", "placeholder",
	"dummy", "xxxx", "redacted", "<", ">", "insert_", "replace_",
}

// Match is a hit inside a scanned body.
type Match struct {
	ID    string
	Name  string
	Value string
	Index int
}

// Scan finds known provider credential formats.
func Scan(content string) []Match {
	var out []Match
	seen := map[string]bool{}
	for _, p := range Patterns {
		for _, loc := range p.RE.FindAllStringIndex(content, -1) {
			v := content[loc[0]:loc[1]]
			// The OpenAI pattern also matches sk-ant-* keys; keep those only
			// under the Anthropic pattern to avoid duplicate findings.
			if p.ID == "openai" && strings.HasPrefix(v, "sk-ant-") {
				continue
			}
			key := p.ID + "|" + v
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Match{ID: p.ID, Name: p.Name, Value: v, Index: loc[0]})
		}
	}
	return out
}

// ScanGeneric finds assignment-style secrets not covered by a known pattern.
func ScanGeneric(content string) []Match {
	var out []Match
	seen := map[string]bool{}
	for _, loc := range genericAssignment.FindAllStringSubmatchIndex(content, -1) {
		v := content[loc[2]:loc[3]]
		if isPlaceholder(v) || isKnownPattern(v) || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, Match{ID: "generic", Name: "Generic secret", Value: v, Index: loc[0]})
	}
	return out
}

// ScanAll combines specific and generic detection.
func ScanAll(content string) []Match {
	return append(Scan(content), ScanGeneric(content)...)
}

// ScanValue checks a single configuration value (e.g. an MCP env var).
func ScanValue(s string) *Match {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, p := range Patterns {
		if loc := p.RE.FindStringIndex(s); loc != nil {
			return &Match{ID: p.ID, Name: p.Name, Value: s[loc[0]:loc[1]]}
		}
	}
	return nil
}

// IsSecretEnvName reports whether an env var name conventionally holds a
// provider credential (used to flag inline MCP env secrets even when the
// value format is unknown).
func IsSecretEnvName(name string) bool {
	up := strings.ToUpper(name)
	if strings.Contains(up, "KEY") || strings.Contains(up, "TOKEN") || strings.Contains(up, "SECRET") {
		return true
	}
	return up == "HF_AUTH" || up == "HUGGING_FACE_HUB_TOKEN"
}

func isPlaceholder(v string) bool {
	lv := strings.ToLower(v)
	for _, m := range placeholderMarkers {
		if strings.Contains(lv, m) {
			return true
		}
	}
	return false
}

func isKnownPattern(v string) bool {
	for _, p := range Patterns {
		if p.RE.MatchString(v) {
			return true
		}
	}
	return false
}
