package sbom

import (
	"encoding/json"
	"strings"
)

// parseBunLock reads bun's text lockfile (lockfileVersion 1 and 2). bun emits
// it with trailing commas, which encoding/json rejects, so the bytes are
// normalized first. Each package entry is a tuple whose first element is the
// resolved "name@version" spec; the packages table carries no dev markers, so
// dev dependencies cannot be distinguished (as in yarn v1).
func parseBunLock(data []byte) ([]Pkg, int, error) {
	var lock struct {
		Packages map[string][]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(stripTrailingCommas(data), &lock); err != nil {
		return nil, 0, err
	}

	var out []Pkg
	skipped := 0
	for _, entry := range lock.Packages {
		if len(entry) == 0 {
			skipped++
			continue
		}
		var spec string
		if err := json.Unmarshal(entry[0], &spec); err != nil || spec == "" {
			skipped++
			continue
		}
		name, ver, ok := splitBunSpec(spec)
		if !ok || !registrySource(entryURL(entry)) {
			skipped++
			continue
		}
		out = append(out, Pkg{Name: name, Version: ver, Ecosystem: "npm"})
	}
	return out, skipped, nil
}

// entryURL returns the resolved source URL from a package tuple, if present.
func entryURL(entry []json.RawMessage) string {
	if len(entry) < 2 {
		return ""
	}
	var url string
	if err := json.Unmarshal(entry[1], &url); err != nil {
		return ""
	}
	return url
}

// registrySource reports whether a resolved URL points at a package registry
// whose name@version identity is meaningful for OSV matching. bun writes an
// empty string for the default registry, so only a custom host is inspected:
// registry hosts keep that identity even when served as a tarball or by a
// mirror of the public package, while git, file, and other direct sources
// become coverage gaps instead of matching under a public package's identity.
func registrySource(url string) bool {
	return url == "" ||
		strings.HasPrefix(url, "https://registry.") ||
		strings.HasPrefix(url, "http://registry.")
}

// splitBunSpec resolves a bun package spec to its registry name and exact
// version. Aliases ("alias@npm:real@1.0.0") resolve to the real package, and
// non-registry sources report as unresolved so they surface as coverage gaps.
func splitBunSpec(spec string) (string, string, bool) {
	if i := strings.Index(spec, "?"); i >= 0 {
		spec = spec[:i]
	}
	if j := strings.Index(spec, "@npm:"); j > 0 {
		spec = spec[j+len("@npm:"):]
	}
	for _, prefix := range []string{"workspace:", "file:", "link:", "git:", "git+", "http:", "https:"} {
		if strings.Contains(spec, prefix) {
			return "", "", false
		}
	}
	i := strings.LastIndexByte(spec, '@')
	if i <= 0 {
		return "", "", false
	}
	name, ver := spec[:i], strings.TrimPrefix(spec[i+1:], "v")
	if name == "" || !semverish.MatchString(ver) {
		return "", "", false
	}
	return name, ver, true
}

// stripTrailingCommas removes commas that are followed only by whitespace and
// a closing brace or bracket. String contents, including escaped quotes, are
// preserved verbatim; ASCII structural bytes cannot appear inside a UTF-8
// continuation sequence, so byte-level scanning is safe.
func stripTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(data) && isJSONSpace(data[j]) {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
