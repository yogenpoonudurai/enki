// Package configutil parses agent configuration files, including JSONC
// (JSON with comments) used by VS Code, Cursor, and Zed.
package configutil

import (
	"encoding/json"

	"github.com/tailscale/hujson"
)

// ParseJSONC parses JSON or JSONC into v.
func ParseJSONC(data []byte, v any) error {
	std, err := hujson.Standardize(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(std, v)
}

// ToMap parses a config file into a generic map.
func ToMap(data []byte) (map[string]any, error) {
	var m map[string]any
	if err := ParseJSONC(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Walk visits every key/value pair in a decoded JSON document. Arrays are
// traversed without adding an index to the path.
func Walk(v any, fn func(path []string, key string, val any)) {
	walk(v, nil, fn)
}

func walk(v any, path []string, fn func(path []string, key string, val any)) {
	switch node := v.(type) {
	case map[string]any:
		for k, val := range node {
			fn(path, k, val)
			np := make([]string, len(path)+1)
			copy(np, path)
			np[len(path)] = k
			walk(val, np, fn)
		}
	case []any:
		for _, item := range node {
			walk(item, path, fn)
		}
	}
}

// Strings extracts string elements from a []any.
func Strings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// StringMap extracts a map[string]string from a decoded JSON object, keeping
// only scalar values.
func StringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}
