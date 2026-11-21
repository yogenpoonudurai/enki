package secretlib

import (
	"strings"
	"testing"
)

const (
	openaiKey    = "sk-test-abcdefghijklmnopqrstuvwxyz123456"
	anthropicKey = "sk-ant-test-abcdefghijklmnopqrstuvwxyz"
)

func TestScanProviderPatterns(t *testing.T) {
	content := "OPENAI=" + openaiKey + "\nANTHROPIC=" + anthropicKey + "\n"
	matches := Scan(content)

	var openai, anthropic int
	for _, m := range matches {
		switch m.ID {
		case "openai":
			openai++
		case "anthropic":
			anthropic++
		}
	}
	if openai != 1 {
		t.Errorf("openai matches = %d, want 1 (Anthropic keys must not double-match)", openai)
	}
	if anthropic != 1 {
		t.Errorf("anthropic matches = %d, want 1", anthropic)
	}
}

func TestScanAWSAndHF(t *testing.T) {
	matches := Scan("key=AKIAABCDEFGHIJKLMNOP token=hf_testabcdefghijklmnopqrstuvwxyz0123456789")
	ids := map[string]bool{}
	for _, m := range matches {
		ids[m.ID] = true
	}
	if !ids["aws"] || !ids["huggingface"] {
		t.Fatalf("missing detections: %+v", ids)
	}
}

func TestScanValue(t *testing.T) {
	if m := ScanValue(openaiKey); m == nil || m.ID != "openai" {
		t.Fatalf("ScanValue = %+v", m)
	}
	if m := ScanValue("not-a-secret"); m != nil {
		t.Fatalf("unexpected match: %+v", m)
	}
}

func TestGenericAssignmentSkipsPlaceholders(t *testing.T) {
	matches := ScanGeneric("api_key = your_api_key_placeholder_here\n")
	if len(matches) != 0 {
		t.Fatalf("placeholder flagged: %+v", matches)
	}
	matches = ScanGeneric("api_key = 8f3c2b1a9d7e6f5a4b3c2d1e0f9a8b7c\n")
	if len(matches) != 1 || matches[0].ID != "generic" {
		t.Fatalf("generic match = %+v", matches)
	}
}

func TestGenericDoesNotDuplicateKnownPatterns(t *testing.T) {
	matches := ScanGeneric("token = " + openaiKey + "\n")
	if len(matches) != 0 {
		t.Fatalf("known pattern duplicated by generic scan: %+v", matches)
	}
}

func TestIsSecretEnvName(t *testing.T) {
	for _, name := range []string{"OPENAI_API_KEY", "HF_TOKEN", "client_secret", "AUTH_TOKEN"} {
		if !IsSecretEnvName(name) {
			t.Errorf("%s should be a secret env name", name)
		}
	}
	for _, name := range []string{"PATH", "HOME", "MODEL_NAME"} {
		if IsSecretEnvName(name) {
			t.Errorf("%s should not be a secret env name", name)
		}
	}
}

func TestNoMatchOnProse(t *testing.T) {
	prose := "The sk- prefix is used by several providers and should not be reported on its own."
	if len(Scan(strings.Repeat(prose, 3))) != 0 {
		t.Fatal("prose produced a match")
	}
}
