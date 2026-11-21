package model

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yogenpoonudurai/enki/internal/scanner"
)

func TestScanCodePatterns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "train.py")
	content := "import torch\n" +
		"m = torch.load('model.pt')\n" +
		"from transformers import AutoModel\n" +
		"m2 = AutoModel.from_pretrained('x/y', trust_remote_code=True)\n" +
		"url = 'http://example.com/weights.safetensors'\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	fs := scanCode(path)
	got := map[string]bool{}
	for _, f := range fs {
		got[f.RuleID] = true
	}
	for _, want := range []string{"MDL-002", "MDL-003", "MDL-004"} {
		if !got[want] {
			t.Errorf("missing %s: %+v", want, got)
		}
	}
}

func TestWeightsOnlySuppressesTorchLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "safe.py")
	if err := os.WriteFile(path, []byte("torch.load(path, weights_only=True)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range scanCode(path) {
		if f.RuleID == "MDL-003" {
			t.Fatal("torch.load with weights_only=True flagged")
		}
	}
}

func TestPickleWeightsGroupedByDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "models")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.pt", "b.pkl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("weights"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sc := &scanner.Context{WorkingDir: root}
	fs, _, err := New().Run(sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].RuleID != "MDL-001" {
		t.Fatalf("findings = %+v", fs)
	}
	if fs[0].Evidence == "" {
		t.Fatal("expected file names in evidence")
	}
}
