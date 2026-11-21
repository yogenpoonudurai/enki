package collector

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverConfigsScope(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	hostCfg := filepath.Join(home, ".claude", "settings.json")
	projCfg := filepath.Join(work, ".mcp.json")
	writeConfig(t, hostCfg)
	writeConfig(t, projCfg)

	cases := []struct {
		host, project bool
		want          []string
	}{
		{true, false, []string{hostCfg}},
		{false, true, []string{projCfg}},
		{true, true, []string{hostCfg, projCfg}},
	}
	for _, tc := range cases {
		got, _ := DiscoverConfigs(home, work, tc.host, tc.project)
		if len(got) != len(tc.want) {
			t.Fatalf("host=%v project=%v got %d configs, want %d: %+v", tc.host, tc.project, len(got), len(tc.want), got)
		}
		seen := map[string]bool{}
		for _, cf := range got {
			seen[cf.Path] = true
		}
		for _, want := range tc.want {
			if !seen[want] {
				t.Fatalf("host=%v project=%v missing %s", tc.host, tc.project, want)
			}
		}
	}
}
