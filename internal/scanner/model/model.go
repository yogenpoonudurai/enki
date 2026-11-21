// Package model inspects local model artifacts and training/inference code for
// unsafe deserialization, remote-code trust, and plaintext weight downloads.
package model

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/scanner"
)

const moduleName = "model-artifacts"

const (
	maxDepth     = 8
	maxFiles     = 20000
	maxCodeFiles = 2000
	maxScanBytes = 1 << 20
	binMinSize   = 10 << 20
)

type Module struct{}

func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }

func (m *Module) Description() string {
	return "Detects unsafe model artifacts (.pt/.pkl), trust_remote_code, and HTTP weight downloads"
}

var weightExts = map[string]bool{
	".pkl": true, ".pickle": true, ".pt": true, ".pth": true, ".ckpt": true, ".bin": true,
}

var codeExts = map[string]bool{
	".py": true, ".ipynb": true, ".sh": true, ".yaml": true, ".yml": true, ".json": true, ".txt": true,
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true, "env": true,
	"__pycache__": true, "site-packages": true, ".cache": true, "dist": true,
	"build": true, ".next": true, "target": true, ".idea": true, ".vscode": true,
}

var (
	trustRemote  = regexp.MustCompile(`(?i)trust_remote_code\s*=\s*True`)
	torchLoad    = regexp.MustCompile(`torch\.load\s*\(`)
	httpWeights  = regexp.MustCompile(`http://[^\s"'<>)]+?\.(?:pt|pth|pkl|ckpt|bin|safetensors)\b`)
	torchWeights = regexp.MustCompile(`weights_only\s*=\s*True`)
)

func (m *Module) Run(sc *scanner.Context) ([]finding.Finding, []scanner.CoverageGap, error) {
	var out []finding.Finding
	var gaps []scanner.CoverageGap

	weightDirs := map[string][]string{}
	var codeFiles []string
	files := 0
	truncated := false
	seenRoots := map[string]bool{}

	for _, root := range modelRoots(sc) {
		root = filepath.Clean(root)
		if seenRoots[root] {
			continue
		}
		seenRoots[root] = true
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable entries are skipped, not fatal
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			depth := strings.Count(rel, string(os.PathSeparator))
			if d.IsDir() {
				if path != root && (skipDirs[d.Name()] || depth >= maxDepth) {
					return filepath.SkipDir
				}
				return nil
			}
			files++
			if files > maxFiles {
				truncated = true
				return filepath.SkipAll
			}
			info, statErr := d.Info()
			if statErr != nil {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			switch {
			case weightExts[ext]:
				if ext == ".bin" && info.Size() < binMinSize {
					return nil
				}
				dir := filepath.Dir(path)
				weightDirs[dir] = append(weightDirs[dir], filepath.Base(path))
			case codeExts[ext]:
				if info.Size() <= maxScanBytes {
					codeFiles = append(codeFiles, path)
				}
			}
			return nil
		})
		if walkErr != nil {
			gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapError, Reason: "file walk failed for " + root + ": " + walkErr.Error()})
		}
		if truncated {
			break
		}
	}
	if truncated {
		gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapTruncated, Reason: fmt.Sprintf("file walk stopped after %d entries; some artifacts were not inspected", maxFiles)})
	}

	dirs := make([]string, 0, len(weightDirs))
	for dir := range weightDirs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	if len(dirs) > 50 {
		gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapTruncated, Reason: fmt.Sprintf("%d additional directories with pickle weights omitted from findings", len(dirs)-50)})
		dirs = dirs[:50]
	}
	for _, dir := range dirs {
		out = append(out, pickleFinding(dir, weightDirs[dir]))
	}

	sort.Strings(codeFiles)
	if len(codeFiles) > maxCodeFiles {
		gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapTruncated, Reason: fmt.Sprintf("source scan limited to %d files; %d skipped", maxCodeFiles, len(codeFiles)-maxCodeFiles)})
		codeFiles = codeFiles[:maxCodeFiles]
	}
	for _, path := range codeFiles {
		out = append(out, scanCode(path)...)
	}

	finding.Sort(out)
	return out, gaps, nil
}

// modelRoots selects project and host artifact locations for the scan scope.
func modelRoots(sc *scanner.Context) []string {
	var roots []string
	if sc.Scope.IncludesProject() {
		roots = append(roots, sc.WorkingDir)
	}
	if sc.Scope.IncludesHost() && sc.HomeDir != "" {
		roots = append(roots,
			filepath.Join(sc.HomeDir, ".cache", "huggingface"),
			filepath.Join(sc.HomeDir, ".cache", "torch"),
			filepath.Join(sc.HomeDir, ".ollama", "models"),
			filepath.Join(sc.HomeDir, "models"),
		)
	}
	return roots
}

func pickleFinding(dir string, names []string) finding.Finding {
	sort.Strings(names)
	shown := names
	if len(shown) > 3 {
		shown = shown[:3]
	}
	f := finding.New("MDL-001", moduleName,
		fmt.Sprintf("%d pickle-based weight file(s) in %s", len(names), filepath.Base(dir)),
		"Pickle-based checkpoints deserialize Python objects and can execute arbitrary code on load. Prefer .safetensors, or load untrusted artifacts only inside a sandbox with object deserialization disabled.",
		finding.SeverityMedium, finding.ConfidenceHigh,
		finding.Location{Path: dir})
	f.Evidence = strings.Join(shown, ", ")
	if len(names) > len(shown) {
		f.Evidence += fmt.Sprintf(" (+%d more)", len(names)-len(shown))
	}
	f.Remediation = &finding.Remediation{
		Class:    finding.ActionModerate,
		Summary:  "Convert weights to safetensors and validate artifact provenance",
		Guidance: "Use safetensors where possible. For required .pt/.pkl artifacts, verify checksums and load them in an isolated environment.",
	}
	f.Tags = []string{"model", "deserialization"}
	return f
}

func scanCode(path string) []finding.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)
	var out []finding.Finding

	if loc := trustRemote.FindStringIndex(content); loc != nil {
		f := finding.New("MDL-002", moduleName,
			"Model code loads remote code with trust_remote_code",
			"trust_remote_code executes Python shipped inside a model repository. A compromised or swapped model repo gains code execution in your process.",
			finding.SeverityHigh, finding.ConfidenceHigh,
			finding.Location{Path: path, Line: lineOf(content, loc[0])})
		f.Evidence = "trust_remote_code=True"
		f.Remediation = &finding.Remediation{
			Class:    finding.ActionModerate,
			Summary:  "Pin the model revision and mirror remote code",
			Guidance: "Pin a commit hash, review the remote modeling file, and prefer loading a vetted local copy with trust_remote_code disabled.",
		}
		f.Tags = []string{"model", "remote-code"}
		out = append(out, f)
	}

	for _, loc := range torchLoad.FindAllStringIndex(content, -1) {
		end := loc[1] + 200
		if end > len(content) {
			end = len(content)
		}
		if torchWeights.MatchString(content[loc[0]:end]) {
			continue
		}
		f := finding.New("MDL-003", moduleName,
			"torch.load without weights_only",
			"On PyTorch releases before 2.6, torch.load deserializes arbitrary Python objects. Loading an untrusted checkpoint can execute code.",
			finding.SeverityMedium, finding.ConfidenceMedium,
			finding.Location{Path: path, Line: lineOf(content, loc[0])})
		f.Evidence = "torch.load(...) without weights_only=True nearby"
		f.Remediation = &finding.Remediation{
			Class:    finding.ActionModerate,
			Summary:  "Pass weights_only=True or require PyTorch 2.6+",
			Guidance: "Use torch.load(path, weights_only=True) or load safetensors; verify checkpoints before use.",
		}
		f.Tags = []string{"model", "deserialization"}
		out = append(out, f)
		break
	}

	seenURLs := map[string]bool{}
	for _, loc := range httpWeights.FindAllStringIndex(content, -1) {
		u := content[loc[0]:loc[1]]
		if seenURLs[u] {
			continue
		}
		seenURLs[u] = true
		f := finding.New("MDL-004", moduleName,
			"Model weights downloaded over plain HTTP",
			"Weights fetched over http:// can be swapped in transit, turning model download into a code-execution vector when combined with pickle formats.",
			finding.SeverityMedium, finding.ConfidenceMedium,
			finding.Location{Path: path, Line: lineOf(content, loc[0])})
		f.Evidence = u
		f.Remediation = &finding.Remediation{
			Class:    finding.ActionModerate,
			Summary:  "Download weights over HTTPS and verify checksums",
			Guidance: "Use https:// URLs and validate the artifact hash before loading.",
		}
		f.Tags = []string{"model", "supply-chain"}
		out = append(out, f)
		break
	}

	return out
}

func lineOf(content string, idx int) int {
	if idx < 0 || idx > len(content) {
		return 0
	}
	return strings.Count(content[:idx], "\n") + 1
}
