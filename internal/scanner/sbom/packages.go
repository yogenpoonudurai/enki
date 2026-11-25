package sbom

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/scanner"
)

// Pkg is a dependency resolved to an exact version.
type Pkg struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Source    string `json:"source"`
	Direct    bool   `json:"direct,omitempty"`
	Dev       bool   `json:"dev,omitempty"`
	Optional  bool   `json:"optional,omitempty"`
}

// Options controls package discovery.
type Options struct {
	Deps            string   // "all" or "ai"
	Roots           []string // project roots; defaults to the working directory
	Depth           int      // directory walk depth
	IncludeDev      bool
	IncludeGlobal   bool
	ScanNodeModules bool
	OSPackages      bool
	NoProject       bool // skip project manifests (host-scoped scans)
}

// DefaultOptions scans everything under the working directory.
func DefaultOptions() Options {
	return Options{Deps: "all", Depth: 3, IncludeDev: true, OSPackages: true}
}

func (o Options) normalized() Options {
	if o.Deps == "" {
		o.Deps = "all"
	}
	if o.Depth <= 0 {
		o.Depth = 3
	}
	return o
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true, "env": true,
	"__pycache__": true, ".cache": true, "dist": true, "build": true,
	".next": true, "target": true, ".idea": true, ".vscode": true, "vendor": true,
}

const maxWalkFiles = 200000

// Discover parses every supported manifest/lockfile under the configured
// roots (plus optional global and OS package inventories) and returns a
// deduplicated package inventory. It never performs network calls.
func Discover(ctx context.Context, opts Options, defaultRoot string) ([]Pkg, []scanner.CoverageGap) {
	opts = opts.normalized()
	roots := opts.Roots
	if len(roots) == 0 {
		roots = []string{defaultRoot}
	}

	var gaps []scanner.CoverageGap
	set := newPackageSet()
	dirsWithNpmLock := map[string]bool{}
	dirsWithPackageJSON := map[string]bool{}
	files := 0

	if !opts.NoProject {
		for _, root := range roots {
			root = filepath.Clean(root)
			err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return nil
				}
				rel, relErr := filepath.Rel(root, path)
				if relErr != nil {
					return nil
				}
				depth := strings.Count(rel, string(os.PathSeparator))
				if d.IsDir() {
					if path != root && (skipDirs[d.Name()] || depth >= opts.Depth) {
						return filepath.SkipDir
					}
					return nil
				}
				files++
				if files > maxWalkFiles {
					return filepath.SkipAll
				}

				base := d.Name()
				switch {
				case base == "package-lock.json" || base == "npm-shrinkwrap.json":
					data, err := os.ReadFile(path)
					if err != nil {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapError, Reason: "cannot read " + path})
						return nil
					}
					ps, skipped, perr := parseNpmLock(data)
					if perr != nil {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapError, Reason: "cannot parse " + path + ": " + perr.Error()})
						return nil
					}
					if skipped > 0 {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapTruncated, Reason: fmt.Sprintf("%d non-registry npm dependencies skipped in %s", skipped, path)})
					}
					set.addAll(ps, path)
					dirsWithNpmLock[filepath.Dir(path)] = true
				case base == "yarn.lock":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					ps, skipped, perr := parseYarnLock(data)
					if perr != nil {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapError, Reason: "cannot parse " + path + ": " + perr.Error()})
						return nil
					}
					if skipped > 0 {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapTruncated, Reason: fmt.Sprintf("%d yarn entries without registry versions skipped in %s", skipped, path)})
					}
					set.addAll(ps, path)
					dirsWithNpmLock[filepath.Dir(path)] = true
				case base == "pnpm-lock.yaml":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					ps, skipped, perr := parsePnpmLock(data)
					if perr != nil {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapError, Reason: "cannot parse " + path + ": " + perr.Error()})
						return nil
					}
					if skipped > 0 {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapTruncated, Reason: fmt.Sprintf("%d pnpm entries without registry versions skipped in %s", skipped, path)})
					}
					set.addAll(ps, path)
					dirsWithNpmLock[filepath.Dir(path)] = true
				case base == "bun.lock":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					ps, skipped, perr := parseBunLock(data)
					if perr != nil {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapError, Reason: "cannot parse " + path + ": " + perr.Error()})
						return nil
					}
					if skipped > 0 {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapTruncated, Reason: fmt.Sprintf("%d bun entries without a registry version skipped in %s", skipped, path)})
					}
					set.addAll(ps, path)
					dirsWithNpmLock[filepath.Dir(path)] = true
				case base == "bun.lockb":
					// The legacy binary lockfile cannot be read without bun;
					// only note the blind spot when the text form is absent.
					dir := filepath.Dir(path)
					if _, statErr := os.Stat(filepath.Join(dir, "bun.lock")); os.IsNotExist(statErr) {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapUnsupported, Reason: "binary bun.lockb is not parsed; run `bun install` to regenerate bun.lock: " + path})
					}
				case base == "package.json":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					dirsWithPackageJSON[filepath.Dir(path)] = true
					set.addAll(parsePackageJSON(data), path)
				case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					set.addAll(parseRequirements(data), path)
				case base == "pyproject.toml":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					set.addAll(parsePyproject(data), path)
				case base == "poetry.lock" || base == "pdm.lock":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					ps, skipped := parseTOMLPackages(data, false)
					if skipped > 0 {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapTruncated, Reason: fmt.Sprintf("%d non-registry entries skipped in %s", skipped, path)})
					}
					set.addAll(ps, path)
				case base == "uv.lock":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					ps, skipped := parseTOMLPackages(data, true)
					if skipped > 0 {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapTruncated, Reason: fmt.Sprintf("%d editable/git/path packages skipped in %s", skipped, path)})
					}
					set.addAll(ps, path)
				case base == "Pipfile.lock":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					ps, perr := parsePipfileLock(data)
					if perr != nil {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapError, Reason: "cannot parse " + path + ": " + perr.Error()})
						return nil
					}
					set.addAll(ps, path)
				case base == "go.mod":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					ps, skipped := parseGoMod(data)
					if skipped > 0 {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapTruncated, Reason: fmt.Sprintf("%d local/unversioned Go replacements skipped in %s", skipped, path)})
					}
					set.addAll(ps, path)
				case base == "go.sum":
					// go.sum cannot identify the selected version; only note the
					// blind spot when go.mod is absent.
					dir := filepath.Dir(path)
					if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); os.IsNotExist(statErr) {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapUnsupported, Reason: "go.sum without go.mod cannot resolve selected module versions: " + path})
					}
				case base == "Cargo.lock":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					set.addAll(parseCargoLock(data), path)
				case base == "packages.lock.json":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					ps, perr := parseNuGetLock(data)
					if perr != nil {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapError, Reason: "cannot parse " + path + ": " + perr.Error()})
						return nil
					}
					set.addAll(ps, path)
				case base == "project.assets.json" && filepath.Base(filepath.Dir(path)) == "obj":
					data, err := os.ReadFile(path)
					if err != nil {
						return nil
					}
					ps, perr := parseProjectAssets(data)
					if perr != nil {
						gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapError, Reason: "cannot parse " + path + ": " + perr.Error()})
						return nil
					}
					set.addAll(ps, path)
				}
				return nil
			})
			if err != nil {
				gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapError, Reason: "walk failed for " + root + ": " + err.Error()})
			}
		}
	}

	gapCount := 0
	for dir := range dirsWithPackageJSON {
		if dirsWithNpmLock[dir] {
			continue
		}
		if gapCount >= 10 {
			gaps = append(gaps, scanner.CoverageGap{Module: moduleName, Kind: scanner.GapUnsupported, Reason: "additional package.json files without a lockfile were not enumerated"})
			break
		}
		gapCount++
		gaps = append(gaps, scanner.CoverageGap{
			Module: moduleName,
			Kind:   scanner.GapUnsupported,
			Reason: "package.json without an npm/yarn/pnpm/bun lockfile: version ranges are unresolved, coverage is incomplete in " + dir,
		})
	}

	if opts.ScanNodeModules && !opts.NoProject {
		for _, root := range roots {
			ps := parseNodeModules(filepath.Clean(root))
			set.addAll(ps, "node_modules")
		}
	}
	if opts.IncludeGlobal {
		ps, globalGaps := globalNpm(ctx)
		set.addAll(ps, "npm-global")
		gaps = append(gaps, globalGaps...)
	}
	if opts.OSPackages {
		ps, osGaps := inventoryOSPackages(ctx)
		set.addAll(ps, "os")
		gaps = append(gaps, osGaps...)
	}

	if !opts.IncludeDev {
		set.dropDev()
	}
	return set.list(), gaps
}

// packageSet deduplicates name@version across sources and merges flags.
type packageSet struct {
	byKey map[string]*Pkg
}

func newPackageSet() *packageSet {
	return &packageSet{byKey: map[string]*Pkg{}}
}

func packageKey(ecosystem, name, version string) string {
	return ecosystem + "|" + strings.ToLower(name) + "|" + version
}

func (s *packageSet) addAll(ps []Pkg, source string) {
	for _, p := range ps {
		if p.Name == "" || p.Version == "" {
			continue
		}
		if p.Source == "" {
			p.Source = source
		}
		key := packageKey(p.Ecosystem, p.Name, p.Version)
		if existing, ok := s.byKey[key]; ok {
			existing.Dev = existing.Dev && p.Dev
			existing.Optional = existing.Optional || p.Optional
			existing.Direct = existing.Direct || p.Direct
			continue
		}
		cp := p
		s.byKey[key] = &cp
	}
}

func (s *packageSet) dropDev() {
	for key, p := range s.byKey {
		if p.Dev {
			delete(s.byKey, key)
		}
	}
}

func (s *packageSet) list() []Pkg {
	out := make([]Pkg, 0, len(s.byKey))
	for _, p := range s.byKey {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// normalizeName canonicalizes package names for catalog matching.
func normalizeName(ecosystem, name string) string {
	n := strings.ToLower(name)
	if ecosystem == "PyPI" {
		n = strings.ReplaceAll(n, "_", "-")
		n = strings.ReplaceAll(n, ".", "-")
	}
	return n
}

var aiCatalog = map[string]map[string]bool{
	"PyPI": setOf(
		"torch", "torchvision", "torchaudio", "tensorflow", "keras", "jax", "flax",
		"transformers", "tokenizers", "safetensors", "accelerate", "peft", "trl",
		"diffusers", "sentence-transformers", "langchain", "langchain-core",
		"langchain-community", "langchain-openai", "langchain-anthropic",
		"llama-index", "llama-index-core", "gradio", "vllm", "openai", "anthropic",
		"huggingface-hub", "datasets", "mcp", "fastmcp", "ollama", "litellm",
		"autogen-agentchat", "pyautogen", "crewai", "pydantic-ai", "instructor",
		"bitsandbytes", "xformers", "onnxruntime", "mlflow", "ray", "langgraph",
		"semantic-kernel", "google-generativeai", "google-genai", "cohere",
	),
	"npm": setOf(
		"openai", "@anthropic-ai/sdk", "@modelcontextprotocol/sdk", "langchain",
		"@langchain/core", "@langchain/openai", "@langchain/anthropic", "ai",
		"ollama", "llamaindex", "@huggingface/inference", "@xenova/transformers",
		"@google/generative-ai", "@google/genai", "cohere-ai", "groq-sdk",
		"mistralai", "@mistralai/mistralai", "@ai-sdk/openai", "@ai-sdk/anthropic",
	),
}

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

func isAIPackage(ecosystem, name string) bool {
	catalog, ok := aiCatalog[ecosystem]
	if !ok {
		return false
	}
	if ecosystem == "npm" {
		return catalog[strings.ToLower(name)]
	}
	return catalog[normalizeName(ecosystem, name)]
}

func sanitizeForID(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
