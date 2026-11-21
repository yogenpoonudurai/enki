// Package rules holds the built-in rule catalog metadata. Detection logic
// lives in the scanner modules; this catalog powers `enki rules list|validate`
// and keeps IDs, modules, and severities documented in one place.
package rules

import "github.com/yogenpoonudurai/enki/internal/finding"

// Version identifies the built-in rule pack in reports.
const Version = "builtin-1"

type Rule struct {
	ID       string           `json:"id"`
	Module   string           `json:"module"`
	Severity string           `json:"severity"`
	Category finding.Category `json:"category"`
	Basis    finding.Basis    `json:"basis"`
	Title    string           `json:"title"`
}

// Catalog lists every built-in rule.
var Catalog = []Rule{
	{"AEP-001", "endpoint-exposure", "CRITICAL/HIGH", finding.CategoryExposure, finding.BasisConditional, "AI service exposed on a network address"},
	{"AEP-002", "endpoint-exposure", "MEDIUM", finding.CategoryExposure, finding.BasisConfirmed, "Loopback AI service reflects arbitrary CORS origins"},
	{"AEP-003", "endpoint-exposure", "HIGH", finding.CategoryExposure, finding.BasisConfirmed, "Gradio app shared through a public tunnel"},
	{"AEP-004", "endpoint-exposure", "HIGH", finding.CategoryExposure, finding.BasisConfirmed, "Jupyter API reachable without a token"},

	{"MCP-001", "mcp", "MEDIUM", finding.CategoryUnsafeConfig, finding.BasisConditional, "Unpinned MCP server package"},
	{"MCP-002", "mcp", "MEDIUM", finding.CategoryUnsafeConfig, finding.BasisConfirmed, "Remote MCP server uses plaintext HTTP"},
	{"MCP-003", "mcp", "HIGH", finding.CategoryExposure, finding.BasisConfirmed, "MCP server embeds a credential"},
	{"MCP-004", "mcp", "MEDIUM", finding.CategoryUnsafeConfig, finding.BasisConfirmed, "MCP server has broad filesystem access"},
	{"MCP-005", "mcp", "INFO", finding.CategoryHygiene, finding.BasisPresence, "MCP server exposes command execution"},
	{"MCP-006", "mcp", "MEDIUM", finding.CategoryHygiene, finding.BasisConfirmed, "MCP config is world-readable"},

	{"SEC-001", "secrets", "HIGH/CRITICAL", finding.CategoryVulnerability, finding.BasisConfirmed, "Provider key in a plaintext file"},
	{"SEC-002", "secrets", "MEDIUM/HIGH", finding.CategoryVulnerability, finding.BasisConfirmed, "Provider key in shell history"},
	{"SEC-003", "secrets", "MEDIUM", finding.CategoryHygiene, finding.BasisConfirmed, "Credential file is readable by other users"},
	{"SEC-004", "secrets", "MEDIUM", finding.CategoryVulnerability, finding.BasisConfirmed, "Hugging Face token stored in plaintext"},

	{"AGT-001", "agent-permissions", "HIGH", finding.CategoryUnsafeConfig, finding.BasisConfirmed, "Agent runs with bypassPermissions or equivalent flag"},
	{"AGT-002", "agent-permissions", "MEDIUM", finding.CategoryUnsafeConfig, finding.BasisConfirmed, "Agent allow-list grants unrestricted shell"},
	{"AGT-003", "agent-permissions", "MEDIUM", finding.CategoryUnsafeConfig, finding.BasisConfirmed, "Agent auto-approves tool actions"},
	{"AGT-004", "agent-permissions", "HIGH", finding.CategoryUnsafeConfig, finding.BasisConfirmed, "Agent may modify sensitive credential paths"},

	{"MDL-001", "model-artifacts", "LOW", finding.CategoryHygiene, finding.BasisPresence, "Pickle-based weight files present"},
	{"MDL-002", "model-artifacts", "HIGH", finding.CategoryUnsafeConfig, finding.BasisConditional, "trust_remote_code enabled"},
	{"MDL-003", "model-artifacts", "MEDIUM", finding.CategoryUnsafeConfig, finding.BasisConditional, "torch.load without weights_only"},
	{"MDL-004", "model-artifacts", "MEDIUM", finding.CategoryUnsafeConfig, finding.BasisConfirmed, "Model weights downloaded over plain HTTP"},

	{"SBOM-001", "sbom", "advisory", finding.CategoryVulnerability, finding.BasisConfirmed, "AI dependency affected by an OSV advisory"},
}

// Validate reports catalog problems: empty fields, duplicate IDs, and modules
// that are not part of the scanner registry.
func Validate(knownModules []string) []string {
	known := make(map[string]bool, len(knownModules))
	for _, m := range knownModules {
		known[m] = true
	}
	var problems []string
	seen := map[string]bool{}
	for _, r := range Catalog {
		if r.ID == "" || r.Module == "" || r.Title == "" || r.Severity == "" {
			problems = append(problems, "rule with empty field: "+r.ID)
		}
		if !r.Category.Valid() {
			problems = append(problems, "invalid category "+string(r.Category)+" for rule "+r.ID)
		}
		if !r.Basis.Valid() {
			problems = append(problems, "invalid basis "+string(r.Basis)+" for rule "+r.ID)
		}
		if seen[r.ID] {
			problems = append(problems, "duplicate rule ID: "+r.ID)
		}
		seen[r.ID] = true
		if !known[r.Module] {
			problems = append(problems, "unknown module "+r.Module+" for rule "+r.ID)
		}
	}
	return problems
}
