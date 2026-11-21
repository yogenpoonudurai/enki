package ai

import (
	"strings"
	"testing"
)

func TestWriteHumanFixPlan(t *testing.T) {
	rep := sampleReport()
	res := &TriageResult{
		Summary:      "Start with the exposed credential.",
		FindingsSent: 3,
		Cost:         Cost{Model: "qwen2.5:3b", InputTokens: 100, OutputTokens: 50},
		Top: []TriageItem{
			{
				FindingID: "sec", RuleID: "SEC-001", Priority: 1, Why: "plaintext key",
				FixSteps:          []string{"chmod 600 .env", "rotate the key"},
				RecommendedAction: "chmod_private", ActionVerified: true,
			},
			{
				FindingID: "mcp", RuleID: "MCP-001", Priority: 2, Why: "pin it",
				FixSteps:          []string{"pin the package"},
				RecommendedAction: "npm/yarn", ActionVerified: false,
			},
		},
	}

	var b strings.Builder
	WriteHuman(&b, res, rep)
	out := b.String()

	for _, want := range []string{
		"enki triage · qwen2.5:3b",
		"score 40",
		"1. [HIGH] SEC-001",
		"enki fix (authoritative): chmod 0600 '/home/alice/project/.env'",
		"AI-suggested steps (verify before running):",
		"1. chmod 600 .env",
		"2. rotate the key",
		"Action: chmod_private (verified enki action)",
		"2. [HIGH] MCP-001",
		"Action: npm/yarn — NOT VERIFIED",
		"Cost: none",
		"AI advice only",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}
