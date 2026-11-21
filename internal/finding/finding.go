// Package finding defines enki's normalized finding model shared by every
// scanner module and reporter.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Severity is ordered from least to most severe. The string values are the
// wire format used in JSON, SARIF, and OCSF outputs.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Order returns the severity rank (INFO=0 … CRITICAL=4).
func (s Severity) Order() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func ParseSeverity(v string) (Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "INFO":
		return SeverityInfo, true
	case "LOW":
		return SeverityLow, true
	case "MEDIUM", "MED":
		return SeverityMedium, true
	case "HIGH":
		return SeverityHigh, true
	case "CRITICAL", "CRIT":
		return SeverityCritical, true
	}
	return "", false
}

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// ActionClass classifies how safe an automated remediation is.
type ActionClass string

const (
	ActionSafe     ActionClass = "safe"
	ActionModerate ActionClass = "moderate"
	ActionRisky    ActionClass = "risky"
)

// Location identifies where a finding was observed. At least one field is set.
type Location struct {
	Path string `json:"path,omitempty"`
	Line int    `json:"line,omitempty"`
	Addr string `json:"addr,omitempty"` // host:port for network findings
}

func (l Location) String() string {
	switch {
	case l.Path != "" && l.Line > 0:
		return fmt.Sprintf("%s:%d", l.Path, l.Line)
	case l.Path != "":
		return l.Path
	case l.Addr != "":
		return l.Addr
	}
	return ""
}

// Remediation describes an optional response action for a finding.
type Remediation struct {
	Class    ActionClass       `json:"class"`
	Summary  string            `json:"summary"`            // e.g. "chmod 600 ~/.config/ai/.env"
	Action   string            `json:"action,omitempty"`   // machine action: chmod_private | remove_json_key | firewall_block
	Params   map[string]string `json:"params,omitempty"`   // action parameters (path, key path, port)
	Command  string            `json:"command,omitempty"`  // exact command for risky/guided actions
	Guidance string            `json:"guidance,omitempty"` // human instructions when no command exists
}

// Finding is the single normalized result type produced by all modules.
type Finding struct {
	ID          string       `json:"id"`
	RuleID      string       `json:"rule_id"`
	Module      string       `json:"module"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Severity    Severity     `json:"severity"`
	Confidence  Confidence   `json:"confidence"`
	Location    Location     `json:"location"`
	Evidence    string       `json:"evidence,omitempty"`
	References  []string     `json:"references,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty"`
	Tags        []string     `json:"tags,omitempty"`
}

// New constructs a finding and derives its stable instance ID.
func New(ruleID, module, title, description string, sev Severity, conf Confidence, loc Location) Finding {
	return Finding{
		ID:          instanceID(ruleID, loc),
		RuleID:      ruleID,
		Module:      module,
		Title:       title,
		Description: description,
		Severity:    sev,
		Confidence:  conf,
		Location:    loc,
	}
}

func instanceID(ruleID string, loc Location) string {
	sum := sha256.Sum256([]byte(ruleID + "|" + loc.Path + "|" + loc.Addr))
	return ruleID + "-" + hex.EncodeToString(sum[:])[:8]
}

// Sort orders findings by severity (descending), then rule ID, then location.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity.Order() != fs[j].Severity.Order() {
			return fs[i].Severity.Order() > fs[j].Severity.Order()
		}
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		return fs[i].Location.String() < fs[j].Location.String()
	})
}
