// Package sarif renders enki findings as SARIF 2.1.0 for code scanning UIs.
package sarif

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/report"
)

const schemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

type document struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []rule `json:"rules,omitempty"`
}

type rule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription message        `json:"shortDescription"`
	Help             message        `json:"help,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type message struct {
	Text string `json:"text"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             message           `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type location struct {
	PhysicalLocation physical `json:"physicalLocation"`
}

type physical struct {
	ArtifactLocation artifact `json:"artifactLocation"`
	Region           *region  `json:"region,omitempty"`
}

type artifact struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
}

// Build converts a report into a SARIF document with deduplicated rules.
func Build(rep *report.Report) document {
	ruleByID := map[string]finding.Finding{}
	var ruleIDs []string
	for _, f := range rep.Findings {
		if _, ok := ruleByID[f.RuleID]; !ok {
			ruleByID[f.RuleID] = f
			ruleIDs = append(ruleIDs, f.RuleID)
		}
	}

	rules := make([]rule, 0, len(ruleIDs))
	index := map[string]int{}
	for i, id := range ruleIDs {
		f := ruleByID[id]
		index[id] = i
		rules = append(rules, rule{
			ID:               id,
			Name:             sanitizeName(f.Module),
			ShortDescription: message{Text: f.Title},
			Help:             message{Text: f.Description},
			Properties: map[string]any{
				"tags":              []string{f.Module},
				"security-severity": securityScore(f.Severity),
			},
		})
	}

	results := make([]result, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		r := result{
			RuleID:              f.RuleID,
			RuleIndex:           index[f.RuleID],
			Level:               levelOf(f.Severity),
			Message:             message{Text: f.Title + ": " + f.Description},
			PartialFingerprints: map[string]string{"enkiFinding/v1": f.ID},
			Properties: map[string]any{
				"severity":   string(f.Severity),
				"confidence": string(f.Confidence),
				"module":     f.Module,
			},
		}
		uri := f.Location.Path
		if uri == "" {
			uri = "enki:" + f.Location.Addr
		}
		phys := physical{ArtifactLocation: artifact{URI: uri}}
		if f.Location.Line > 0 {
			phys.Region = &region{StartLine: f.Location.Line}
		}
		r.Locations = []location{{PhysicalLocation: phys}}
		results = append(results, r)
	}

	return document{
		Schema:  schemaURL,
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "enki",
				Version:        rep.Tool.Version,
				InformationURI: "https://github.com/yogenpoonudurai/enki",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// Write emits SARIF JSON to w.
func Write(w io.Writer, rep *report.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Build(rep))
}

func levelOf(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func securityScore(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "9.5"
	case finding.SeverityHigh:
		return "8.0"
	case finding.SeverityMedium:
		return "5.5"
	case finding.SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
}

func sanitizeName(s string) string {
	if s == "" {
		return "enki"
	}
	return strings.ReplaceAll(s, " ", "-")
}
