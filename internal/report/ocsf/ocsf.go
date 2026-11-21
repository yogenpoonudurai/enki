// Package ocsf renders enki findings as OCSF Detection Finding (class 2004)
// events for SIEM ingestion.
package ocsf

import (
	"encoding/json"
	"io"

	"github.com/yogenpoonudurai/enki/internal/finding"
	"github.com/yogenpoonudurai/enki/internal/report"
)

const ocsfVersion = "1.1.0"

type Metadata struct {
	Version string  `json:"version"`
	Product Product `json:"product"`
}

type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

type FindingInfo struct {
	UID         string   `json:"uid"`
	Title       string   `json:"title"`
	Desc        string   `json:"desc,omitempty"`
	Types       []string `json:"types,omitempty"`
	CreatedTime int64    `json:"created_time,omitempty"`
}

type Resource struct {
	UID  string `json:"uid"`
	Type string `json:"type"`
}

type Remediation struct {
	Desc  string `json:"desc,omitempty"`
	KBURL string `json:"kb_url,omitempty"`
}

type Event struct {
	ClassUID     int          `json:"class_uid"`
	ClassName    string       `json:"class_name"`
	CategoryUID  int          `json:"category_uid"`
	CategoryName string       `json:"category_name"`
	ActivityID   int          `json:"activity_id"`
	ActivityName string       `json:"activity_name"`
	TypeUID      int          `json:"type_uid"`
	SeverityID   int          `json:"severity_id"`
	Severity     string       `json:"severity"`
	ConfidenceID int          `json:"confidence_id,omitempty"`
	Time         int64        `json:"time"`
	Metadata     Metadata     `json:"metadata"`
	FindingInfo  FindingInfo  `json:"finding_info"`
	Resources    []Resource   `json:"resources,omitempty"`
	Remediation  *Remediation `json:"remediation,omitempty"`
	Scope        string       `json:"scope,omitempty"`
	Category     string       `json:"category,omitempty"`
	Basis        string       `json:"basis,omitempty"`
}

// Build converts a report into OCSF detection finding events.
func Build(rep *report.Report) []Event {
	events := make([]Event, 0, len(rep.Findings))
	created := rep.Scan.StartedAt.UnixMilli()
	scope := rep.Scan.Scope
	if scope == "" {
		scope = "full"
	}
	for _, f := range rep.Findings {
		ev := Event{
			ClassUID:     2004,
			ClassName:    "Detection Finding",
			CategoryUID:  2,
			CategoryName: "Findings",
			ActivityID:   1,
			ActivityName: "Create",
			TypeUID:      200401,
			SeverityID:   severityID(f.Severity),
			Severity:     string(f.Severity),
			ConfidenceID: confidenceID(f.Confidence),
			Time:         created,
			Scope:        scope,
			Category:     string(f.Category),
			Basis:        string(f.Basis),
			Metadata: Metadata{
				Version: ocsfVersion,
				Product: Product{Name: "enki", VendorName: "Enki", Version: rep.Tool.Version},
			},
			FindingInfo: FindingInfo{
				UID:         f.ID,
				Title:       f.Title,
				Desc:        f.Description,
				Types:       []string{f.RuleID},
				CreatedTime: created,
			},
		}
		if loc := f.Location.String(); loc != "" {
			typ := "File"
			if f.Location.Path == "" {
				typ = "Network Endpoint"
			}
			ev.Resources = []Resource{{UID: loc, Type: typ}}
		}
		if f.Remediation != nil {
			ev.Remediation = &Remediation{Desc: f.Remediation.Summary}
		}
		events = append(events, ev)
	}
	return events
}

// Write emits OCSF events as an indented JSON array.
func Write(w io.Writer, rep *report.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Build(rep))
}

func severityID(s finding.Severity) int {
	switch s {
	case finding.SeverityCritical:
		return 5
	case finding.SeverityHigh:
		return 4
	case finding.SeverityMedium:
		return 3
	case finding.SeverityLow:
		return 2
	default:
		return 1
	}
}

func confidenceID(c finding.Confidence) int {
	switch c {
	case finding.ConfidenceHigh:
		return 3
	case finding.ConfidenceMedium:
		return 2
	case finding.ConfidenceLow:
		return 1
	default:
		return 0
	}
}
