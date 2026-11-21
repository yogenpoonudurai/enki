package sbom

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/yogenpoonudurai/enki/internal/finding"
)

// CycloneDX is a minimal CycloneDX 1.5 BOM.
type CycloneDX struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Version         int                `json:"version"`
	Metadata        CdxMetadata        `json:"metadata"`
	Components      []CdxComponent     `json:"components"`
	Vulnerabilities []CdxVulnerability `json:"vulnerabilities,omitempty"`
}

type CdxMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []CdxTool `json:"tools"`
}

type CdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CdxComponent struct {
	Type       string        `json:"type"`
	BomRef     string        `json:"bom-ref"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	Purl       string        `json:"purl,omitempty"`
	Scope      string        `json:"scope,omitempty"`
	Properties []CdxProperty `json:"properties,omitempty"`
}

type CdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CdxVulnerability struct {
	ID          string      `json:"id"`
	Source      CdxSource   `json:"source"`
	Description string      `json:"description,omitempty"`
	Ratings     []CdxRating `json:"ratings,omitempty"`
	Affects     []CdxAffect `json:"affects"`
}

type CdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type CdxRating struct {
	Method   string  `json:"method,omitempty"`
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity,omitempty"`
}

type CdxAffect struct {
	Ref string `json:"ref"`
}

// PkgRef is the stable component reference for a package.
func PkgRef(p Pkg) string {
	return p.Ecosystem + ":" + p.Name + "@" + p.Version
}

// BuildCycloneDX assembles a CycloneDX BOM. vulns is keyed by PkgRef and may
// be nil when vulnerability enrichment is not requested.
func BuildCycloneDX(pkgs []Pkg, toolVersion string, vulns map[string][]*Advisory) *CycloneDX {
	bom := &CycloneDX{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: newBOMSerial(),
		Version:      1,
		Metadata: CdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools:     []CdxTool{{Vendor: "Enki", Name: "enki", Version: toolVersion}},
		},
	}

	for _, p := range pkgs {
		comp := CdxComponent{
			Type:    componentType(p),
			BomRef:  PkgRef(p),
			Name:    p.Name,
			Version: p.Version,
			Purl:    purlFor(p),
		}
		if p.Dev || p.Optional {
			comp.Scope = "optional"
		}
		comp.Properties = []CdxProperty{
			{Name: "enki:ecosystem", Value: p.Ecosystem},
			{Name: "enki:source", Value: p.Source},
		}
		if p.Dev {
			comp.Properties = append(comp.Properties, CdxProperty{Name: "enki:dev", Value: "true"})
		}
		if p.Direct {
			comp.Properties = append(comp.Properties, CdxProperty{Name: "enki:direct", Value: "true"})
		}
		bom.Components = append(bom.Components, comp)
	}

	if len(vulns) > 0 {
		byID := map[string]*CdxVulnerability{}
		for _, p := range pkgs {
			ref := PkgRef(p)
			for _, adv := range vulns[ref] {
				key := groupKey(adv)
				if existing, ok := byID[key]; ok {
					existing.Affects = appendAffect(existing.Affects, ref)
					continue
				}
				v := &CdxVulnerability{
					ID:          adv.ID,
					Source:      CdxSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + adv.ID},
					Description: adv.Summary,
					Ratings: []CdxRating{{
						Method:   "CVSSv31",
						Score:    adv.CVSS,
						Severity: cdxSeverity(adv.Severity),
					}},
					Affects: []CdxAffect{{Ref: ref}},
				}
				byID[key] = v
			}
		}
		for _, v := range byID {
			bom.Vulnerabilities = append(bom.Vulnerabilities, *v)
		}
		sort.Slice(bom.Vulnerabilities, func(i, j int) bool {
			return bom.Vulnerabilities[i].ID < bom.Vulnerabilities[j].ID
		})
	}
	return bom
}

// Write emits the BOM as indented JSON.
func (b *CycloneDX) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(b)
}

func appendAffect(list []CdxAffect, ref string) []CdxAffect {
	for _, a := range list {
		if a.Ref == ref {
			return list
		}
	}
	return append(list, CdxAffect{Ref: ref})
}

func componentType(p Pkg) string {
	if isOSPackage(p.Ecosystem) {
		return "operating-system"
	}
	return "library"
}

func isOSPackage(eco string) bool {
	for _, prefix := range []string{"Debian:", "Ubuntu:", "Alpine:", "Rocky Linux:", "AlmaLinux:", "OS"} {
		if strings.HasPrefix(eco, prefix) {
			return true
		}
	}
	return false
}

func purlFor(p Pkg) string {
	name := p.Name
	switch {
	case p.Ecosystem == "npm":
		return "pkg:npm/" + strings.ReplaceAll(name, "@", "%40") + "@" + p.Version
	case p.Ecosystem == "PyPI":
		return "pkg:pypi/" + normalizeName("PyPI", name) + "@" + p.Version
	case p.Ecosystem == "Go":
		return "pkg:golang/" + name + "@" + p.Version
	case p.Ecosystem == "crates.io":
		return "pkg:cargo/" + name + "@" + p.Version
	case p.Ecosystem == "NuGet":
		return "pkg:nuget/" + name + "@" + p.Version
	case strings.HasPrefix(p.Ecosystem, "Debian:"):
		return "pkg:deb/debian/" + name + "@" + p.Version
	case strings.HasPrefix(p.Ecosystem, "Ubuntu:"):
		return "pkg:deb/ubuntu/" + name + "@" + p.Version
	case strings.HasPrefix(p.Ecosystem, "Alpine:"):
		return "pkg:apk/alpine/" + name + "@" + p.Version
	case strings.HasPrefix(p.Ecosystem, "Rocky Linux:"):
		return "pkg:rpm/rocky-linux/" + name + "@" + p.Version
	case strings.HasPrefix(p.Ecosystem, "AlmaLinux:"):
		return "pkg:rpm/almalinux/" + name + "@" + p.Version
	}
	return ""
}

func cdxSeverity(s finding.Severity) string {
	return strings.ToLower(string(s))
}

func newBOMSerial() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "urn:uuid:00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// IsAIPackage exposes the catalog filter for the sbom command.
func IsAIPackage(ecosystem, name string) bool { return isAIPackage(ecosystem, name) }

// NewClient returns the default OSV client.
func NewClient() Client { return newClient() }
