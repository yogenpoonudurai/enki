package sbom

import (
	"math"
	"strings"

	"github.com/yogenpoonudurai/enki/internal/finding"
)

var (
	avWeight  = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acWeight  = map[string]float64{"L": 0.77, "H": 0.44}
	uiWeight  = map[string]float64{"N": 0.85, "R": 0.62}
	ciaWeight = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	prWeightU = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prWeightC = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
)

// cvssV3BaseScore computes the CVSS v3.0/v3.1 base score from a vector string.
func cvssV3BaseScore(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	if !strings.HasPrefix(vector, "CVSS:3.0/") && !strings.HasPrefix(vector, "CVSS:3.1/") {
		return 0, false
	}
	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	scopeChanged := metrics["S"] == "C"
	prTable := prWeightU
	if scopeChanged {
		prTable = prWeightC
	}

	av, ok1 := avWeight[metrics["AV"]]
	ac, ok2 := acWeight[metrics["AC"]]
	pr, ok3 := prTable[metrics["PR"]]
	ui, ok4 := uiWeight[metrics["UI"]]
	c, ok5 := ciaWeight[metrics["C"]]
	i, ok6 := ciaWeight[metrics["I"]]
	a, ok7 := ciaWeight[metrics["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}

	var score float64
	if scopeChanged {
		score = math.Min(1.08*(impact+exploitability), 10)
	} else {
		score = math.Min(impact+exploitability, 10)
	}
	return roundup(score), true
}

// roundup matches the CVSS v3.1 specification: round to six decimals, then
// ceiling to one decimal.
func roundup(x float64) float64 {
	intInput := math.Round(x*1000000) / 1000000
	if intInput == math.Trunc(intInput) {
		return intInput
	}
	return math.Ceil(intInput*10) / 10
}

func severityFromScore(score float64) finding.Severity {
	switch {
	case score >= 9.0:
		return finding.SeverityCritical
	case score >= 7.0:
		return finding.SeverityHigh
	case score >= 4.0:
		return finding.SeverityMedium
	case score > 0:
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

func severityFromVector(vector string) (finding.Severity, float64, bool) {
	score, ok := cvssV3BaseScore(vector)
	if !ok {
		return "", 0, false
	}
	return severityFromScore(score), score, true
}
