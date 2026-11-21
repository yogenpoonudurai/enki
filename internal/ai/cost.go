package ai

import "time"

// Pricing is USD per 1M tokens at off-peak rates.
type Pricing struct {
	InputPerM  float64
	OutputPerM float64
}

// PricingTable covers the models enki knows about; unknown models report 0.
var PricingTable = map[string]Pricing{
	"deepseek-flash":  {InputPerM: 0.15, OutputPerM: 0.60},
	"deepseek-v4-pro": {InputPerM: 0.66, OutputPerM: 1.98},
}

// IsMetered reports whether enki has pricing for this model.
func IsMetered(model string) bool {
	_, ok := PricingTable[model]
	return ok
}

// EstimateUSD returns the estimated cost; peak hours are double off-peak.
func EstimateUSD(model string, inputTokens, outputTokens int, peak bool) float64 {
	p, ok := PricingTable[model]
	if !ok {
		return 0
	}
	factor := 1.0
	if peak {
		factor = 2.0
	}
	return (float64(inputTokens)/1e6)*p.InputPerM*factor +
		(float64(outputTokens)/1e6)*p.OutputPerM*factor
}

// IsPeak reports DeepSeek's peak window: 01:00-04:00 and 06:00-10:00 UTC on
// weekdays.
func IsPeak(t time.Time) bool {
	t = t.UTC()
	if t.Weekday() == time.Saturday || t.Weekday() == time.Sunday {
		return false
	}
	h := t.Hour()
	return (h >= 1 && h < 4) || (h >= 6 && h < 10)
}
