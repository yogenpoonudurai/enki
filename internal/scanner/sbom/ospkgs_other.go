//go:build !linux

package sbom

import (
	"context"

	"github.com/yogenpoonudurai/enki/internal/scanner"
)

// inventoryOSPackages is Linux-only; other platforms report the gap.
func inventoryOSPackages(ctx context.Context) ([]Pkg, []scanner.CoverageGap) {
	return nil, []scanner.CoverageGap{{
		Module: moduleName,
		Kind:   scanner.GapUnsupported,
		Reason: "OS package inventory is Linux-only",
	}}
}
