//go:build !linux

package sbom

import (
	"context"

	"github.com/yogenpoonudurai/enki/internal/scanner"
)

// inventoryOSPackages is Linux-only; other platforms report nothing.
func inventoryOSPackages(ctx context.Context) ([]Pkg, []scanner.CoverageGap) {
	return nil, nil
}
