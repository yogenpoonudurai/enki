//go:build windows

package remediate

import "os"

func fileOwner(os.FileInfo) (int, int) { return -1, -1 }

func preserveOwner(string, int, int) error { return nil }
