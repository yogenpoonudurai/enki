package sbom

import (
	"bufio"
	"strings"
)

// parseCargoLock extracts registry packages from Cargo.lock. Entries without
// a source are workspace members and are skipped.
func parseCargoLock(data []byte) []Pkg {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var out []Pkg
	inBlock := false
	var name, version, source string
	flush := func() {
		if inBlock && name != "" && version != "" && source != "" {
			out = append(out, Pkg{Name: name, Version: version, Ecosystem: "crates.io"})
		}
		name, version, source = "", "", ""
	}
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		switch {
		case t == "[[package]]":
			flush()
			inBlock = true
		case strings.HasPrefix(t, "name = "):
			if inBlock {
				name = unquoteTOML(strings.TrimPrefix(t, "name = "))
			}
		case strings.HasPrefix(t, "version = "):
			if inBlock {
				version = unquoteTOML(strings.TrimPrefix(t, "version = "))
			}
		case strings.HasPrefix(t, "source = "):
			if inBlock {
				source = t
			}
		}
	}
	flush()
	return out
}
