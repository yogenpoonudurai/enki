package jsonout

import (
	"encoding/json"
	"io"

	"github.com/yogenpoonudurai/enki/internal/report"
)

// Write emits the report as indented JSON.
func Write(w io.Writer, rep *report.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
