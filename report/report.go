// Package report renders a model.Report. (Stub: replaced by the real implementation.)
package report

import (
	"encoding/json"
	"io"

	"github.com/nguyenquocanhz/diagward/model"
)

// Options control rendering.
type Options struct {
	Lang    string // "vi" or "en"
	Color   bool   // ANSI colours (Text only)
	ASCII   bool   // Text: no box drawing or symbols outside ASCII
	Width   int    // terminal width for Text (0 = 100)
	Verbose bool   // Text: include tables, coverage and evidence
}

// Text renders for a terminal.
func Text(w io.Writer, r *model.Report, o Options) error { return JSON(w, r) }

// HTML renders a self-contained HTML file.
func HTML(w io.Writer, r *model.Report, o Options) error { return JSON(w, r) }

// Markdown renders for tickets and chat.
func Markdown(w io.Writer, r *model.Report, o Options) error { return JSON(w, r) }

// JSON renders the report as indented JSON.
func JSON(w io.Writer, r *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
