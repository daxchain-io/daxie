// Package render holds the cli frontend's output-formatting helpers: the human
// table writer and the --json marshaling (result + error envelope). The
// typed-error → exit-code MAPPING lives one level up in cli/render.go (§5.7);
// this subpackage only formats. It imports domain (the wire contract) but no
// provider — it is part of the frontend layer.
//
// Terminal QR rendering and the receive NDJSON stream are later milestones; this
// package leaves clean seams for them (the Mode struct + the single Result/
// ErrorEnvelope entry points) and implements neither in M0.
package render

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// Mode selects output style. The whole frontend threads one Mode value so the
// --json / --quiet choice is made once and never re-derived per command.
type Mode struct {
	JSON  bool // --json: machine output (single JSON object on stdout)
	Quiet bool // --quiet: suppress non-essential human lines
}

// Table is a small helper for building aligned human output. Commands construct
// one, add rows, and Flush to the writer. It is intentionally tiny — the design
// rejects a Renderer interface (§2.1.1); a couple of concrete helpers suffice.
type Table struct {
	w    *tabwriter.Writer
	rows int
}

// NewTable returns a Table writing tab-aligned columns to w.
func NewTable(w io.Writer) *Table {
	return &Table{w: tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)}
}

// Row writes one tab-separated row. Cells are joined with a tab so tabwriter
// aligns columns.
func (t *Table) Row(cells ...string) {
	// tabwriter buffers; write errors (if any) surface from Flush, not here.
	for i, c := range cells {
		if i > 0 {
			_, _ = fmt.Fprint(t.w, "\t")
		}
		_, _ = fmt.Fprint(t.w, c)
	}
	_, _ = fmt.Fprintln(t.w)
	t.rows++
}

// Flush aligns and emits all buffered rows.
func (t *Table) Flush() error { return t.w.Flush() }

// Line writes a single human line to w, suppressed when Mode.Quiet. Use it for
// progress/labels that are noise to a script. Essential output (the actual
// result value) must NOT go through Line — it always prints.
func Line(w io.Writer, m Mode, format string, args ...any) {
	if m.Quiet {
		return
	}
	// Best-effort progress line; a terminal write failure is unrecoverable here.
	_, _ = fmt.Fprintf(w, format+"\n", args...)
}
