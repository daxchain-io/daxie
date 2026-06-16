package render

import (
	"encoding/json"
	"io"

	"github.com/daxchain-io/daxie/internal/domain"
)

// Result writes a successful command result.
//
//   - In JSON mode it marshals jsonValue as a single indented object on w
//     (stdout keeps the single-result contract, §5.7) and ignores the human func.
//   - Otherwise it calls human(w) to render the table, honoring Quiet through the
//     caller's use of Line/Table.
//
// Marshaling errors are returned (they indicate a programming bug in a result
// struct) so the caller funnels them through the error registry as `internal`.
func Result(w io.Writer, m Mode, jsonValue any, human func(io.Writer)) error {
	if m.JSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(jsonValue)
	}
	if human != nil {
		human(w)
	}
	return nil
}

// errEnvelope is the §5.7 wire shape: {"error":{...}}. domain.Error already
// marshals to {"code","exit","message","retryable","data"}, so we wrap it under
// the "error" key for the on-stderr JSON form.
type errEnvelope struct {
	Error *domain.Error `json:"error"`
}

// ErrorEnvelope writes the §5.7 error rendering to stderr and returns the exit
// code carried by the error.
//
//   - JSON mode: the structured envelope {"error":{...}} as one line on stderr.
//   - Human mode: a single "daxie: <message> (<code>)" line on stderr.
//
// Quiet does NOT suppress errors — a failing command must always say why on
// stderr; --quiet only trims success chatter.
func ErrorEnvelope(stderr io.Writer, m Mode, e *domain.Error) domain.ExitCode {
	if m.JSON {
		enc := json.NewEncoder(stderr)
		enc.SetEscapeHTML(false)
		// Encode emits a trailing newline (one JSON object per line on stderr).
		_ = enc.Encode(errEnvelope{Error: e})
		return e.Exit
	}
	msg := e.Msg
	if msg == "" {
		msg = e.Code
	}
	// Best-effort; a stderr write failure cannot itself be reported anywhere.
	_, _ = io.WriteString(stderr, "daxie: "+msg+" ("+e.Code+")\n")
	return e.Exit
}
