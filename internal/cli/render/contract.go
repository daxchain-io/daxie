package render

import (
	"io"
	"strconv"

	"github.com/daxchain-io/daxie/internal/domain"
)

// contract.go holds the human renderers for the M10 `daxie contract` views
// (cli-spec §`daxie contract`). It formats only — the --json form is the domain
// struct marshaled by Result; these funcs are the human-mode branch. No float
// anywhere (§2.5): every value is already an exact string on the domain result.
//
// This file is a FRONTEND leaf: it imports domain (the wire contract) but no
// provider — the arch matrix + the M10 per-file guard enforce it.

// ContractCallResult writes the `contract call` view: each labeled return on its own
// line (the values are the essential output, printed even under --quiet via the table).
func ContractCallResult(w io.Writer, m Mode, r domain.ContractCallResult) {
	if len(r.Returns) == 0 {
		_, _ = io.WriteString(w, "(no return values)\n")
	} else {
		tbl := NewTable(w)
		for _, v := range r.Returns {
			name := v.Name
			if name == "" {
				name = v.Type
			}
			tbl.Row(name, v.Value)
		}
		_ = tbl.Flush()
	}
	Line(w, m, "method:   %s", r.Method)
	Line(w, m, "contract: %s", destAddr(r.Contract))
	Line(w, m, "network:  %s", r.Network)
}

// EncodeResult writes the `contract encode` view: the 0x calldata is the essential
// output (printed even under --quiet).
func EncodeResult(w io.Writer, _ Mode, r domain.EncodeResult) {
	_, _ = io.WriteString(w, r.Calldata+"\n")
}

// DecodeResult writes the `contract decode` view: the method + selector + the decoded
// labeled args.
func DecodeResult(w io.Writer, m Mode, r domain.DecodeResult) {
	_, _ = io.WriteString(w, r.Method+"\n")
	Line(w, m, "selector: %s", r.Selector)
	if len(r.Args) > 0 {
		tbl := NewTable(w)
		for _, a := range r.Args {
			name := a.Name
			if name == "" {
				name = a.Type
			}
			tbl.Row(name, a.Type, a.Value)
		}
		_ = tbl.Flush()
	}
}

// ContractLogs writes the `contract logs` view: one block per decoded log with its
// location header + the labeled args.
func ContractLogs(w io.Writer, m Mode, r domain.ContractLogsResult) {
	if len(r.Logs) == 0 {
		_, _ = io.WriteString(w, "(no matching logs)\n")
		Line(w, m, "event:   %s", r.Event)
		Line(w, m, "network: %s", r.Network)
		return
	}
	for _, lg := range r.Logs {
		_, _ = io.WriteString(w, lg.Event+" @ block "+strconv.FormatUint(lg.Block, 10)+" tx "+lg.TxHash+"\n")
		for _, a := range lg.Args {
			name := a.Name
			if name == "" {
				name = a.Type
			}
			Line(w, m, "  %s = %s", name, a.Value)
		}
	}
	Line(w, m, "network: %s", r.Network)
}

// ContractRow writes the `contract add`/`show` single-row view: the alias→address
// binding plus, for `show`, the function/event signatures.
func ContractRow(w io.Writer, m Mode, r domain.ContractRow) {
	_, _ = io.WriteString(w, r.Address+"\n")
	Line(w, m, "alias:     %s", r.Alias)
	Line(w, m, "network:   %s", r.Network)
	Line(w, m, "functions: %d", r.FuncCount)
	Line(w, m, "events:    %d", r.EvtCount)
	for _, f := range r.Functions {
		Line(w, m, "  fn    %s", f)
	}
	for _, e := range r.Events {
		Line(w, m, "  event %s", e)
	}
}

// ContractList writes the `contract list` view as an alias-sorted aligned table.
func ContractList(w io.Writer, m Mode, r domain.ContractListResult) {
	if len(r.Contracts) == 0 {
		_, _ = io.WriteString(w, "(no contracts registered)\n")
		return
	}
	tbl := NewTable(w)
	if !m.Quiet {
		tbl.Row("ALIAS", "ADDRESS", "FUNCTIONS", "EVENTS")
	}
	for _, c := range r.Contracts {
		tbl.Row(c.Alias, c.Address, strconv.Itoa(c.FuncCount), strconv.Itoa(c.EvtCount))
	}
	_ = tbl.Flush()
}

// destAddr renders a Dest as its human label (the alias/name when present, else the
// 0x address).
func destAddr(d domain.Dest) string {
	if d.Name != "" {
		return d.Name + " (" + d.Address.Hex() + ")"
	}
	return d.Address.Hex()
}
