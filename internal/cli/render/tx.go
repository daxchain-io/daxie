package render

import (
	"io"
	"strconv"

	"github.com/daxchain-io/daxie/internal/domain"
)

// tx.go holds the human renderers for the M3 tx pipeline + gas + contacts results
// (cli-spec §`daxie tx`/§`daxie gas`/§`daxie contacts`). It formats only — the
// --json form is the domain struct marshaled by Result; these funcs are the
// human-mode branch. Every helper honors Mode.Quiet via render.Line for the
// non-essential context lines while always printing the one essential value
// (the hash for a send, the base fee + speeds for gas, the table for contacts).
//
// No float anywhere (§2.5): every fee/amount is already a decimal string on the
// domain result; we print it verbatim.

// TxResult writes the human view of a broadcast/awaited transaction. The HASH is
// the essential output (printed even under --quiet, like the balance value) so a
// script reading stdout always gets it; the from/to/nonce/gas/status context is
// non-essential chatter via Line.
func TxResult(w io.Writer, m Mode, r domain.TxResult) {
	// The hash is the one thing every caller wants on stdout. A dry-run has no
	// hash yet (nothing signed) — fall back to the resolved destination so the
	// preview still emits an essential line.
	if r.Hash != "" {
		_, _ = io.WriteString(w, r.Hash+"\n")
	}
	to := r.To.Address.Hex()
	if r.To.Name != "" {
		to = r.To.Name + " (" + to + ")"
	}
	Line(w, m, "from:    %s", r.From.Hex())
	Line(w, m, "to:      %s", to)
	Line(w, m, "amount:  %s wei", r.AmountWei)
	Line(w, m, "nonce:   %d", r.Nonce)
	Line(w, m, "status:  %s", string(r.Status))
	if r.Confirmations > 0 {
		Line(w, m, "confirmations: %d", r.Confirmations)
	}
	if r.BlockNumber != nil {
		Line(w, m, "block:   %d", *r.BlockNumber)
	}
	renderGasLines(w, m, r.Gas)
	if r.JournalID != "" {
		Line(w, m, "journal: %s", r.JournalID)
	}
}

// GasQuotes writes the human view of `daxie gas`: the next base fee plus the
// slow/normal/fast suggestions in a small aligned table. The base fee is the
// essential anchor; the three rows are the suggestions.
func GasQuotes(w io.Writer, m Mode, r domain.GasQuotesResult) {
	if r.BaseFee != "" {
		// The base fee IS the headline answer of `daxie gas` (printed even under
		// --quiet, like the balance value).
		_, _ = io.WriteString(w, "base fee: "+r.BaseFee+" wei\n")
	}
	Line(w, m, "network: %s", r.Network)
	tbl := NewTable(w)
	if !m.Quiet {
		tbl.Row("SPEED", "MAX-FEE/GAS", "PRIORITY/GAS", "GAS-PRICE")
	}
	gasRow(tbl, "slow", r.Slow)
	gasRow(tbl, "normal", r.Normal)
	gasRow(tbl, "fast", r.Fast)
	_ = tbl.Flush()
}

// gasRow writes one speed row, choosing 1559 vs legacy columns from the quote.
func gasRow(tbl *Table, speed string, q domain.GasResult) {
	if q.Legacy {
		tbl.Row(speed, "-", "-", dash(q.GasPrice))
		return
	}
	tbl.Row(speed, dash(q.MaxFeePerGas), dash(q.PriorityFee), "-")
}

// renderGasLines writes the gas decision attached to a TxResult as context lines.
func renderGasLines(w io.Writer, m Mode, g domain.GasResult) {
	Line(w, m, "gas-limit: %d", g.GasLimit)
	if g.Legacy {
		Line(w, m, "gas-price: %s wei", g.GasPrice)
		return
	}
	Line(w, m, "max-fee:   %s wei", g.MaxFeePerGas)
	Line(w, m, "priority:  %s wei", g.PriorityFee)
}

// ContactsTable writes the contacts roster as a name-sorted aligned table.
func ContactsTable(w io.Writer, m Mode, rows []domain.ContactRow) {
	tbl := NewTable(w)
	if !m.Quiet {
		tbl.Row("NAME", "ADDRESS", "ENS")
	}
	for _, c := range rows {
		tbl.Row(c.Name, c.Address, c.ENS)
	}
	_ = tbl.Flush()
}

// Contact writes a single contact (the `contacts show` view). The address is the
// essential output; name/ens are context.
func Contact(w io.Writer, m Mode, c domain.ContactRow) {
	_, _ = io.WriteString(w, c.Address+"\n")
	Line(w, m, "name: %s", c.Name)
	if c.ENS != "" {
		Line(w, m, "ens:  %s", c.ENS)
	}
	if c.PinnedAt != "" {
		Line(w, m, "pinned-at: %s", c.PinnedAt)
	}
}

// TxRows writes the `tx list` journal view (newest-first) as an aligned table.
func TxRows(w io.Writer, m Mode, rows []domain.TxRow) {
	tbl := NewTable(w)
	if !m.Quiet {
		tbl.Row("HASH", "NONCE", "KIND", "TO", "VALUE-WEI", "STATUS", "TS")
	}
	for _, r := range rows {
		tbl.Row(r.Hash, strconv.FormatUint(r.Nonce, 10), r.Kind, r.To, r.ValueWei, r.Status, r.TS)
	}
	_ = tbl.Flush()
}

// dash renders an empty fee string as "-" so a sparse 1559/legacy column reads
// cleanly in the table.
func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
