package render

import (
	"io"
	"strconv"

	"github.com/daxchain-io/daxie/internal/domain"
)

// token.go holds the human renderers for the M5 token registry + ERC-20 approval +
// token-balance views (cli-spec §`daxie token` / §`daxie balance`). It formats only
// — the --json form is the domain struct marshaled by Result; these funcs are the
// human-mode branch. Every helper honors Mode.Quiet via render.Line for the
// non-essential context while always printing the one essential value.
//
// No float anywhere (§2.5): every amount is already an exact decimal string (a
// base-unit integer and a decimals-formatted human form) on the domain result; we
// print it verbatim.

// TokenInfo writes the human view of `token info`: the contract is the essential
// output; symbol/decimals/registration are context.
func TokenInfo(w io.Writer, m Mode, r domain.TokenInfoResult) {
	_, _ = io.WriteString(w, r.Contract+"\n")
	if r.Symbol != "" {
		Line(w, m, "symbol:   %s", r.Symbol)
	}
	Line(w, m, "decimals: %d", r.Decimals)
	Line(w, m, "kind:     %s", r.Kind)
	Line(w, m, "network:  %s", r.Network)
	if r.Registered {
		prov := "registered"
		if r.Bundled {
			prov = "bundled"
		}
		Line(w, m, "alias:    %s (%s)", r.Alias, prov)
	} else {
		Line(w, m, "alias:    (not registered — add with `daxie token add %s`)", r.Contract)
	}
}

// TokenList writes the `token list` view as an alias-sorted aligned table with a
// provenance column (bundled vs registered).
func TokenList(w io.Writer, m Mode, r domain.TokenListResult) {
	tbl := NewTable(w)
	if !m.Quiet {
		tbl.Row("ALIAS", "ADDRESS", "SYMBOL", "DECIMALS", "SOURCE")
	}
	for _, t := range r.Tokens {
		tbl.Row(t.Alias, t.Contract, t.Symbol, strconv.Itoa(t.Decimals), tokenSource(t.Bundled))
	}
	_ = tbl.Flush()
}

// Allowance writes the `token allowance` view: the formatted allowance is the
// essential output (or "unlimited"); owner/spender/contract are context.
func Allowance(w io.Writer, m Mode, r domain.AllowanceResult) {
	headline := r.AllowanceFormatted
	if r.Unlimited {
		headline = "unlimited"
	}
	sym := r.Symbol
	if sym != "" {
		sym = " " + sym
	}
	_, _ = io.WriteString(w, headline+sym+"\n")
	Line(w, m, "owner:    %s", r.Owner)
	Line(w, m, "spender:  %s", r.Spender)
	Line(w, m, "token:    %s", r.Contract)
	Line(w, m, "base:     %s", r.Allowance)
	Line(w, m, "network:  %s", r.Network)
}

// BalanceToken writes a single `balance --token` view: the formatted token balance
// is the essential output (printed even under --quiet, like the ETH balance value).
func BalanceToken(w io.Writer, m Mode, r domain.BalanceResult) {
	if r.Token == nil {
		return
	}
	tb := r.Token
	sym := tb.Symbol
	if sym == "" {
		sym = tb.Alias
	}
	_, _ = io.WriteString(w, tb.Formatted+" "+sym+"\n")
	Line(w, m, "address: %s   network: %s", r.Address, r.Network)
	Line(w, m, "token:   %s", tb.Contract)
	Line(w, m, "base:    %s", tb.Base)
}

// BalanceAll writes the `balance --all` view: the ETH balance line plus an
// alias-sorted table of every nonzero registry token. The ETH value is the headline.
func BalanceAll(w io.Writer, m Mode, r domain.BalanceResult) {
	_, _ = io.WriteString(w, r.Eth+" "+r.Symbol+"\n")
	Line(w, m, "address: %s   network: %s", r.Address, r.Network)
	if len(r.Tokens) == 0 {
		Line(w, m, "(no token balances)")
		return
	}
	tbl := NewTable(w)
	if !m.Quiet {
		tbl.Row("TOKEN", "BALANCE", "ADDRESS")
	}
	for _, t := range r.Tokens {
		label := t.Symbol
		if label == "" {
			label = t.Alias
		}
		tbl.Row(label, t.Formatted, t.Contract)
	}
	_ = tbl.Flush()
}

// tokenSource renders the provenance column for `token list`.
func tokenSource(bundled bool) string {
	if bundled {
		return "bundled"
	}
	return "registered"
}
