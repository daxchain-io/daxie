package render

import (
	"io"

	"github.com/daxchain-io/daxie/internal/domain"
)

// nft.go holds the human renderers for the M6 NFT registry + ownership views
// (cli-spec §`daxie nft`). It formats only — the --json form is the domain struct
// marshaled by Result; these funcs are the human-mode branch. Every helper honors
// Mode.Quiet via render.Line for the non-essential context while always printing
// the one essential value. `nft send` reuses renderTxOutcome/TxResult (an NFT send
// returns a TxResult).
//
// No float anywhere (§2.5): token_id and the 1155 balance are exact decimal
// strings on the domain result; we print them verbatim.

// NFTCollection writes the `nft add` echo: the contract is the essential output;
// alias/kind/name/network are context.
func NFTCollection(w io.Writer, m Mode, r domain.NFTCollectionResult) {
	c := r.Collection
	_, _ = io.WriteString(w, c.Contract+"\n")
	Line(w, m, "alias:   %s", c.Alias)
	Line(w, m, "kind:    %s", c.Kind)
	if c.Name != "" {
		Line(w, m, "name:    %s", c.Name)
	}
	Line(w, m, "network: %s", c.Network)
}

// NFTAlias writes the `nft alias` echo: the alias is the essential output;
// collection/token-id/network are context.
func NFTAlias(w io.Writer, m Mode, r domain.NFTAliasResult) {
	a := r.Alias
	_, _ = io.WriteString(w, a.Alias+"\n")
	Line(w, m, "collection: %s", a.Collection)
	Line(w, m, "token-id:   %s", a.TokenID)
	Line(w, m, "network:    %s", a.Network)
}

// NFTAliasList writes the `nft aliases` view as an alias-sorted aligned table.
func NFTAliasList(w io.Writer, m Mode, r domain.NFTAliasesResult) {
	tbl := NewTable(w)
	if !m.Quiet {
		tbl.Row("ALIAS", "COLLECTION", "TOKEN-ID")
	}
	for _, a := range r.Aliases {
		tbl.Row(a.Alias, a.Collection, a.TokenID)
	}
	_ = tbl.Flush()
}

// NFTShow writes the `nft show` view: the owner (721) or balance (1155) is the
// essential output; collection/kind/token-id are context.
func NFTShow(w io.Writer, m Mode, r domain.NFTShowResult) {
	// The headline is what the caller most wants: the owner for a 721, the balance
	// for a 1155, else the collection#id identity.
	switch {
	case r.Owner != "":
		_, _ = io.WriteString(w, r.Owner+"\n")
	case r.Balance != "":
		_, _ = io.WriteString(w, r.Balance+"\n")
	default:
		_, _ = io.WriteString(w, r.Collection+"#"+r.TokenID+"\n")
	}
	Line(w, m, "collection: %s", r.Collection)
	if r.Alias != "" {
		Line(w, m, "alias:      %s", r.Alias)
	}
	if r.NFTAlias != "" {
		Line(w, m, "nft-alias:  %s", r.NFTAlias)
	}
	Line(w, m, "kind:       %s", r.Kind)
	Line(w, m, "token-id:   %s", r.TokenID)
	if r.Owner != "" {
		Line(w, m, "owner:      %s", r.Owner)
	}
	if r.Account != "" {
		Line(w, m, "account:    %s", r.Account)
	}
	if r.Balance != "" {
		Line(w, m, "balance:    %s", r.Balance)
	}
	if r.Account != "" {
		Line(w, m, "owned-by-you: %v", r.OwnedByYou)
	}
	Line(w, m, "network:    %s", r.Network)
}

// NFTList writes the `nft list` view: the owner address line plus an aligned table
// of the owned NFTs (collection / token-id / kind / qty). An empty list prints a
// (no NFTs) note.
func NFTList(w io.Writer, m Mode, r domain.NFTListResult) {
	_, _ = io.WriteString(w, r.Address+"\n")
	Line(w, m, "network: %s", r.Network)
	if len(r.Owned) == 0 {
		Line(w, m, "(no NFTs in registered collections)")
		return
	}
	tbl := NewTable(w)
	if !m.Quiet {
		tbl.Row("COLLECTION", "TOKEN-ID", "KIND", "QTY", "NFT-ALIAS")
	}
	for _, n := range r.Owned {
		label := n.Alias
		if label == "" {
			label = n.Collection
		}
		qty := n.Balance
		if qty == "" {
			qty = "1" // a 721 is a single token
		}
		tbl.Row(label, n.TokenID, n.Kind, qty, n.NFTAlias)
	}
	_ = tbl.Flush()
}
