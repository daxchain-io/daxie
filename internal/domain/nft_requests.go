package domain

// nft_requests.go is the wire contract for the M6 NFT registry + ERC-721/1155
// transfer/read surface (design §2.8, §4.2/§4.3, §5.1, §7.8, cli-spec §`daxie
// nft`). It obeys the same triple-duty + no-float rules as token_requests.go:
//
//   - token_id is a DECIMAL STRING everywhere (§7.8): NFT ids routinely exceed
//     2^53, so they NEVER cross as an int64/float — only as a base-10 string
//     validated upstream over math/big. ERC-1155 quantities are likewise strings.
//   - Every user value is a string/int on the wire so the same struct serves the
//     CLI --json output, the MCP tool schema (M11), and the v1.1 HTTP body.
//   - SECRET MATERIAL NEVER APPEARS HERE: an NFT send signs through the SAME
//     pipeline as a transfer, so NFTSendRequest RETURNS a TxResult (raw_tx never
//     reaches the wire).
//
// Anti-spoofing (§7.8 / requirements §2): a collection is named by a REGISTRY
// ALIAS or a raw 0x contract address; an individual NFT by a `<collection>#<id>`
// reference (the collection an alias or 0x) or by an individual-NFT alias.
// Resolution is registry-only for alias forms — a name not in the registry is an
// error, NEVER an on-chain name()/symbol() lookup. ParseNFTRef does the syntactic
// split only; service.resolveNFT (the one chokepoint) turns it into a concrete
// {collection addr, kind, token_id}, and the registry never touches the chain to
// resolve an alias.

import "strings"

// NFTRef is the parsed form of a `--nft` reference. The reference is one of:
//
//   - `<collection>#<tokenId>` — Collection (an alias OR a raw 0x) + TokenID (a
//     decimal string); Alias is "".
//   - a bare individual-NFT alias ("my-punk") — Alias set, Collection/TokenID "".
//
// token_id is NEVER parsed to an integer here; it stays a STRING so a 2^200 id
// round-trips intact (§7.8). The syntactic shape is validated (exactly one '#'
// for the collection#id form, non-empty parts); the SEMANTIC validation (is the
// token id a non-negative decimal, does the collection alias resolve) happens in
// service/registry, which own the registry + math/big.
type NFTRef struct {
	Collection string // alias or 0x ("" when Raw was a bare individual-NFT alias)
	TokenID    string // decimal string ("" for the bare-alias form)
	Alias      string // the bare individual-NFT alias form, else ""
	Raw        string // the original input, trimmed
}

// IsAlias reports whether the reference was a bare individual-NFT alias (no '#').
func (r NFTRef) IsAlias() bool { return r.Alias != "" }

// ParseNFTRef splits a `--nft` reference into its parts. It splits on the FIRST
// '#': everything before is the collection (alias or 0x), everything after is the
// token id (a decimal string, NOT parsed to int). A reference with NO '#' is a
// bare individual-NFT alias. Errors (usage class, exit 2):
//
//   - an empty reference;
//   - more than one '#' (an ambiguous reference);
//   - an empty collection or empty token-id part around a single '#'.
//
// It does NOT validate that the token id is a decimal integer or that the
// collection resolves — those are service/registry concerns (they own math/big +
// the registry). This keeps the wire parse a pure syntactic split.
func ParseNFTRef(s string) (NFTRef, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return NFTRef{}, New(CodeUsage+".bad_nft_ref",
			"an NFT reference is required (a <collection>#<tokenId> or an NFT alias)")
	}
	n := strings.Count(raw, "#")
	switch n {
	case 0:
		// A bare individual-NFT alias.
		return NFTRef{Alias: raw, Raw: raw}, nil
	case 1:
		col, id, _ := strings.Cut(raw, "#")
		col = strings.TrimSpace(col)
		id = strings.TrimSpace(id)
		if col == "" || id == "" {
			return NFTRef{}, Newf(CodeUsage+".bad_nft_ref",
				"%q is not a valid <collection>#<tokenId> reference (both parts are required)", raw)
		}
		return NFTRef{Collection: col, TokenID: id, Raw: raw}, nil
	default:
		return NFTRef{}, Newf(CodeUsage+".bad_nft_ref",
			"%q has more than one '#'; an NFT reference is <collection>#<tokenId>", raw)
	}
}

// ─── nft registry: add / alias / aliases ──────────────────────────────────────

// NFTAddRequest registers a collection alias→contract on a network (`daxie nft add
// <0x> [--name <alias>]`). Contract is the raw 0x collection address; Name is the
// optional alias override — when empty, service defaults it to the case-folded
// on-chain name() (read for DISPLAY; the registry never touches the chain to
// resolve). The kind (erc721|erc1155) is DETECTED on-chain via ERC-165 at add and
// STORED (the §10.1 detection check); a non-NFT address is rejected (usage.not_nft,
// exit 2).
type NFTAddRequest struct {
	Contract string `json:"contract"`       // raw 0x collection address
	Name     string `json:"name,omitempty"` // --name alias override; "" ⇒ folded on-chain name()
	Network  string `json:"network,omitempty"`
	RPC      string `json:"rpc,omitempty"`
}

// NFTCollectionRow is one collection registry entry echo. Kind is the ERC-165
// detected standard; Name is the on-chain display name (display only, never
// resolved against).
type NFTCollectionRow struct {
	Alias    string `json:"alias"`
	Contract string `json:"contract"` // EIP-55 hex
	Kind     string `json:"kind"`     // "erc721" | "erc1155"
	Network  string `json:"network"`
	Name     string `json:"name,omitempty"` // on-chain display name (display only)
}

// NFTCollectionResult wraps one collection row (the `nft add` echo).
type NFTCollectionResult struct {
	Collection NFTCollectionRow `json:"collection"`
}

// NFTAliasRequest aliases one individual NFT (`daxie nft alias <collection#tokenId>
// <alias>`). Ref is the `<collection>#<tokenId>` reference (the collection an alias
// or 0x); Alias is the new individual-NFT alias. The collection MUST already be a
// registered collection alias on the network (the nft alias binds to a known
// contract); token_id is stored as a decimal string (§7.8).
type NFTAliasRequest struct {
	Ref     string `json:"ref"`   // <collection>#<tokenId>
	Alias   string `json:"alias"` // the new individual-NFT alias
	Network string `json:"network,omitempty"`
}

// NFTAliasRow is one individual-NFT alias entry. Collection is the COLLECTION
// ALIAS it binds to; TokenID is the decimal string (§7.8).
type NFTAliasRow struct {
	Alias      string `json:"alias"`
	Collection string `json:"collection"` // collection alias
	TokenID    string `json:"token_id"`   // DECIMAL STRING (§7.8)
	Network    string `json:"network"`
}

// NFTAliasResult wraps one individual-NFT alias row (the `nft alias` echo).
type NFTAliasResult struct {
	Alias NFTAliasRow `json:"alias"`
}

// NFTAliasesRequest lists the individual-NFT aliases on a network (`daxie nft
// aliases`).
type NFTAliasesRequest struct {
	Network string `json:"network,omitempty"`
}

// NFTAliasesResult is the alias-sorted roster of individual-NFT aliases.
type NFTAliasesResult struct {
	Network string        `json:"network"`
	Aliases []NFTAliasRow `json:"aliases"`
}

// ─── nft reads: show / list ───────────────────────────────────────────────────

// NFTShowRequest reads ownership/metadata for one NFT (`daxie nft show <ref>` or
// `daxie nft show --contract <0x> --token-id <N>`). Read-only; no signing, no
// policy. NFT is a `<collection>#<tokenId>` or an individual-NFT alias; the
// --contract + --token-id form is an alternative that names the collection raw.
// Account (optional) is the address an ERC-1155 balance is read for (a 721 reports
// ownerOf regardless).
type NFTShowRequest struct {
	NFT      string `json:"nft,omitempty"`      // <collection>#<tokenId> | individual-NFT alias
	Contract string `json:"contract,omitempty"` // raw collection (the --contract form)
	TokenID  string `json:"token_id,omitempty"` // decimal string (the --token-id form)
	Account  string `json:"account,omitempty"`  // 1155 balanceOf subject (default: the active account)
	Network  string `json:"network,omitempty"`
	RPC      string `json:"rpc,omitempty"`
}

// NFTShowResult is the ownership/metadata view of one NFT. token_id is a decimal
// string; Owner is the 721 ownerOf; Balance is the 1155 balanceOf(account,id) when
// an account was given. OwnedByYou marks whether the resolved owner/holder is the
// active/queried account.
type NFTShowResult struct {
	Network    string `json:"network"`
	Collection string `json:"collection"`          // EIP-55 hex
	Alias      string `json:"alias,omitempty"`     // collection alias when registered
	NFTAlias   string `json:"nft_alias,omitempty"` // individual-NFT alias when the ref was one
	Kind       string `json:"kind"`                // "erc721" | "erc1155"
	TokenID    string `json:"token_id"`            // DECIMAL STRING
	Owner      string `json:"owner,omitempty"`     // 721: ownerOf (EIP-55 hex)
	Account    string `json:"account,omitempty"`   // 1155: the balance subject (EIP-55 hex)
	Balance    string `json:"balance,omitempty"`   // 1155: balanceOf(account,id) base-unit string
	OwnedByYou bool   `json:"owned_by_you,omitempty"`
}

// NFTListRequest lists owned NFTs across REGISTERED collections (`daxie nft list
// [--account <ref>]`). v1 enumerates the registry collections + the account's
// individual-NFT aliases and reports ownership per the §10.3 discovery note (no
// on-chain enumeration of arbitrary holdings — an indexer is the future seam).
type NFTListRequest struct {
	Account string `json:"account,omitempty"`
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
}

// NFTListResult is the owned-NFT roster for an account on a network.
type NFTListResult struct {
	Network string          `json:"network"`
	Address string          `json:"address"` // EIP-55 hex
	Owned   []NFTShowResult `json:"owned"`
}

// ─── nft send (a transfer through the SAME pipeline → a TxResult) ──────────────

// NFTSendRequest sends an NFT (`daxie nft send --to <recip> --nft <ref> [--amount
// N]`). It signs+broadcasts through the SAME §5.1 pipeline as an ETH/ERC-20
// transfer (KindTransfer), so it RETURNS a TxResult. The policy destination is the
// RECIPIENT (--to), NEVER the collection contract (§4.2/§4.3); the fail-closed-no-
// allowlist rule applies (ETH exempt, NFT NOT). For ERC-1155, Amount is the
// quantity (default 1); for ERC-721, Amount must be empty or "1" (a 721 carries no
// quantity).
type NFTSendRequest struct {
	NFT    string `json:"nft"`              // <collection>#<tokenId> | individual-NFT alias
	To     string `json:"to"`               // recipient: 0x | contact (the policy subject)
	Amount string `json:"amount,omitempty"` // ERC-1155 quantity (default 1); 721: empty/1

	From    string  `json:"from,omitempty"`
	Network string  `json:"network,omitempty"`
	RPC     string  `json:"rpc,omitempty"`
	Nonce   *uint64 `json:"nonce,omitempty"`

	DryRun bool `json:"dry_run,omitempty"`
	// Confirm is the agent-facing TTY-confirmation skip (like tx send / token
	// approve). An NFT send has no unlimited ceremony.
	Confirm bool `json:"confirm" jsonschema:"send without an interactive confirmation; defaults to false"`
	// Yes is the CLI-only TTY-skip mirror, excluded from the MCP schema (json:"-").
	Yes  bool     `json:"-"`
	Wait WaitOpts `json:"wait,omitempty"`
}
