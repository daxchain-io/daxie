package domain

// token_requests.go is the wire contract for the M5 token registry + ERC-20
// transfer/approval surface (design §2.8, §4.2, §5.1, §7.8, cli-spec §`daxie
// token` / §`daxie balance`). It obeys the same triple-duty rules as the M2/M3
// wire files:
//
//   - NO float field anywhere (§2.5): every token amount is an exact decimal
//     STRING — both the base-unit integer and the decimals-formatted human form
//     are strings assembled over math/big upstream. Decimals is an int (a small
//     count), used for DISPLAY only; amounts NEVER cross as a float.
//   - Every user value is a string/int on the wire so the same struct serves the
//     CLI --json output, the MCP tool schema (M11), and the v1.1 HTTP body.
//   - SECRET MATERIAL NEVER APPEARS HERE: a token op signs through the same
//     pipeline, so an approval RETURNS a TxResult (raw_tx never reaches it).
//
// Anti-spoofing (§7.8 / requirements §2): a token is named by a REGISTRY ALIAS or
// a raw 0x contract address. Resolution is registry-only — a name not in the
// registry (or the bundled majors) is an error, NEVER an on-chain symbol() lookup.
// These request structs carry the alias/0x verbatim; service.resolveAsset is the
// one chokepoint that turns it into a contract (registry for an alias; the literal
// for a 0x).

// ─── token registry (info/add/rename/list/remove) ────────────────────────────

// TokenInfoRequest reads on-chain metadata (symbol/decimals + kind) for a token
// WITHOUT registering it (`daxie token info <0x|alias>`). Token is an alias (then
// the registered contract is used) or a raw 0x contract. This is the one token
// path that touches the chain for display metadata; it never resolves an alias by
// symbol (an unregistered name is ref.not_found).
type TokenInfoRequest struct {
	Token   string `json:"token"`             // alias or raw 0x contract
	Network string `json:"network,omitempty"` // --network override
	RPC     string `json:"rpc,omitempty"`     // --rpc endpoint override
}

// TokenInfoResult is the on-chain metadata view of a token. Decimals is a count
// (display only); Symbol is the on-chain DISPLAY symbol (never used to resolve).
// Registered/Alias report whether the address is in the local registry (so the
// caller can suggest `token add`).
type TokenInfoResult struct {
	Network    string `json:"network"`
	Contract   string `json:"contract"`          // EIP-55 hex
	Kind       string `json:"kind"`              // "erc20"
	Symbol     string `json:"symbol,omitempty"`  // on-chain display symbol
	Decimals   int    `json:"decimals"`          // display precision
	Registered bool   `json:"registered"`        // true when the address is in the registry
	Alias      string `json:"alias,omitempty"`   // the registry alias when registered
	Bundled    bool   `json:"bundled,omitempty"` // true when it resolved from the bundled majors
}

// TokenAddRequest registers a token alias→contract on a network (`daxie token add
// <0x> [--name <alias>]`). Contract is the raw 0x address; Name is the optional
// alias override — when empty, service defaults it to the case-folded on-chain
// symbol (read via erc.Symbol; the registry never touches the chain). A collision
// (case-insensitive) with a file entry OR a bundled major is usage.duplicate
// (requires --name).
type TokenAddRequest struct {
	Contract string `json:"contract"`       // raw 0x contract address
	Name     string `json:"name,omitempty"` // --name alias override; "" ⇒ folded on-chain symbol
	Network  string `json:"network,omitempty"`
	RPC      string `json:"rpc,omitempty"`
}

// TokenRenameRequest renames a FILE alias on a network (`daxie token rename <old>
// <new>`). A bundled major cannot be renamed in place (usage.bundled_immutable);
// an absent old alias is ref.not_found.
type TokenRenameRequest struct {
	Old     string `json:"old"`
	New     string `json:"new"`
	Network string `json:"network,omitempty"`
}

// TokenRemoveRequest deletes a FILE alias on a network (`daxie token remove
// <alias>`). A bundled major cannot be removed (usage.bundled_immutable).
type TokenRemoveRequest struct {
	Alias   string `json:"alias"`
	Network string `json:"network,omitempty"`
}

// TokenListRequest lists the merged known set (bundled majors ∪ file entries) for
// a network (`daxie token list`).
type TokenListRequest struct {
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
}

// TokenRow is one row in `token list` / a single registry entry echo. Bundled
// marks a compiled-in major (provenance); Decimals is display precision.
type TokenRow struct {
	Alias    string `json:"alias"`
	Contract string `json:"contract"` // EIP-55 hex
	Kind     string `json:"kind"`     // "erc20"
	Symbol   string `json:"symbol,omitempty"`
	Decimals int    `json:"decimals"`
	Network  string `json:"network"`
	Bundled  bool   `json:"bundled,omitempty"`
}

// TokenResult wraps one registry row (add/rename).
type TokenResult struct {
	Token TokenRow `json:"token"`
}

// TokenListResult is the merged registry roster, alias-sorted.
type TokenListResult struct {
	Network string     `json:"network"`
	Tokens  []TokenRow `json:"tokens"`
}

// TokenRemoveResult confirms a token removal.
type TokenRemoveResult struct {
	Alias   string `json:"alias"`
	Network string `json:"network"`
	Removed bool   `json:"removed"`
}

// ─── approve / allowance / revoke (spend-equivalents, §4.2) ──────────────────

// ApproveRequest builds an ERC-20 approve(spender, amount) (`daxie token approve`)
// or a revoke (approve(spender, 0), `daxie token revoke`). It signs+broadcasts
// through the SAME pipeline as a transfer (KindApprove), so it RETURNS a TxResult.
//
//	--spender              → Spender (0x address or contact name; the POLICY subject)
//	--amount               → Amount (token base units, e.g. "100"); ignored on revoke
//	--unlimited            → Unlimited (approve(spender, 2^256-1)); requires --yes
//	--wait/--confirmations/--timeout → Wait
//
// Token is the alias-or-0x of the token contract (resolved registry-only). The
// policy destination for an approval is the SPENDER, never the token contract
// (§4.2). Unlimited requires the explicit --unlimited --yes ceremony (Confirm).
type ApproveRequest struct {
	Token     string `json:"token"`               // alias or raw 0x token contract
	Spender   string `json:"spender"`             // 0x address or contact name (the policy subject)
	Amount    string `json:"amount,omitempty"`    // token base-unit decimal; ignored when Unlimited / revoke
	Unlimited bool   `json:"unlimited,omitempty"` // approve(spender, 2^256-1); requires Confirm

	From    string `json:"from,omitempty"` // sending account ref; "" ⇒ default account
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`

	DryRun bool `json:"dry_run,omitempty"`
	// Confirm is the agent-facing acknowledgement: for an UNLIMITED approval it is
	// the --unlimited --yes ceremony bit the policy unlimited gate requires (§4.2);
	// for a bounded approval it is the ordinary TTY-confirmation skip (like tx send).
	Confirm bool `json:"confirm" jsonschema:"default=false"`
	// Yes is the CLI-only TTY-skip mirror, excluded from the MCP schema (json:"-").
	Yes bool `json:"-"`

	Wait WaitOpts `json:"wait,omitempty"`
}

// AllowanceRequest reads allowance(owner, spender) for a token (read-only;
// `daxie token allowance`). No signing, no policy. Owner defaults to the active
// account; Spender is required.
type AllowanceRequest struct {
	Token   string `json:"token"`           // alias or raw 0x token contract
	Owner   string `json:"owner,omitempty"` // account ref; "" ⇒ default account
	Spender string `json:"spender"`         // 0x address or contact name
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
}

// AllowanceResult is the current allowance of spender over owner's token balance.
// Allowance is the exact base-unit decimal string; AllowanceFormatted is the
// decimals-aware human form (no float). Unlimited marks a 2^256-1 allowance.
type AllowanceResult struct {
	Network            string `json:"network"`
	Contract           string `json:"contract"` // EIP-55 hex
	Symbol             string `json:"symbol,omitempty"`
	Decimals           int    `json:"decimals"`
	Owner              string `json:"owner"`               // EIP-55 hex
	Spender            string `json:"spender"`             // EIP-55 hex
	Allowance          string `json:"allowance"`           // exact base-unit decimal string
	AllowanceFormatted string `json:"allowance_formatted"` // decimals-aware human form
	Unlimited          bool   `json:"unlimited,omitempty"`
}

// ─── balance --token / --all ─────────────────────────────────────────────────

// TokenBalance is one token row in a `balance --all` listing (or the single
// `--token` block on BalanceResult). Wei here is the exact base-unit string;
// Formatted is the decimals-aware human form (no float, §2.5).
type TokenBalance struct {
	Alias     string `json:"alias,omitempty"`   // the registry alias, when known
	Contract  string `json:"contract"`          // EIP-55 hex
	Symbol    string `json:"symbol,omitempty"`  // display symbol
	Decimals  int    `json:"decimals"`          // display precision
	Kind      string `json:"kind"`              // "erc20"
	Base      string `json:"base"`              // exact base-unit decimal string
	Formatted string `json:"formatted"`         // decimals-aware human form
	Bundled   bool   `json:"bundled,omitempty"` // provenance (a compiled-in major)
}
