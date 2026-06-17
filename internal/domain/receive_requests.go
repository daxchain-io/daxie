package domain

// receive_requests.go is the M8 `daxie receive` wire contract (design §5.8/§5.9):
// the inbound-detection request, the resolved target/asset views, the per-transfer
// detection record, and the terminal result. It is triple-duty (CLI flags, MCP
// input/output schema, and the in-process service call) and carries NO float
// (§2.5) — every amount is a base-unit decimal string assembled over math/big.
//
// The detection engine itself lives in internal/service/receive*.go; this file is
// only the boundary types both frontends bind against. The mode/attribution
// consts encode the §5.8 completion rules and the "only attributable kinds satisfy
// --exact" non-negotiable so service and tests share one vocabulary.

// ReceiveRequest is the inbound-detection request (cli-spec `daxie receive`). The
// command BLOCKS until the listening address receives the expected asset and it
// reaches the confirmation target, streaming NDJSON events on stdout. An empty
// Amount with no asset flags is the ModeAny path (any inbound ETH); --exact
// without --amount is a usage error; --token and --nft are mutually exclusive;
// --new requires a writable keystore (§3.3).
type ReceiveRequest struct {
	// Account is an EXISTING account reference (wallet/idx | wallet/alias | 0x |
	// ENS). "" resolves the §7.7 default account, UNLESS New is set (then a fresh
	// index is derived instead).
	Account string `json:"account,omitempty" jsonschema:"account ref to listen on; defaults to the active account"`
	// New derives a FRESH invoice address via keys.DeriveNext (a keystore meta.json
	// write — requires a writable keystore, §3.3). Mutually informs Account: when
	// New is set the listening address is the freshly derived index, not Account.
	New bool `json:"new,omitempty" jsonschema:"derive a fresh invoice address (requires a writable keystore)"`
	// Wallet is the --new target wallet (REQUIRED when New is set).
	Wallet string `json:"wallet,omitempty" jsonschema:"target wallet for --new"`
	// Name optionally aliases the fresh --new index in the same step.
	Name string `json:"name,omitempty" jsonschema:"optional alias for the fresh --new index"`
	// Amount is the target amount: human ETH ("0.5") for the native asset, or a
	// base-unit decimal ("100") for a token / ERC-1155 quantity. "" ⇒ any-inbound
	// (ModeAny).
	Amount string `json:"amount,omitempty" jsonschema:"target amount; e.g. 0.5 (ETH) or 100 (token base units); omit for any-inbound"`
	// Exact requires ONE single ATTRIBUTABLE transfer (tx | log) exactly equal to
	// Amount. A balance-delta detection can never satisfy it. Requires Amount.
	Exact bool `json:"exact,omitempty" jsonschema:"require one single attributable transfer equal to --amount"`
	// Token selects an ERC-20 by registry alias or 0x contract; mutually exclusive
	// with NFT.
	Token string `json:"token,omitempty" jsonschema:"ERC-20 registry alias or contract; omit for ETH"`
	// NFT selects an NFT as "<collection>#<id>" or an individual-NFT alias;
	// mutually exclusive with Token.
	NFT string `json:"nft,omitempty" jsonschema:"NFT as <collection>#<id> or an nft alias; omit for ETH"`
	// Confirmations overrides the per-network confirmation target (§5.2). nil ⇒ the
	// per-network default.
	Confirmations *uint64 `json:"confirmations,omitempty" jsonschema:"override the per-network confirmation target; omit for the default"`
	// Timeout bounds the wait. ZERO ⇒ UNBOUNDED invoice wait (NOT the tx 10m
	// default) — the §5.8 default.
	Timeout Duration `json:"timeout,omitempty" jsonschema:"Go duration, e.g. 5m; ZERO/omit = UNBOUNDED invoice wait (set one for agents)"`
	// FromBlock is the resume baseline (= last_scanned+1 from a prior timeout line).
	// nil ⇒ the head at listen start (minus receive.lookback-blocks).
	FromBlock *uint64 `json:"from_block,omitempty" jsonschema:"resume baseline block (last_scanned+1 from a prior timeout); omit for the head at listen start"`
	// Network / RPC are the per-invocation endpoint selection (§2.8).
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
	// QR is a CLI-only terminal-QR decoration of the listening address; excluded
	// from the MCP/HTTP schema (json:"-").
	QR bool `json:"-"`
}

// ReceiveMode is the resolved completion mode (§5.8 completion table). It is
// derived from the request flags by ResolveReceiveMode.
type ReceiveMode string

const (
	// ModeAny is "no amount + no asset flags": any single confirmed inbound ETH
	// satisfies it (cumulative ≥ 1 wei).
	ModeAny ReceiveMode = "any"
	// ModeCumulative is the --amount default: the SUM of confirmed inbound
	// (any attribution) ≥ Amount.
	ModeCumulative ReceiveMode = "cumulative"
	// ModeExact is --exact: exactly ONE confirmed ATTRIBUTABLE transfer
	// (tx | log) whose value == Amount.
	ModeExact ReceiveMode = "exact"
	// ModeNFT is --nft: the named token arrives + confirms. ERC-721 ⇒ one transfer;
	// ERC-1155 with --amount ⇒ cumulative quantity ≥ Amount.
	ModeNFT ReceiveMode = "nft"
)

// The attribution tags carried on every detection (§5.8). Only the two
// ATTRIBUTABLE kinds (AttribTx, AttribLog) can satisfy ModeExact; AttribBalanceDelta
// counts toward cumulative but has no single transfer to equal X, so it can never
// trip --exact (the review non-negotiable).
const (
	// AttribTx is an ETH block-scan inbound (a tx with to==addr && value>0).
	// Attributable: it is bound to a specific tx.
	AttribTx = "tx"
	// AttribLog is a token/NFT Transfer log. Attributable: bound to a tx + log
	// index.
	AttribLog = "log"
	// AttribBalanceDelta is the ETH balance-delta safety net (an unattributed
	// positive residue — catches internal CALL transfers invisible to block-scan).
	// UNattributable: it cannot satisfy --exact.
	AttribBalanceDelta = "balance-delta"
)

// IsAttributable reports whether an attribution tag can satisfy --exact. Only tx
// and log are attributable; balance-delta is not (§5.8). The detection engine and
// the completion check both gate --exact through this so the rule lives in one
// place.
func IsAttributable(attribution string) bool {
	return attribution == AttribTx || attribution == AttribLog
}

// ReceiveTarget is the resolved completion target echoed on the listening line and
// carried in the result. Timeout is *string so the §5.8 example's "timeout":null
// (unbounded wait) is emitted verbatim and a bounded wait emits the duration
// string.
type ReceiveTarget struct {
	Mode          ReceiveMode `json:"mode"`
	Amount        string      `json:"amount,omitempty"` // base-unit decimal string; "" for ModeAny
	Confirmations uint64      `json:"confirmations"`
	Timeout       *string     `json:"timeout"` // null ⇒ unbounded
}

// ReceiveAsset is the resolved asset being listened for. Kind is "eth" for the
// native path; Contract/Alias/Decimals/TokenID carry the token/NFT specifics.
type ReceiveAsset struct {
	Kind     string `json:"kind"`               // "eth" | "erc20" | "erc721" | "erc1155"
	Contract string `json:"contract,omitempty"` // EIP-55 hex (token/NFT)
	Alias    string `json:"alias,omitempty"`
	Decimals int    `json:"decimals,omitempty"` // erc20 only (display)
	TokenID  string `json:"token_id,omitempty"` // nft only (decimal string)
}

// DetectedTransfer is one CONFIRMED inbound transfer carried in the result's
// Transfers slice. TxHash/LogIndex are empty for a balance-delta detection (it has
// no single attributable tx). Value/TokenID are base-unit / decimal strings.
type DetectedTransfer struct {
	TxHash      string `json:"tx_hash,omitempty"` // "" for balance-delta
	LogIndex    *int   `json:"log_index,omitempty"`
	From        string `json:"from,omitempty"`
	Value       string `json:"value"` // base-unit decimal string
	TokenID     string `json:"token_id,omitempty"`
	Block       uint64 `json:"block"`
	BlockHash   string `json:"block_hash,omitempty"`
	Attribution string `json:"attribution"` // tx | log | balance-delta
}

// ReceiveResult is the terminal result for the in-process / MCP caller. The same
// outcome is also carried in the final EvComplete / EvTimeout event so a CLI agent
// can read it from the stream without inspecting $? (§5.9). Status is "complete"
// (Exit 0) or "timeout" (Exit 8). Remaining is at FULL fixed-point precision and
// Resume (timeout only) is an executable `daxie receive …` command.
type ReceiveResult struct {
	Address             string             `json:"address"` // EIP-55 hex (the listening address)
	Network             string             `json:"network"`
	ChainID             uint64             `json:"chain_id"`
	Asset               ReceiveAsset       `json:"asset"`
	Target              ReceiveTarget      `json:"target"`
	Status              string             `json:"status"`               // "complete" | "timeout"
	CumulativeConfirmed string             `json:"cumulative_confirmed"` // base-unit decimal
	Remaining           string             `json:"remaining"`            // base-unit decimal (FULL precision)
	Transfers           []DetectedTransfer `json:"transfers"`
	LastScanned         uint64             `json:"last_scanned"`
	Resume              string             `json:"resume,omitempty"` // executable `daxie receive …` (timeout only)
	Exit                int                `json:"exit"`             // 0 complete | 8 timeout
}

// ResolveReceiveMode resolves the §5.8 completion mode from the request flags and
// validates the cross-flag rules. It is the ONE place the mode + the usage
// rejections live so the CLI, the MCP handler, and the service agree:
//
//   - --token and --nft together ⇒ usage error (mutually exclusive).
//   - --exact without --amount ⇒ usage error (there is no single value to equal).
//   - --new without --wallet ⇒ usage error (the derive target is required).
//   - --nft ⇒ ModeNFT (Amount, if present, is the ERC-1155 cumulative quantity).
//   - --amount (no --nft) ⇒ ModeExact if --exact else ModeCumulative.
//   - no amount + no asset flags ⇒ ModeAny (any inbound ETH).
//
// Token presence alone (no --amount) keeps ModeAny semantics over that token —
// any inbound of the token — which the engine treats as "cumulative ≥ 1 base
// unit" exactly like ModeAny does for ETH.
func ResolveReceiveMode(req ReceiveRequest) (ReceiveMode, error) {
	if req.Token != "" && req.NFT != "" {
		return "", New(CodeUsage+".asset_conflict",
			"--token and --nft are mutually exclusive (a receive listens for one asset)")
	}
	if req.Exact && req.Amount == "" {
		return "", New(CodeUsage+".exact_needs_amount",
			"--exact requires --amount (it matches one single transfer equal to that amount)")
	}
	if req.New && req.Wallet == "" {
		return "", New(CodeUsage+".new_needs_wallet",
			"--new requires --wallet (the wallet to derive the fresh invoice address from)")
	}
	switch {
	case req.NFT != "":
		return ModeNFT, nil
	case req.Amount != "":
		if req.Exact {
			return ModeExact, nil
		}
		return ModeCumulative, nil
	default:
		// No amount, no NFT: any-inbound. (A bare --token with no --amount is
		// "any inbound of this token", handled as ModeAny by the engine.)
		return ModeAny, nil
	}
}
