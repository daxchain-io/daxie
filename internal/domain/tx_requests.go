package domain

import "github.com/ethereum/go-ethereum/common"

// tx_requests.go is the wire contract for the M3 transaction pipeline + gas +
// contacts use cases (design §5.2, §5.4, §7.8, cli-spec §`daxie tx`/§`daxie
// gas`/§`daxie contacts`). It obeys the same triple-duty rules as the M1/M2 wire
// files (keys_requests.go, chain_requests.go):
//
//   - NO float field anywhere (§2.5): every wei/gas quantity is an exact decimal
//     STRING assembled over math/big in core; gas limits + nonces + chain ids are
//     integers; durations cross the wire as domain.Duration (a string).
//   - Every user value is a string/int on the wire so the same struct serves the
//     CLI --json output, the MCP tool schema (M11), and the v1.1 HTTP body.
//   - SECRET MATERIAL NEVER APPEARS HERE: a raw_tx never reaches a result struct
//     (it lives only in the journal); requests carry refs/addresses, never keys.
//
// M3 ships ETH transfers only. Token (`--token`, M5) and ENS (`--to name.eth`,
// M7) fields are PLUMBED so the wire shape is frozen, but service rejects them
// with usage.unsupported / fails clean rather than faking anything.

// ─── tx send (the pipeline, §5.2 verbatim) ───────────────────────────────────

// TxRequest is the §5.2 send request. The CLI maps its flags onto these fields
// (no new pipeline input); the same struct is the MCP `eth_send` tool input.
//
//	--from / DAXIE_ACCOUNT → From ("" ⇒ default account, §7.7)
//	--to                   → To   (0x | contact name | ENS — ENS is M7, fails clean)
//	--amount               → Amount (ETH decimal, e.g. "0.5"; token base units in M5)
//	--token                → Token (M5; service rejects usage.unsupported in M3)
//	gas flags              → GasLimit/MaxFee/PriorityFee/GasPrice/Speed/Legacy
//	--nonce                → Nonce (pin; bypasses derivation, still locks + journals)
//	--dry-run              → DryRun (policy.Evaluate, no reservation, stop before sign)
//	--yes                  → Yes (CLI-only TTY confirmation skip — NOT a safety ack)
//	--wait/--confirmations/--timeout → Wait
type TxRequest struct {
	From   string `json:"from" jsonschema:"account ref; defaults to the active account"`
	To     string `json:"to" jsonschema:"address, ENS name, or contact"`
	Amount string `json:"amount" jsonschema:"e.g. 0.5 (ETH) or 100 (token base units)"`
	Token  string `json:"token,omitempty" jsonschema:"registry alias or contract; omit for ETH"`

	GasLimit    string  `json:"gas_limit,omitempty"`
	MaxFee      string  `json:"max_fee,omitempty"` // "30gwei"
	PriorityFee string  `json:"priority_fee,omitempty"`
	GasPrice    string  `json:"gas_price,omitempty"` // --legacy only
	Speed       string  `json:"speed,omitempty"`     // slow|normal|fast
	Legacy      bool    `json:"legacy,omitempty"`
	Nonce       *uint64 `json:"nonce,omitempty" jsonschema:"type=integer,minimum=0"`

	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`

	DryRun bool `json:"dry_run,omitempty"`

	// Confirm is the --yes gate as the agent-facing field: MCP default false,
	// declared not inferred (a tool must opt in to send). It is the
	// confirmation-skip switch, NOT a safety acknowledgement (§5.1).
	Confirm bool `json:"confirm" jsonschema:"default=false"`
	// Yes is the CLI-only TTY-skip mirror, excluded from the MCP schema (json:"-").
	Yes bool `json:"-"`

	Wait WaitOpts `json:"wait,omitempty"`
}

// WaitOpts is the §5.2 --wait selection. Enabled gates the §5.3 state machine;
// nil Confirmations ⇒ the per-network default (mainnet 2, Sepolia 1, user 1);
// zero Timeout ⇒ the tx.wait-timeout default (10m).
type WaitOpts struct {
	Enabled       bool     `json:"enabled,omitempty"`
	Confirmations *uint64  `json:"confirmations,omitempty" jsonschema:"type=integer,minimum=0"`
	Timeout       Duration `json:"timeout,omitempty" jsonschema:"type=string,format=duration"`
}

// TxResult is the §5.2 send/status/wait result. AmountWei is the canonical wei
// decimal string; the gas decision is echoed in Gas; Status is the lifecycle
// position (timeout is NOT failure — it is resumable, §5.3).
type TxResult struct {
	Hash          string         `json:"hash"`
	Network       string         `json:"network"`
	From          common.Address `json:"from"`
	To            Dest           `json:"to"`
	Asset         Asset          `json:"asset"`
	AmountWei     string         `json:"amount_wei"`
	Nonce         uint64         `json:"nonce"`
	Gas           GasResult      `json:"gas"`
	Status        TxStatus       `json:"status"`
	Confirmations uint64         `json:"confirmations"`
	BlockNumber   *uint64        `json:"block_number,omitempty"`
	JournalID     string         `json:"journal_id"`

	// Resume is set on a timeout result so an agent can re-poll without inspecting
	// $? (§5.3: --json carries {"status":"pending","resume":"daxie tx wait 0x…"}).
	Resume string `json:"resume,omitempty"`
	// Replaced is set when a replacement (speedup/cancel) supersedes another tx —
	// the superseded hash, for the cross-link echo.
	Replaced string `json:"replaced,omitempty"`
	// DryRun marks a check-only result (no broadcast); the verdict passed.
	DryRun bool `json:"dry_run,omitempty"`
	// Classification is the M10 `contract send --dry-run` calldata classification
	// verdict (§4.3): how ClassifyCalldata read the raw calldata, so an agent
	// pre-flights whether its bytes are treated as a spend-equivalent before signing.
	// nil for every non-contract-send path (and omitted from the wire).
	Classification *Classification `json:"classification,omitempty"`
}

// Classification is the M10 contract-send calldata classification verdict surfaced on
// a --dry-run TxResult (§4.3 "classified_as"/"spender"/"unlimited"). ClassifiedAs is
// "approve"|"transfer"|"unknown"; Spender/Recipient is the DECODED policy subject (the
// calldata bytes, never the contract or the ABI claim); Unlimited is the sentinel
// match; Selector is the leading 4-byte selector (set on the unknown path for the
// stage-5b triple). No float anywhere (§2.5).
type Classification struct {
	ClassifiedAs string `json:"classified_as"`       // "approve" | "transfer" | "unknown"
	Spender      string `json:"spender,omitempty"`   // decoded spender (approve)
	Recipient    string `json:"recipient,omitempty"` // decoded recipient (transfer)
	Unlimited    bool   `json:"unlimited,omitempty"` // sentinel/unbounded
	Selector     string `json:"selector,omitempty"`  // unknown path: the 4-byte selector
	Contract     string `json:"contract,omitempty"`  // the contract (tx To)
}

// TxStatus is the §5.2 lifecycle status on a TxResult. timeout is deliberately
// distinct from failure: it is the resumable "still pending at the deadline"
// outcome (exit 8), not a terminal error.
type TxStatus string

const (
	TxStatusPending   TxStatus = "pending"
	TxStatusConfirmed TxStatus = "confirmed"
	TxStatusReverted  TxStatus = "reverted"
	TxStatusReplaced  TxStatus = "replaced"
	TxStatusTimeout   TxStatus = "timeout" // NOT failure; resumable
)

// Dest is the resolved destination echo on a TxResult: the address plus the
// human ref it resolved from (a contact name in M3, an ENS name in M7), so the
// caller can confirm "this is who I think it is" without re-resolving.
//
// M7 adds provenance (Via/ENSName, additive + omitempty so an M6 JSON envelope is
// byte-identical when they are empty). The service's §4.3 stage-4 pin-drift
// producer reads Via to decide whether a fresh-resolution drift check applies, and
// the EvResolved echo + the result block surface ENSName so an agent/human sees the
// name AND the address it actually resolved to before signing (§4.8).
type Dest struct {
	Address common.Address `json:"address"`
	Name    string         `json:"name,omitempty"` // contact/ENS name it resolved from, if any
	// Via records how the destination was supplied: "ens" (an ENS name, resolved
	// fresh per-invocation), "contact" (a registry contact, snapshot), or "literal"
	// (a raw 0x address — no drift check applies). Empty (omitted) for paths that
	// never set it, which the stage-4 producer treats as a literal address.
	Via string `json:"via,omitempty"`
	// ENSName is the exact ENS name the destination came from ("vitalik.eth"),
	// non-empty only when Via=="ens". The pin-drift Check carries it for the
	// ens_drift/ens_unresolved messaging; the echo shows it alongside the address.
	ENSName string `json:"ens_name,omitempty"`
}

// Asset is the wire asset block on a TxResult. ETH in M3; the token fields
// (Symbol/Contract/Decimals) are plumbed for M5 but stay empty for an ETH send.
type Asset struct {
	Kind     string `json:"kind"` // "eth" | "erc20" | "erc721" | "erc1155" | "contract"
	Symbol   string `json:"symbol,omitempty"`
	Contract string `json:"contract,omitempty"`
	Decimals *int   `json:"decimals,omitempty"`
}

// GasResult is the gas decision on the wire (§5.4). No float anywhere — every
// fee is an exact wei decimal string. WorstCaseGasWei = GasLimit × MaxFeePerGas
// (or × GasPrice in legacy) is the value policy reserved against.
type GasResult struct {
	Legacy          bool   `json:"legacy"`
	GasLimit        uint64 `json:"gas_limit"`
	MaxFeePerGas    string `json:"max_fee_per_gas,omitempty"`
	PriorityFee     string `json:"priority_fee,omitempty"`
	GasPrice        string `json:"gas_price,omitempty"`
	BaseFee         string `json:"base_fee,omitempty"`
	Speed           string `json:"speed,omitempty"`
	Source          string `json:"source,omitempty"` // "fee-history" | "fallback" | "legacy"
	WorstCaseGasWei string `json:"worst_case_gas_wei,omitempty"`
}

// ─── tx status / wait / list ─────────────────────────────────────────────────

// TxStatusRequest folds the journal record for a hash plus a single receipt/nonce
// re-check (no account lock; §5.6 deadlock-free rule). It never broadcasts.
type TxStatusRequest struct {
	Hash    string `json:"hash"`
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
}

// WaitRequest runs the §5.3 state machine on a known hash (the resume-after-
// timeout entry point). nil Confirmations ⇒ per-network default; zero Timeout ⇒
// tx.wait-timeout default.
type WaitRequest struct {
	Hash          string   `json:"hash"`
	Confirmations *uint64  `json:"confirmations,omitempty" jsonschema:"type=integer,minimum=0"`
	Timeout       Duration `json:"timeout,omitempty" jsonschema:"type=string,format=duration"`
	Network       string   `json:"network,omitempty"`
	RPC           string   `json:"rpc,omitempty"`
}

// TxListRequest lists journal records for an account (newest-first). An empty
// Account lists every record on the chain.
type TxListRequest struct {
	Account string `json:"account,omitempty"`
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
	Limit   int    `json:"limit,omitempty"` // 0 = no limit
}

// TxRow is one row in `tx list` (a folded latest-per-id journal record). It is
// the history view — terminal rows are kept (the journal IS the history, §5.6).
type TxRow struct {
	JournalID  string `json:"journal_id"`
	Hash       string `json:"hash,omitempty"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	From       string `json:"from"`
	To         string `json:"to"`
	Nonce      uint64 `json:"nonce"`
	ValueWei   string `json:"value_wei"`
	TS         string `json:"ts"`
	Network    string `json:"network"`
	Replaces   string `json:"replaces,omitempty"`
	ReplacedBy string `json:"replaced_by,omitempty"`
}

// TxListResult is the `tx list` roster.
type TxListResult struct {
	Txs []TxRow `json:"txs"`
}

// ─── tx speedup / cancel / abandon (RBF, §5.5) ───────────────────────────────

// SpeedupRequest rebuilds the identical tx with bumped fees on a pending,
// Daxie-originated hash (foreign hash → ref.not_found; already mined →
// tx.already_mined). The gas opts override the +12.5% bump floor (validated; an
// override below the floor → tx.replacement_underpriced).
type SpeedupRequest struct {
	Hash        string `json:"hash"`
	MaxFee      string `json:"max_fee,omitempty"`
	PriorityFee string `json:"priority_fee,omitempty"`
	GasPrice    string `json:"gas_price,omitempty"`
	Speed       string `json:"speed,omitempty"`

	Network string   `json:"network,omitempty"`
	RPC     string   `json:"rpc,omitempty"`
	Yes     bool     `json:"-"`
	Confirm bool     `json:"confirm" jsonschema:"default=false"`
	Wait    WaitOpts `json:"wait,omitempty"`
}

// CancelRequest replaces a pending tx with a 0-value self-send (to=from, gas
// 21000) at bumped fees, journal kind "cancel" (§5.5).
type CancelRequest struct {
	Hash        string `json:"hash"`
	MaxFee      string `json:"max_fee,omitempty"`
	PriorityFee string `json:"priority_fee,omitempty"`
	GasPrice    string `json:"gas_price,omitempty"`
	Speed       string `json:"speed,omitempty"`

	Network string   `json:"network,omitempty"`
	RPC     string   `json:"rpc,omitempty"`
	Yes     bool     `json:"-"`
	Confirm bool     `json:"confirm" jsonschema:"default=false"`
	Wait    WaitOpts `json:"wait,omitempty"`
}

// AbandonRequest voids a signed-never-broadcast record (the §5.6 escape hatch):
// failed + reservation.Release + the nonce freed.
type AbandonRequest struct {
	Hash    string `json:"hash"`
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
}

// AbandonResult confirms an abandon.
type AbandonResult struct {
	Hash      string `json:"hash"`
	JournalID string `json:"journal_id"`
	Abandoned bool   `json:"abandoned"`
}

// ─── gas ─────────────────────────────────────────────────────────────────────

// GasRequest is the read-only `daxie gas` selection: a network/endpoint plus an
// optional --speed focus and the legacy toggle. It prints all three speed quotes
// regardless of Speed; Speed only marks which row is the "selected" one.
type GasRequest struct {
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
	Speed   string `json:"speed,omitempty"`
	Legacy  bool   `json:"legacy,omitempty"`
}

// GasQuotesResult is the §5.4 three-speed `daxie gas` view + the next base fee.
// Each quote is a full GasResult (no float; decimal-string fees).
type GasQuotesResult struct {
	Network string    `json:"network"`
	Legacy  bool      `json:"legacy"`
	BaseFee string    `json:"base_fee,omitempty"`
	Slow    GasResult `json:"slow"`
	Normal  GasResult `json:"normal"`
	Fast    GasResult `json:"fast"`
}

// ─── contacts (§7.8) ─────────────────────────────────────────────────────────

// ContactAddRequest adds a name→address entry to the network-agnostic contacts
// registry (§7.8). The name follows the §3.1 grammar; a duplicate is usage.*. The
// address is a raw 0x OR an ENS name (M7) — an ENS name is resolved NOW against
// Network/RPC and the resolved 0x is stored (a snapshot; §2.8 per-call endpoint).
// Network/RPC are read only on the ENS path.
type ContactAddRequest struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
}

// ContactShowRequest / ContactRemoveRequest select one contact by name
// (case-insensitive); a miss is ref.not_found (exit 10).
type ContactShowRequest struct {
	Name string `json:"name"`
}

type ContactRemoveRequest struct {
	Name string `json:"name"`
}

// ContactListRequest lists every contact (no filter in v1).
type ContactListRequest struct{}

// ContactRow is one contacts entry on the wire. ENS/PinnedAt are the M7 pin half
// (present now, populated only by M7).
type ContactRow struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	ENS      string `json:"ens,omitempty"`
	PinnedAt string `json:"pinned_at,omitempty"`
}

// ContactResult wraps one contact row (add/show).
type ContactResult struct {
	Contact ContactRow `json:"contact"`
}

// ContactListResult is the contacts roster, name-sorted.
type ContactListResult struct {
	Contacts []ContactRow `json:"contacts"`
}

// ContactRemoveResult confirms a contact removal.
type ContactRemoveResult struct {
	Name    string `json:"name"`
	Removed bool   `json:"removed"`
}

// ─── M3 error-code constants ─────────────────────────────────────────────────

// These name the M3 tx/gas leaves the pipeline emits. Their exit projections are
// ALREADY in error.go's codeExit registry (authored complete in M0); this only
// gives the strings Go names so service stops literaling them. No new exit
// numbers, no codeExit edits.
const (
	// CodeTxReverted — receipt status 0x0 (exit 7).
	CodeTxReverted = "tx.reverted"
	// CodeTxReplaced — the nonce was consumed by a different hash (exit 9).
	CodeTxReplaced = "tx.replaced"
	// CodeTxReplacementUnderpriced — an RBF override below the +12.5% bump floor
	// or geth's pricebump (exit 9).
	CodeTxReplacementUnderpriced = "tx.replacement_underpriced"
	// CodeTxAlreadyMined — `tx speedup`/`tx cancel` on a hash that already has a
	// receipt (exit 9).
	CodeTxAlreadyMined = "tx.already_mined"
	// CodeTxNonceGap — a nonce gap detected during reconciliation (exit 9).
	CodeTxNonceGap = "tx.nonce_gap"
	// CodeFundsInsufficient — `insufficient funds` on broadcast (exit 5).
	CodeFundsInsufficient = "funds.insufficient"
	// CodeTxWaitTimeout — the §5.3 deadline hit in a non-terminal state (exit 8,
	// resumable, retryable).
	CodeTxWaitTimeout = "tx.wait_timeout"
	// CodePolicyDenied — the policy verdict denied the tx (exit 3). M3's stub
	// always allows, so service emits this only on the gas-cap / RBF paths.
	CodePolicyDenied = "policy.denied"
	// CodePolicyDeniedGasCap — maxFeePerGas/gasPrice exceeded policy.max-gas-price
	// (exit 3). The gas_cap_below_bump_floor RBF sub-reason rides in Error.Data,
	// not a separate code.
	CodePolicyDeniedGasCap = "policy.denied.gas_cap"
	// CodeTxIntegrityReservationMissing — a `broadcast` record whose reservation
	// id resolves to no durable reservation (counter-file tampering; exit 12). The
	// shared rebroadcast helper refuses to resurrect it.
	CodeTxIntegrityReservationMissing = "tx.integrity.reservation_missing"
	// CodeStateCorrupt — an unrecoverable journal/state corruption (exit 11).
	CodeStateCorrupt = "state.corrupt"
)
