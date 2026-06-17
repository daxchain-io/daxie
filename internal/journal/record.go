// Package journal is the crash-safe local transaction journal + nonce manager
// (design §5.6). It persists Daxie-originated transactions as JSONL (one record =
// one line = one write(2)), one file per chain, guarded by cross-platform flock
// (via internal/fsx). IDs are ULIDs (in-package, see id.go). The journal is the
// source of truth for consumed nonces; the nonce cache file is an accelerator.
//
// The two statuses `signed` (journaled BEFORE broadcast, no recorded broadcast) and
// `broadcast` (after broadcast succeeded) are the §5.1 reconciliation discriminator:
// "no broadcast recorded ⇒ release; broadcast recorded ⇒ commit". This is what makes
// a crash only ever UNDER-spend.
//
// Dependency surface (§2.2, enforced by arch_test): journal imports internal/fsx,
// internal/secret, internal/domain, and the go-ethereum value types only. It NEVER
// imports service, a frontend, or policy — policy CANNOT import journal; service
// bridges the two for the §5.1 reconciliation.
package journal

// Status is the record lifecycle (§5.6). `signed` = journaled BEFORE broadcast (no
// recorded broadcast); `broadcast` = after broadcast succeeded — the §5.1
// reconciliation discriminator. `failed` records are excluded from nonce folding (a
// refused broadcast never burns the nonce). The terminal set {confirmed, reverted,
// replaced, failed} is what Unresolved() filters OUT.
type Status string

const (
	StatusSigned    Status = "signed"
	StatusBroadcast Status = "broadcast"
	StatusPending   Status = "pending"
	StatusMined     Status = "mined"
	StatusConfirmed Status = "confirmed"
	StatusReverted  Status = "reverted"
	StatusReplaced  Status = "replaced"
	StatusDropped   Status = "dropped"
	StatusFailed    Status = "failed"
)

// terminalStatuses are the statuses a record never leaves: it is resolved and is
// only kept as `tx list` history. Unresolved() returns everything NOT in this set.
var terminalStatuses = map[Status]bool{
	StatusConfirmed: true,
	StatusReverted:  true,
	StatusReplaced:  true,
	StatusFailed:    true,
}

// IsTerminal reports whether s is a resolved status (§5.6 — Unresolved excludes
// these; compaction may drop superseded non-terminal lines but keeps terminal ones).
func (s Status) IsTerminal() bool { return terminalStatuses[s] }

// consumesNonce reports whether a record in status s consumed an on-chain nonce for
// the purpose of nonce folding (§5.6: "max(nonce over ALL records that consumed an
// on-chain nonce — every status EXCEPT failed)"). Only `failed` (a refused
// broadcast) did not burn the nonce.
func (s Status) consumesNonce() bool { return s != StatusFailed }

// Kind classifies the tx (§5.6). M3 only WRITES eth-transfer / cancel / speedup; the
// remaining variants are declared so the on-disk schema is stable for M5/M6/M10 (a
// `contract send` whose calldata the §4.2 classifier recognizes is journaled under
// the classified kind, e.g. erc20-transfer / approve).
type Kind string

const (
	KindETHTransfer     Kind = "eth-transfer"
	KindERC20Transfer   Kind = "erc20-transfer"
	KindERC721Transfer  Kind = "erc721-transfer"
	KindERC1155Transfer Kind = "erc1155-transfer"
	KindApprove         Kind = "approve"
	KindContractCall    Kind = "contract-call"
	KindCancel          Kind = "cancel"
	KindSpeedup         Kind = "speedup"
)

// Asset is the journaled asset block (§5.6). For ETH: Kind="eth" (or empty), Amount
// mirrors value_wei. uint256 quantities are decimal strings; Amount is null for an
// unrecognized contract-call; TokenID is a decimal string or nil.
type Asset struct {
	Kind     string  `json:"kind"` // "eth" | "erc20" | "erc721" | "erc1155" | "contract"
	Contract *string `json:"contract,omitempty"`
	Alias    string  `json:"alias,omitempty"`
	Decimals *int    `json:"decimals,omitempty"`
	Amount   *string `json:"amount"` // decimal string; null for an unrecognized contract-call
	TokenID  *string `json:"token_id,omitempty"`
}

// Fees is the journaled fee block (§5.6). Decimal strings; GasPrice is non-nil only
// in legacy mode (the 1559 fields are nil then, and vice-versa).
type Fees struct {
	Type              string  `json:"type"` // "eip1559" | "legacy"
	GasLimit          uint64  `json:"gas_limit"`
	MaxFeePerGas      *string `json:"max_fee_per_gas"`
	MaxPriorityPerGas *string `json:"max_priority_fee_per_gas"`
	GasPrice          *string `json:"gas_price"` // legacy only, else null
	Speed             string  `json:"speed,omitempty"`
}

// Receipt is the journaled receipt block (§5.6), nil until mined.
type Receipt struct {
	BlockNumber       uint64 `json:"block_number"`
	BlockHash         string `json:"block_hash"`
	GasUsed           uint64 `json:"gas_used"`
	EffectiveGasPrice string `json:"effective_gas_price"` // decimal string
	Status            uint64 `json:"status"`              // 1 ok, 0 reverted
}

// Record is one journal line (§5.6 schema, VERBATIM field names). One record = one
// line = one write(2). Reads fold latest-wins-per-id; Seq is assigned under the
// flock at append time. RawTx carries the full signed RLP written at status=signed
// BEFORE broadcast, so recovery rebroadcasts the SAME bytes (idempotent).
type Record struct {
	V               int      `json:"v"`  // schema version, 1
	ID              string   `json:"id"` // ULID
	Seq             uint64   `json:"seq"`
	TS              string   `json:"ts"` // RFC3339Nano (UTC) from the injected clock
	ChainID         uint64   `json:"chain_id"`
	Network         string   `json:"network"`
	Kind            Kind     `json:"kind"`
	Status          Status   `json:"status"`
	Source          string   `json:"source"` // "cli" | "mcp" | "mcp:<principal>"
	From            string   `json:"from"`
	To              string   `json:"to"`
	Nonce           uint64   `json:"nonce"`
	TxHash          string   `json:"tx_hash"`
	RawTx           string   `json:"raw_tx"` // 0x… full signed RLP, written at status=signed BEFORE broadcast
	ValueWei        string   `json:"value_wei"`
	Asset           Asset    `json:"asset"`
	Fees            Fees     `json:"fees"`
	ReservationID   string   `json:"reservation_id"`
	WorstCaseGasWei string   `json:"worst_case_gas_wei"`
	Replaces        *string  `json:"replaces"`
	ReplacedBy      *string  `json:"replaced_by"`
	Receipt         *Receipt `json:"receipt"`
	Error           *string  `json:"error"`
	RPC             string   `json:"rpc"`
}

// recordVersion is the current schema version stamped into Record.V on append.
const recordVersion = 1

// clone returns a deep-ish copy of r safe to mutate without aliasing the caller's
// record (pointer fields are copied by value of the pointer; SetState replaces, not
// mutates, them). It is used when SetState derives a new line from the prior latest.
func (r *Record) clone() *Record {
	if r == nil {
		return nil
	}
	cp := *r
	return &cp
}
