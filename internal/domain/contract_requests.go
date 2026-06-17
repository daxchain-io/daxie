package domain

// contract_requests.go is the M10 `daxie contract` wire contract (design §2.5): the
// request/result types for the broadest-reach signing path (`contract send`) plus the
// four PURE read/build paths (`contract call`/`logs`/`encode`/`decode`). They are
// triple-duty (§2.5): the CLI flag-binding target, the future MCP input-schema source
// (§6.2), and the v1.1 HTTP body — so they carry json + jsonschema tags.
//
// The §2.5 decimal-exactness rule holds verbatim: NO float-typed field anywhere.
// Positional args cross as []string (coerced ONCE in core by the ABI — "parse once",
// §2.3); return/decoded values come back as labeled string-typed DecodedValue entries
// (a uint256 exceeds int64, so it is a decimal STRING, never a JSON number; arrays/
// tuples are JSON-encoded strings). ContractSend returns the SAME domain.TxResult as
// SendTx — one result type for every broadcasting op (§5.1).

// ABISource is the ABI-resolution input. Precedence is enforced in core (§2.5):
// a registered alias's stored ABI > --abi/--abi-stdin JSON > inline --sig. EXACTLY
// ONE source must be resolvable for the named method/event; a disagreement (e.g. a
// registered alias AND an explicit --sig) is usage.* (exit 2). ABIJSON is the file
// contents or the stdin bytes — the file/stdin read is a FRONTEND I/O concern; the
// frontend reads it and hands the bytes here.
type ABISource struct {
	Alias   string `json:"alias,omitempty"`    // registry alias → its stored ABI
	ABIJSON string `json:"abi_json,omitempty"` // --abi file contents OR --abi-stdin (read by the frontend)
	Sig     string `json:"sig,omitempty"`      // inline "earned(address)(uint256)"
}

// DecodedValue is one labeled output / decoded arg. Value is ALWAYS a string (a
// uint256 exceeds int64 → decimal string; arrays/tuples → JSON-encoded string), so
// the §2.5 no-float rule holds across the boundary. Name is the ABI label when the
// ABI declares one (else a positional "arg0"); Type is the solidity type.
type DecodedValue struct {
	Name  string `json:"name,omitempty"` // ABI output/arg name when present
	Type  string `json:"type"`           // solidity type, e.g. "uint256","bytes32[]"
	Value string `json:"value"`          // decimal string / 0x / JSON-encoded compound
}

// ── contract call (READ; eth_call; NEVER signs, NEVER policy — §5.11) ──────────

// ContractCallRequest is `daxie contract call`: a read-only eth_call. Contract is an
// alias / 0x / ENS; Method is the function name (omit when --sig carries it); Args are
// positional strings coerced by the ABI. From is an OPTIONAL msg.sender (a 0x/ENS/
// account ref resolved via Signer.Address — NOT a signer, no unlock). Block is a number
// or tag (empty = latest).
type ContractCallRequest struct {
	Contract string    `json:"contract" jsonschema:"alias, 0x address, or ENS of the contract"`
	Method   string    `json:"method,omitempty" jsonschema:"function name; omit when --sig carries it"`
	Args     []string  `json:"args,omitempty" jsonschema:"positional args as strings, coerced by the ABI"`
	ABI      ABISource `json:"abi,omitempty"`
	From     string    `json:"from,omitempty" jsonschema:"optional msg.sender (address/ENS/account ref); NOT a signer"`
	Block    string    `json:"block,omitempty" jsonschema:"block number or tag; empty = latest"`
	Network  string    `json:"network,omitempty"`
	RPC      string    `json:"rpc,omitempty"`
}

// ContractCallResult is the decoded eth_call return: the resolved+echoed contract Dest
// (§2.5), the resolved method name, one labeled DecodedValue per ABI output, and the
// block read (nil = latest).
type ContractCallResult struct {
	Contract Dest           `json:"contract"` // resolved + echoed (Dest, §2.5)
	Method   string         `json:"method"`
	Returns  []DecodedValue `json:"returns"` // one per ABI output, labeled
	Block    *uint64        `json:"block,omitempty"`
	Network  string         `json:"network"`
}

// ── contract send (SIGNS; routes through §5.1 exactly like tx send) ────────────

// ContractSendRequest is `daxie contract send`: the broadest-reach signing path. The
// Contract is the tx DESTINATION (the policy destination, resolved+echoed before sign).
// abi.PackCall(method, coercedArgs) becomes the tx data; Value is msg.value (folds into
// SpendWei for EVERY contract send, recognition-independent — §4.3 stage 2). The gas/
// nonce/wait/dry-run/confirm fields are IDENTICAL to TxRequest so there is ONE gas+wait
// surface (the 21000-EOA gas exception does NOT apply — a contract call is never 21000).
type ContractSendRequest struct {
	Contract string    `json:"contract" jsonschema:"alias, 0x address, or ENS — the tx DESTINATION"`
	Method   string    `json:"method,omitempty"`
	Args     []string  `json:"args,omitempty"`
	ABI      ABISource `json:"abi,omitempty"`
	Value    string    `json:"value,omitempty" jsonschema:"msg.value, e.g. 0.5 (ETH); counts vs spend limits"`
	From     string    `json:"from,omitempty"`
	// gas/nonce/wait/dry-run/confirm — IDENTICAL to TxRequest so there is ONE gas+wait surface.
	GasLimit    string  `json:"gas_limit,omitempty"`
	MaxFee      string  `json:"max_fee,omitempty"`
	PriorityFee string  `json:"priority_fee,omitempty"`
	GasPrice    string  `json:"gas_price,omitempty"`
	Speed       string  `json:"speed,omitempty"`
	Legacy      bool    `json:"legacy,omitempty"`
	Nonce       *uint64 `json:"nonce,omitempty" jsonschema:"type=integer,minimum=0"`
	Network     string  `json:"network,omitempty"`
	RPC         string  `json:"rpc,omitempty"`
	DryRun      bool    `json:"dry_run,omitempty"`
	Confirm     bool    `json:"confirm" jsonschema:"default=false"` // the --yes gate; MCP default false
	Yes         bool    `json:"-"`                                  // CLI-only TTY skip; excluded from MCP schema
	// AckUnlimited is the SEPARATE deliberate unlimited-approval acknowledgement — the
	// CLI --unlimited flag, the MCP acknowledgeUnlimited field — mapped straight to
	// Check.Acked (§4.2 line 1561). It is DISTINCT from Confirm/Yes: --yes only skips the
	// TTY confirmation, while AckUnlimited is the deliberate "I accept an infinite
	// allowance" bit. A `contract send` whose calldata classifies as an unlimited
	// approve/setApprovalForAll/permit sentinel without AckUnlimited is denied
	// policy.denied.unlimited_unacked (exit 3) — EXACTLY like `token approve --unlimited`,
	// so the generic noun cannot silently defeat the typed ceremony (§11 D12).
	AckUnlimited bool     `json:"acknowledge_unlimited,omitempty" jsonschema:"default=false"`
	Wait         WaitOpts `json:"wait,omitempty"`
}

// ContractSend returns the SAME domain.TxResult as SendTx (§5.2) — one result type for
// every broadcasting op. (No dedicated result type is declared, by design.)

// ── contract logs (READ; eth_getLogs; NEVER signs — §5.11) ────────────────────

// LogFilter is one indexed-arg filter (name=value). The value is coerced to a 32-byte
// topic by the ABI (an address arg is ref/ENS-resolved). A filter on a NON-indexed arg
// is usage.* (exit 2).
type LogFilter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// DecodedLog is one decoded log: its location + the labeled args (indexed from Topics,
// non-indexed from Data, merged in ABI order).
type DecodedLog struct {
	TxHash    string         `json:"tx_hash"`
	LogIndex  uint           `json:"log_index"`
	Block     uint64         `json:"block"`
	BlockHash string         `json:"block_hash"`
	Event     string         `json:"event"`
	Args      []DecodedValue `json:"args"` // indexed (topics) + non-indexed (data), labeled
}

// ContractLogsRequest is `daxie contract logs`: a read-only eth_getLogs. Event is the
// event name (omit when --sig carries it); Args are indexed-arg filters; the block
// range defaults to latest (empty ToBlock).
type ContractLogsRequest struct {
	Contract  string      `json:"contract" jsonschema:"alias, 0x address, or ENS"`
	Event     string      `json:"event,omitempty" jsonschema:"event name; omit when --sig carries it"`
	ABI       ABISource   `json:"abi,omitempty"`
	Args      []LogFilter `json:"args,omitempty" jsonschema:"indexed-arg filters (name=value)"`
	FromBlock string      `json:"from_block,omitempty"`
	ToBlock   string      `json:"to_block,omitempty"` // empty = latest
	Network   string      `json:"network,omitempty"`
	RPC       string      `json:"rpc,omitempty"`
}

// ContractLogsResult is the decoded log set for an event on a contract.
type ContractLogsResult struct {
	Contract Dest         `json:"contract"`
	Event    string       `json:"event"`
	Logs     []DecodedLog `json:"logs"`
	Network  string       `json:"network"`
}

// ── encode / decode (PURE; no chain, no signing, NO policy — §5.11, §11 D12) ──

// EncodeRequest is `daxie contract encode`: build selector||abi(args) → 0x calldata.
// Pure — for relayers/meta-tx/debugging. It carries no contract (the destination is
// irrelevant to building bytes) UNLESS the ABI comes from a registered alias; the
// frontend supplies the alias via ABI.Alias when the first positional is one.
type EncodeRequest struct {
	Method  string    `json:"method,omitempty"`
	Args    []string  `json:"args,omitempty"`
	ABI     ABISource `json:"abi,omitempty"`
	Network string    `json:"network,omitempty"` // only to resolve a registered alias's ABI
}

// EncodeResult is the 0x calldata bytes.
type EncodeResult struct {
	Calldata string `json:"calldata"` // "0x…"
}

// DecodeRequest is `daxie contract decode`: parse 0x calldata → method + selector +
// labeled args. Pure — never touches the chain or policy.
type DecodeRequest struct {
	Calldata string    `json:"calldata" jsonschema:"0x… raw calldata"`
	ABI      ABISource `json:"abi,omitempty"` // --sig "stake(uint256)" or a registered/--abi ABI
	Network  string    `json:"network,omitempty"`
}

// DecodeResult is the decoded calldata: the resolved method, the leading 4-byte
// selector, and the labeled args.
type DecodeResult struct {
	Method   string         `json:"method"`
	Selector string         `json:"selector"` // "0x…" 4-byte
	Args     []DecodedValue `json:"args"`
}

// ── contract registry (state class; §7.8 contracts[]) ─────────────────────────

// ContractRow is one `daxie contract list`/`add`/`show` entry: the alias↔address
// binding (the anti-spoofing unit) + an ABI summary. ABI bytes are not echoed in a
// list (only the function/event counts); `show` carries the function/event names.
type ContractRow struct {
	Alias     string   `json:"alias"`
	Address   string   `json:"address"`
	Network   string   `json:"network"`
	Functions []string `json:"functions,omitempty"` // function signatures (show)
	Events    []string `json:"events,omitempty"`    // event signatures (show)
	FuncCount int      `json:"function_count"`
	EvtCount  int      `json:"event_count"`
}

// ContractListResult is `contract list`.
type ContractListResult struct {
	Network   string        `json:"network"`
	Contracts []ContractRow `json:"contracts"`
}

// ContractRemoveResult is `contract remove`.
type ContractRemoveResult struct {
	Alias   string `json:"alias"`
	Network string `json:"network"`
	Removed bool   `json:"removed"`
}

// ── contract request structs the frontend fills for the registry CRUD ─────────

// ContractAddRequest is `daxie contract add <alias> <0x> (--abi | --abi-stdin)`. The
// ABIJSON is the file/stdin bytes the frontend read; core validates it via abi.ParseJSON
// before store (invalid ⇒ usage.bad_abi, never stored).
type ContractAddRequest struct {
	Alias   string `json:"alias"`
	Address string `json:"address"`
	ABIJSON string `json:"abi_json"`
	Network string `json:"network,omitempty"`
	RPC     string `json:"rpc,omitempty"`
}

// ContractShowRequest / ContractListRequest / ContractRemoveRequest are the read/admin
// requests (alias + network).
type ContractShowRequest struct {
	Alias   string `json:"alias"`
	Network string `json:"network,omitempty"`
}
type ContractListRequest struct {
	Network string `json:"network,omitempty"`
}
type ContractRemoveRequest struct {
	Alias   string `json:"alias"`
	Network string `json:"network,omitempty"`
}
