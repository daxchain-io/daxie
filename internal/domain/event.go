package domain

import "github.com/ethereum/go-ethereum/common"

// EventKind enumerates the progress events the core emits over the one streaming
// seam (§5.9). The full set is defined here so every milestone shares one sink
// type; M1 use cases emit none of the tx/receive kinds (wallet/account ops are
// fire-and-return), but the seam exists so M3+ is a thin addition and so the
// uniform (ctx, Principal, Request, EventSink) service shape holds from M1.
type EventKind string

const (
	EvResolved     EventKind = "resolved"     // ENS/contact resolved (echo before signing)
	EvEstimated    EventKind = "estimated"    // gas/fees estimated
	EvPolicyOK     EventKind = "policy_ok"    // policy check passed
	EvSigned       EventKind = "signed"       // tx signed (pre-broadcast)
	EvBroadcast    EventKind = "broadcast"    // raw tx submitted
	EvConfirmation EventKind = "confirmation" // one per confirmation block (--wait)
	EvListening    EventKind = "listening"    // receive — address emitted, now blocking
	EvDetected     EventKind = "detected"     // receive — inbound transfer seen
	EvConfirming   EventKind = "confirming"   // receive — awaiting confirmations
	EvConfirmed    EventKind = "confirmed"    // receive — one per confirmed inbound (NOT terminal)
	EvReorged      EventKind = "reorged"      // receive — a confirmed detection reorged out (subtract)
	EvHeartbeat    EventKind = "heartbeat"    // receive — quiet-period keepalive
	EvComplete     EventKind = "complete"     // receive — the single terminal success line (carries Exit)
	EvTimeout      EventKind = "timeout"      // receive — terminal line on timeout (carries Exit)
)

// EventAsset is the resolved asset echoed on the receive `listening` line (§5.8).
// It mirrors ReceiveAsset's wire shape but lives on Event so the service emit and
// the renderer share one type without the renderer importing the request structs.
type EventAsset struct {
	Kind     string `json:"kind"`               // "eth" | "erc20" | "erc721" | "erc1155"
	Contract string `json:"contract,omitempty"` // EIP-55 hex (token/NFT)
	Alias    string `json:"alias,omitempty"`
	Decimals int    `json:"decimals,omitempty"` // erc20 only (display)
	TokenID  string `json:"token_id,omitempty"` // nft only (decimal string)
}

// EventTarget is the resolved completion target echoed on the receive `listening`
// line (§5.8). Timeout is *string so an unbounded wait emits "timeout":null
// verbatim.
type EventTarget struct {
	Mode          string  `json:"mode"`
	Amount        string  `json:"amount,omitempty"`
	Confirmations uint64  `json:"confirmations"`
	Timeout       *string `json:"timeout"`
}

// Event is the single progress record streamed through EventSink (§5.9). One sink
// type does not mean one destination: the FRONTEND routes per use case via the
// Stream hint — send/wait progress to stderr, receive's NDJSON to stdout — and
// reads the terminal exit code from Exit so agents never inspect $?.
//
// No float field (§2.5). Address is a geth value type (the one non-stdlib import
// domain permits). Stream is json:"-" — a frontend routing hint, never on the
// wire.
type Event struct {
	Kind    EventKind      `json:"event"`
	Hash    string         `json:"hash,omitempty"`
	Address common.Address `json:"address,omitempty"`
	Conf    uint64         `json:"confirmations,omitempty"`
	Target  uint64         `json:"target,omitempty"`
	Detail  string         `json:"detail,omitempty"`
	Exit    *int           `json:"exit,omitempty"` // carried by terminal receive lines
	Stream  string         `json:"-"`              // "stdout" (receive) | "stderr" (send/wait)

	// ── M8 receive payload (§5.8/§5.9) ──
	//
	// The receive NDJSON wire shape is produced by cli/render/receive.go, which
	// constructs a purpose-built struct PER kind so the §5.8 key set is byte-exact
	// (no stray send/wait keys, no key collisions on "confirmations"/"target").
	// These fields are therefore the data carrier the renderer maps from; their
	// json:"-" tags keep them OFF a whole-Event marshal so a future generic
	// json.Marshal(Event) cannot leak a half-formed receive line or collide with
	// the send/wait keys above. No float anywhere (§2.5): amounts are base-unit
	// decimal strings.
	V                   int          `json:"-"` // always 1 on receive lines (renderer stamps it)
	Network             string       `json:"-"`
	ChainID             uint64       `json:"-"`
	Asset               *EventAsset  `json:"-"` // listening
	TargetSpec          *EventTarget `json:"-"` // listening
	TxHash              string       `json:"-"` // detected/confirming/confirmed/reorged
	LogIndex            *int         `json:"-"` // detected
	From                string       `json:"-"` // detected
	Value               string       `json:"-"` // detected/confirmed/reorged (base-unit decimal)
	TokenID             *string      `json:"-"` // detected (nft); nil ⇒ null in eth/erc20 examples
	Block               uint64       `json:"-"` // detected
	BlockHash           string       `json:"-"` // detected
	Attribution         string       `json:"-"` // detected (tx|log|balance-delta)
	Match               *bool        `json:"-"` // detected
	CumulativeDetected  string       `json:"-"`
	CumulativeConfirmed string       `json:"-"`
	Remaining           string       `json:"-"`
	LastScanned         uint64       `json:"-"`
	FromBlock           uint64       `json:"-"` // listening
	TxHashes            []string     `json:"-"` // complete
	Resume              string       `json:"-"` // timeout
	Note                string       `json:"-"` // ETH-listen "verify balance before resuming"
	TS                  string       `json:"-"` // RFC3339 timestamp (service clock)
}

// EventSink is the one streaming callback the core emits to (§5.9). A nil sink
// means "no progress" — the common fire-and-return case for every M1
// wallet/account/keystore use case. Callers MUST tolerate a nil sink.
type EventSink func(Event)

// Emit is a nil-safe sink invocation so service use cases need no nil guard at
// every call site: s.Emit(sink, ev) is a no-op when sink is nil.
func Emit(sink EventSink, ev Event) {
	if sink != nil {
		sink(ev)
	}
}
