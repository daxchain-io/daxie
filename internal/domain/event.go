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
	EvComplete     EventKind = "complete"     // receive — the single terminal success line (carries Exit)
	EvTimeout      EventKind = "timeout"      // receive — terminal line on timeout (carries Exit)
)

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
