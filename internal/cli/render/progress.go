package render

import (
	"fmt"
	"io"

	"github.com/daxchain-io/daxie/internal/domain"
)

// progress.go builds the EventSink the cli frontend hands to the send/wait use
// cases (§5.9). The binding rule: send/wait progress goes to STDERR, NEVER stdout
// — under --json, stdout must carry EXACTLY ONE final object (the TxResult), so
// every interim Event (resolved/estimated/policy_ok/signed/broadcast/confirmation)
// is written to stderr regardless of mode. The Event.Stream hint says "stderr" for
// these kinds; we honor it and additionally hard-route everything that is not the
// terminal receive line away from stdout, so a future event with a missing Stream
// hint can never leak onto stdout and break the single-object contract.
//
// In --json mode the interim events are SUPPRESSED entirely (an agent parses the
// one stdout object and branches on its Status/exit; the human progress chatter on
// stderr would be noise it never reads). In human mode they print as short
// stderr lines so an operator watching a --wait sees confirmations tick up.

// StderrProgress returns the send/wait EventSink (§5.9). stderr is where every
// non-terminal progress line goes. jsonMode suppresses the human chatter (the one
// JSON result object is emitted separately by the command via render.Result on
// stdout); a nil writer yields a no-op sink.
//
// The returned sink is safe for the core's nil-tolerant Emit contract — callers
// may pass it or nil interchangeably.
func StderrProgress(stderr io.Writer, jsonMode bool) domain.EventSink {
	if stderr == nil {
		return nil
	}
	return func(ev domain.Event) {
		// Hard invariant: send/wait events NEVER touch stdout. The Event carries a
		// Stream hint ("stderr" for send/wait) but we do not consult stdout here at
		// all — this sink only ever owns the stderr stream, so the single-object
		// stdout contract holds by construction.
		if jsonMode {
			// --json: the result is the single stdout object; interim progress is
			// suppressed so nothing competes with it and stderr stays quiet for
			// machine consumers. (A wait that ultimately fails still surfaces via the
			// §5.7 error envelope on stderr from mapError, not from here.)
			return
		}
		line := humanEventLine(ev)
		if line == "" {
			return
		}
		_, _ = io.WriteString(stderr, line+"\n")
	}
}

// humanEventLine formats one progress Event as a short human stderr line. An
// unrecognized kind yields "" (skipped) so the sink never prints noise for events
// a future milestone adds.
func humanEventLine(ev domain.Event) string {
	switch ev.Kind {
	case domain.EvResolved:
		if ev.Detail != "" {
			return "resolved: " + ev.Detail
		}
		return "resolved: " + ev.Address.Hex()
	case domain.EvEstimated:
		if ev.Detail != "" {
			return "gas estimated: " + ev.Detail
		}
		return "gas estimated"
	case domain.EvPolicyOK:
		return "policy: ok"
	case domain.EvSigned:
		if ev.Hash != "" {
			return "signed: " + ev.Hash
		}
		return "signed"
	case domain.EvBroadcast:
		return "broadcast: " + ev.Hash
	case domain.EvConfirmation:
		// One per confirmation block during --wait. Show progress toward the target.
		if ev.Target > 0 {
			return fmt.Sprintf("confirmation %d/%d", ev.Conf, ev.Target)
		}
		return fmt.Sprintf("confirmation %d", ev.Conf)
	default:
		return ""
	}
}
