package domain

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestKeystoreDerivationWatermarkExit pins the one new M1 code to its §5.7 exit
// integer (11, STATE). A change here is a wire break.
func TestKeystoreDerivationWatermarkExit(t *testing.T) {
	if got := ExitOf(CodeKeystoreDerivationWatermark); got != ExitState {
		t.Errorf("ExitOf(%q) = %d (%s), want %d (STATE)", CodeKeystoreDerivationWatermark, got, got, ExitState)
	}
	// The const string must be the canonical dotted code, and New must derive the
	// exit from it (not fall through to ExitInternal).
	if CodeKeystoreDerivationWatermark != "keystore.derivation_watermark" {
		t.Errorf("watermark code const = %q, want keystore.derivation_watermark", CodeKeystoreDerivationWatermark)
	}
	if e := New(CodeKeystoreDerivationWatermark, "next_index below materialized index"); e.Exit != ExitState {
		t.Errorf("New(watermark).Exit = %d, want %d", e.Exit, ExitState)
	}
}

// TestKeystoreCodeConstsMatchRegistry guards the M1 keystore code consts against
// the registry: each must map to its documented §5.7 exit, never to ExitInternal
// (which would mislabel a real condition as a daxie bug).
func TestKeystoreCodeConstsMatchRegistry(t *testing.T) {
	cases := []struct {
		code string
		want ExitCode
	}{
		{CodeKeystoreReadOnly, ExitNotFound},         // 10
		{CodeKeystorePermsInsecure, ExitIntegrity},   // 12
		{CodeKeystoreDerivationWatermark, ExitState}, // 11
	}
	for _, c := range cases {
		if got := ExitOf(c.code); got != c.want {
			t.Errorf("ExitOf(%q) = %d (%s), want %d (%s)", c.code, got, got, c.want, c.want)
		}
		if ExitOf(c.code) == ExitInternal {
			t.Errorf("keystore code %q resolves to ExitInternal(1); must have a distinct §5.7 exit", c.code)
		}
	}
}

// TestEventMarshal proves the §5.9 Event marshals to the documented wire shape:
// the kind under "event", omitempty on the optional fields, the exit pointer
// surfaced, and the Stream routing hint kept OFF the wire (json:"-").
func TestEventMarshal(t *testing.T) {
	exit := 0
	ev := Event{
		Kind:    EvBroadcast,
		Hash:    "0xabc",
		Address: common.HexToAddress("0x52908400098527886E0F7030069857D2E4169EE7"),
		Conf:    2,
		Target:  2,
		Detail:  "mined",
		Exit:    &exit,
		Stream:  "stderr", // must NOT appear on the wire
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal Event: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal Event: %v", err)
	}
	if _, ok := m["event"]; !ok {
		t.Errorf("Event must serialize Kind under \"event\": %s", b)
	}
	if _, ok := m["stream"]; ok {
		t.Errorf("Stream is a frontend routing hint and must never serialize: %s", b)
	}
	if _, ok := m["exit"]; !ok {
		t.Errorf("Exit pointer (non-nil) must serialize: %s", b)
	}
	// Round-trip the kind string.
	var got Event
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if got.Kind != EvBroadcast {
		t.Errorf("kind round-trip = %q, want %q", got.Kind, EvBroadcast)
	}
}

// TestEventOmitsEmptyOptionals: a bare Event omits the string/number/pointer
// optionals (so the receive NDJSON stays terse) and never serializes Stream.
//
// Documented exception: Address is geth's common.Address, a [20]byte ARRAY.
// encoding/json's omitempty does NOT suppress a zero-valued array (omitempty only
// fires for false/0/""/nil/empty-slice/empty-map), so a zero Address always
// serializes as the all-zero hex. This is a property of the §5.9 struct as
// designed — events that carry no address (the M1 case, and tx/wait/receive lines
// where an address is irrelevant) emit "address":"0x000…0". Callers that care set
// a real Address; downstream parsers treat the zero address as "absent".
func TestEventOmitsEmptyOptionals(t *testing.T) {
	b, _ := json.Marshal(Event{Kind: EvListening})
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"hash", "confirmations", "target", "detail", "exit", "stream"} {
		if _, ok := m[k]; ok {
			t.Errorf("empty optional %q should be omitted: %s", k, b)
		}
	}
	if _, ok := m["event"]; !ok {
		t.Errorf("event key must always be present: %s", b)
	}
	// Address is an array type: omitempty cannot suppress it, so the zero address
	// is present. Pin that reality so a future struct change is a conscious choice.
	if _, ok := m["address"]; !ok {
		t.Errorf("zero common.Address (array type) is NOT suppressed by omitempty; expected it present: %s", b)
	}
}

// TestEventKindStrings pins the §5.9 kind tag strings (the receive NDJSON contract
// agents parse). A drift here breaks downstream parsers.
func TestEventKindStrings(t *testing.T) {
	want := map[EventKind]string{
		EvResolved: "resolved", EvEstimated: "estimated", EvPolicyOK: "policy_ok",
		EvSigned: "signed", EvBroadcast: "broadcast", EvConfirmation: "confirmation",
		EvListening: "listening", EvDetected: "detected", EvConfirming: "confirming",
		EvConfirmed: "confirmed", EvComplete: "complete", EvTimeout: "timeout",
	}
	for k, s := range want {
		if string(k) != s {
			t.Errorf("EventKind %v = %q, want %q", k, string(k), s)
		}
	}
}

// TestEmitNilSafe: Emit on a nil sink is a no-op (the fire-and-return case every
// M1 use case relies on), and a non-nil sink receives the event.
func TestEmitNilSafe(t *testing.T) {
	// Must not panic.
	Emit(nil, Event{Kind: EvSigned})

	var got *Event
	sink := EventSink(func(e Event) { got = &e })
	Emit(sink, Event{Kind: EvSigned})
	if got == nil || got.Kind != EvSigned {
		t.Errorf("Emit did not deliver to a non-nil sink: %+v", got)
	}
}
