package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// receive_test.go locks the §5.8 NDJSON wire shape: every line carries "v":1, all
// amounts are base-unit decimal STRINGS (no float), the address is on the up-front
// `listening` line, the per-event key set matches §5.8, the terminal
// `complete`/`timeout` lines carry `exit`, and a non-receive kind never leaks onto
// the stream. The human-mode branch is asserted to lead with the address and to
// route to the SAME (stdout) writer.

// parseLine decodes one NDJSON line into a generic map so a test can assert the
// exact key set + value TYPES (a number vs a string) the §5.8 contract requires.
func parseLine(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber() // distinguish JSON number from string for the amount-is-string check
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("line is not valid JSON: %v\n%q", err, line)
	}
	return m
}

// jsonSinkLines runs the JSON ReceiveStream over evs and returns the emitted
// non-empty lines.
func jsonSinkLines(evs ...domain.Event) []string {
	var buf bytes.Buffer
	sink := ReceiveStream(&buf, true)
	for _, ev := range evs {
		sink(ev)
	}
	out := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(out) == 1 && out[0] == "" {
		return nil
	}
	return out
}

func mustStringField(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("missing field %q in %v", key, m)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("field %q must be a JSON string, got %T (%v)", key, v, v)
	}
	return s
}

// Every receive NDJSON line carries "v":1 (a JSON number == 1).
func TestReceiveEveryLineHasV1(t *testing.T) {
	addr := common.HexToAddress("0x52ae00000000000000000000000000000000beef")
	tokID := "42"
	exit0, exit8 := 0, 8
	li := 7
	match := true
	evs := []domain.Event{
		{Kind: domain.EvListening, Address: addr, Network: "mainnet", ChainID: 1,
			Asset:      &domain.EventAsset{Kind: "erc20", Contract: "0xa0b8", Alias: "USDC", Decimals: 6},
			TargetSpec: &domain.EventTarget{Mode: "cumulative", Amount: "100000000", Confirmations: 2}, FromBlock: 19000200},
		{Kind: domain.EvDetected, TxHash: "0x9c1f", LogIndex: &li, From: "0xbeef", Value: "60000000",
			TokenID: &tokID, Block: 19000208, BlockHash: "0x77aa", Attribution: "log", Match: &match,
			CumulativeDetected: "60000000", CumulativeConfirmed: "0", Remaining: "100000000", LastScanned: 19000208},
		{Kind: domain.EvConfirming, TxHash: "0x9c1f", Conf: 1, Target: 2, CumulativeConfirmed: "0", Remaining: "100000000", LastScanned: 19000209},
		{Kind: domain.EvConfirmed, TxHash: "0x9c1f", Value: "60000000", CumulativeConfirmed: "60000000", Remaining: "40000000", LastScanned: 19000210},
		{Kind: domain.EvReorged, TxHash: "0x9c1f", Value: "60000000", CumulativeConfirmed: "0", Remaining: "100000000", LastScanned: 19000212},
		{Kind: domain.EvHeartbeat, CumulativeConfirmed: "60000000", Remaining: "40000000", LastScanned: 19000240},
		{Kind: domain.EvComplete, CumulativeConfirmed: "100000000", TxHashes: []string{"0x9c1f", "0x3d2b"}, Address: addr, LastScanned: 19000260, Exit: &exit0},
		{Kind: domain.EvTimeout, CumulativeConfirmed: "60000000", Remaining: "40000000", LastScanned: 19000275,
			Resume: "daxie receive --account treasury/payroll --token USDC --amount 40 --from-block 19000276", Exit: &exit8},
	}
	lines := jsonSinkLines(evs...)
	if len(lines) != len(evs) {
		t.Fatalf("expected %d lines, got %d:\n%s", len(evs), len(lines), strings.Join(lines, "\n"))
	}
	for _, line := range lines {
		m := parseLine(t, line)
		v, ok := m["v"]
		if !ok {
			t.Errorf("line missing \"v\": %s", line)
			continue
		}
		if n, ok := v.(json.Number); !ok || n.String() != "1" {
			t.Errorf("line \"v\" must be the number 1, got %v (%T): %s", v, v, line)
		}
	}
}

// The listening line leads the stream and carries the address + the resolved
// target (mode/confirmations/amount) — the address-up-front guarantee.
func TestReceiveListeningCarriesAddressAndTarget(t *testing.T) {
	addr := common.HexToAddress("0x52ae00000000000000000000000000000000beef")
	lines := jsonSinkLines(domain.Event{
		Kind: domain.EvListening, Address: addr, Network: "mainnet", ChainID: 1,
		Asset:      &domain.EventAsset{Kind: "erc20", Contract: "0xa0b8", Alias: "USDC", Decimals: 6},
		TargetSpec: &domain.EventTarget{Mode: "cumulative", Amount: "100000000", Confirmations: 2},
		FromBlock:  19000200,
	})
	m := parseLine(t, lines[0])
	if got := mustStringField(t, m, "event"); got != "listening" {
		t.Errorf("event = %q, want listening", got)
	}
	if got := mustStringField(t, m, "address"); got != addr.Hex() {
		t.Errorf("address = %q, want %q", got, addr.Hex())
	}
	tgt, ok := m["target"].(map[string]any)
	if !ok {
		t.Fatalf("target must be an object: %s", lines[0])
	}
	if tgt["mode"] != "cumulative" {
		t.Errorf("target.mode = %v, want cumulative", tgt["mode"])
	}
	// confirmations is a NUMBER on the target object (§5.8).
	if n, ok := tgt["confirmations"].(json.Number); !ok || n.String() != "2" {
		t.Errorf("target.confirmations must be number 2, got %v (%T)", tgt["confirmations"], tgt["confirmations"])
	}
	// amount is a base-unit decimal STRING.
	if _, ok := tgt["amount"].(string); !ok {
		t.Errorf("target.amount must be a string, got %T", tgt["amount"])
	}
	asset, ok := m["asset"].(map[string]any)
	if !ok || asset["kind"] != "erc20" || asset["alias"] != "USDC" {
		t.Errorf("asset object wrong: %v", m["asset"])
	}
}

// An unbounded listen (Timeout nil) emits "timeout":null on the target — the §5.8
// invoice-wait default.
func TestReceiveListeningUnboundedTimeoutIsNull(t *testing.T) {
	lines := jsonSinkLines(domain.Event{
		Kind:       domain.EvListening,
		Address:    common.HexToAddress("0x1"),
		TargetSpec: &domain.EventTarget{Mode: "any", Confirmations: 1, Timeout: nil},
	})
	if !strings.Contains(lines[0], `"timeout":null`) {
		t.Errorf("unbounded listen must emit \"timeout\":null, got: %s", lines[0])
	}
}

// A balance-delta detection renders tx_hash:null (no bound tx) and attribution
// "balance-delta"; an ETH/erc20 detection renders token_id:null (not an NFT).
func TestReceiveDetectedNullFields(t *testing.T) {
	lines := jsonSinkLines(domain.Event{
		Kind: domain.EvDetected, TxHash: "", From: "0xbeef", Value: "5000",
		Block: 100, Attribution: "balance-delta",
		CumulativeDetected: "5000", CumulativeConfirmed: "0", Remaining: "1000", LastScanned: 100,
	})
	line := lines[0]
	if !strings.Contains(line, `"tx_hash":null`) {
		t.Errorf("balance-delta detection must render tx_hash:null, got: %s", line)
	}
	if !strings.Contains(line, `"token_id":null`) {
		t.Errorf("non-NFT detection must render token_id:null, got: %s", line)
	}
	m := parseLine(t, line)
	if got := mustStringField(t, m, "attribution"); got != "balance-delta" {
		t.Errorf("attribution = %q, want balance-delta", got)
	}
	// value/cumulative/remaining are decimal STRINGS.
	for _, k := range []string{"value", "cumulative_detected", "cumulative_confirmed", "remaining"} {
		if _, ok := m[k].(string); !ok {
			t.Errorf("field %q must be a decimal string, got %T", k, m[k])
		}
	}
}

// A confirming line carries confirmations + target as NUMBERS (§5.8) and the
// cumulative/remaining as strings.
func TestReceiveConfirmingNumbers(t *testing.T) {
	m := parseLine(t, jsonSinkLines(domain.Event{
		Kind: domain.EvConfirming, TxHash: "0x9c1f", Conf: 1, Target: 2,
		CumulativeConfirmed: "0", Remaining: "100000000", LastScanned: 19000209,
	})[0])
	if got := mustStringField(t, m, "event"); got != "confirming" {
		t.Errorf("event = %q, want confirming", got)
	}
	if n, ok := m["confirmations"].(json.Number); !ok || n.String() != "1" {
		t.Errorf("confirmations must be number 1, got %v (%T)", m["confirmations"], m["confirmations"])
	}
	if n, ok := m["target"].(json.Number); !ok || n.String() != "2" {
		t.Errorf("target must be number 2, got %v (%T)", m["target"], m["target"])
	}
}

// The terminal complete line carries exit:0 (a number), the cumulative, and the
// tx_hashes list — and is the success terminal.
func TestReceiveCompleteCarriesExit0(t *testing.T) {
	addr := common.HexToAddress("0x52ae")
	exit0 := 0
	m := parseLine(t, jsonSinkLines(domain.Event{
		Kind: domain.EvComplete, CumulativeConfirmed: "100000000",
		TxHashes: []string{"0x9c1f", "0x3d2b"}, Address: addr, LastScanned: 19000260, Exit: &exit0,
	})[0])
	if got := mustStringField(t, m, "event"); got != "complete" {
		t.Errorf("event = %q, want complete", got)
	}
	if n, ok := m["exit"].(json.Number); !ok || n.String() != "0" {
		t.Errorf("complete.exit must be number 0, got %v (%T)", m["exit"], m["exit"])
	}
	if got := mustStringField(t, m, "address"); got != addr.Hex() {
		t.Errorf("complete.address = %q, want %q", got, addr.Hex())
	}
	hashes, ok := m["tx_hashes"].([]any)
	if !ok || len(hashes) != 2 {
		t.Errorf("complete.tx_hashes must be a 2-element list, got %v", m["tx_hashes"])
	}
}

// The terminal timeout line carries exit:8, the remaining at full precision, and
// the executable resume string.
func TestReceiveTimeoutCarriesExit8AndResume(t *testing.T) {
	exit8 := 8
	resume := "daxie receive --account treasury/payroll --token USDC --amount 40 --from-block 19000276"
	m := parseLine(t, jsonSinkLines(domain.Event{
		Kind: domain.EvTimeout, CumulativeConfirmed: "60000000", Remaining: "40000000",
		LastScanned: 19000275, Resume: resume, Note: "verify balance before resuming", Exit: &exit8,
	})[0])
	if got := mustStringField(t, m, "event"); got != "timeout" {
		t.Errorf("event = %q, want timeout", got)
	}
	if n, ok := m["exit"].(json.Number); !ok || n.String() != "8" {
		t.Errorf("timeout.exit must be number 8, got %v (%T)", m["exit"], m["exit"])
	}
	if got := mustStringField(t, m, "resume"); got != resume {
		t.Errorf("timeout.resume = %q, want %q", got, resume)
	}
	if got := mustStringField(t, m, "remaining"); got != "40000000" {
		t.Errorf("timeout.remaining = %q, want 40000000 (full precision, never rounded)", got)
	}
	if got := mustStringField(t, m, "note"); got != "verify balance before resuming" {
		t.Errorf("timeout.note = %q", got)
	}
}

// A non-receive kind (a stray send/wait event) never leaks onto the receive
// stream — the single-object-on-stdout exception is for receive lines ONLY.
func TestReceiveStreamSkipsNonReceiveKinds(t *testing.T) {
	if lines := jsonSinkLines(domain.Event{Kind: domain.EvBroadcast, Hash: "0xabc"}); lines != nil {
		t.Errorf("send/wait kind must not appear on the receive stream, got: %v", lines)
	}
}

// A nil writer yields a nil (no-op) sink (the core's nil-tolerant Emit contract).
func TestReceiveStreamNilWriter(t *testing.T) {
	if ReceiveStream(nil, true) != nil {
		t.Error("ReceiveStream(nil, …) must return a nil sink")
	}
}

// Human mode leads with the address on the listening line and renders to the SAME
// (stdout) writer; the terminal complete line reports the exit code.
func TestReceiveHumanLeadsWithAddress(t *testing.T) {
	addr := common.HexToAddress("0x52ae00000000000000000000000000000000beef")
	exit0 := 0
	var buf bytes.Buffer
	sink := ReceiveStream(&buf, false)
	sink(domain.Event{Kind: domain.EvListening, Address: addr, Asset: &domain.EventAsset{Kind: "erc20", Alias: "USDC"}})
	sink(domain.Event{Kind: domain.EvComplete, CumulativeConfirmed: "100000000", Exit: &exit0})
	out := buf.String()
	if !strings.Contains(out, addr.Hex()) {
		t.Errorf("human listening line must contain the address, got:\n%s", out)
	}
	if !strings.Contains(out, "listening:") {
		t.Errorf("human listening line missing label, got:\n%s", out)
	}
	if !strings.Contains(out, "complete:") || !strings.Contains(out, "exit 0") {
		t.Errorf("human complete line missing/no exit, got:\n%s", out)
	}
}

// Human timeout renders the resume command so an operator can copy-paste it.
func TestReceiveHumanTimeoutShowsResume(t *testing.T) {
	exit8 := 8
	var buf bytes.Buffer
	sink := ReceiveStream(&buf, false)
	sink(domain.Event{Kind: domain.EvTimeout, CumulativeConfirmed: "0", Remaining: "5000000000000000000",
		Resume: "daxie receive --account a --amount 5 --from-block 100", Exit: &exit8})
	out := buf.String()
	if !strings.Contains(out, "timeout:") || !strings.Contains(out, "exit 8") {
		t.Errorf("human timeout line wrong: %s", out)
	}
	if !strings.Contains(out, "resume: daxie receive --account a --amount 5 --from-block 100") {
		t.Errorf("human timeout must show the resume command: %s", out)
	}
}

// An unset amount renders as the decimal string "0" (never the empty string) so
// every amount field is a well-formed decimal on the wire.
func TestReceiveAmountDefaultsToZeroString(t *testing.T) {
	m := parseLine(t, jsonSinkLines(domain.Event{
		Kind: domain.EvHeartbeat, LastScanned: 5,
	})[0])
	if got := mustStringField(t, m, "cumulative_confirmed"); got != "0" {
		t.Errorf("unset cumulative_confirmed must render \"0\", got %q", got)
	}
	if got := mustStringField(t, m, "remaining"); got != "0" {
		t.Errorf("unset remaining must render \"0\", got %q", got)
	}
}
