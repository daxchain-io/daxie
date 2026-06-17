package abi

import (
	"bufio"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// mustHex parses a 0x… string into bytes, failing the test on a bad literal.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// codeOf extracts the canonical domain error code from err (or "" if none).
func codeOf(err error) string {
	var de *domain.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

// ── golden calldata (PackCall vs cast/foundry, byte-for-byte) ────────────────────

// TestPackCallGolden pins PackCall byte-for-byte against the cast-derived vectors in
// testdata/golden_calldata.txt (the §2.9 "validated against foundry, not merely
// round-tripped" gate). Each line is parsed via ParseSig + CoerceArgs + PackCall, so
// the WHOLE encode path — not just a hand-packed word — is proven against foundry.
func TestPackCallGolden(t *testing.T) {
	f, err := os.Open("testdata/golden_calldata.txt")
	if err != nil {
		t.Fatalf("open golden file: %v", err)
	}
	defer func() { _ = f.Close() }()

	var c Codec
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			t.Fatalf("malformed golden line %q", line)
		}
		sig := strings.TrimSpace(parts[0])
		argFields := strings.Fields(strings.TrimSpace(parts[1]))
		wantHex := strings.TrimSpace(parts[2])

		parsed, method, isEvent, err := c.ParseSig(sig)
		if err != nil {
			t.Fatalf("ParseSig(%q): %v", sig, err)
		}
		if isEvent {
			t.Fatalf("ParseSig(%q) classified a function as an event", sig)
		}
		coerced, _, err := c.CoerceArgs(parsed, method, argFields, nil)
		if err != nil {
			t.Fatalf("CoerceArgs(%q, %v): %v", sig, argFields, err)
		}
		got, err := c.PackCall(parsed, method, coerced)
		if err != nil {
			t.Fatalf("PackCall(%q): %v", sig, err)
		}
		want := mustHex(t, wantHex)
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("PackCall(%q) calldata mismatch vs cast\n got: 0x%s\nwant: %s", sig, hex.EncodeToString(got), wantHex)
		}
		n++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan golden file: %v", err)
	}
	if n == 0 {
		t.Fatal("no golden vectors were read")
	}
}

// TestPackCallStakeFromJSONABI proves the registry-stored-ABI source (ParseJSON)
// encodes stake(uint256) to the SAME bytes as the --sig source — the two ABI sources
// must agree byte-for-byte (no source-dependent encoding).
func TestPackCallStakeFromJSONABI(t *testing.T) {
	var c Codec
	abiJSON, err := os.ReadFile("testdata/staking.json")
	if err != nil {
		t.Fatalf("read staking.json: %v", err)
	}
	parsed, err := c.ParseJSON(abiJSON)
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	coerced, _, err := c.CoerceArgs(parsed, "stake", []string{"1000000000000000000"}, nil)
	if err != nil {
		t.Fatalf("CoerceArgs: %v", err)
	}
	got, err := c.PackCall(parsed, "stake", coerced)
	if err != nil {
		t.Fatalf("PackCall: %v", err)
	}
	const want = "0xa694fc3a0000000000000000000000000000000000000000000000000de0b6b3a7640000"
	if "0x"+hex.EncodeToString(got) != want {
		t.Errorf("stake calldata from JSON ABI = 0x%s, want %s", hex.EncodeToString(got), want)
	}
}

// ── ParseJSON ─────────────────────────────────────────────────────────────────────

func TestParseJSON(t *testing.T) {
	var c Codec
	abiJSON, err := os.ReadFile("testdata/staking.json")
	if err != nil {
		t.Fatalf("read staking.json: %v", err)
	}
	parsed, err := c.ParseJSON(abiJSON)
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	if _, ok := parsed.Methods["stake"]; !ok {
		t.Error("ParseJSON dropped the stake method")
	}
	if _, ok := parsed.Events["Staked"]; !ok {
		t.Error("ParseJSON dropped the Staked event")
	}
}

func TestParseJSONRejectsInvalid(t *testing.T) {
	var c Codec
	cases := []struct {
		name string
		json string
	}{
		{"empty", ""},
		{"whitespace", "   \n "},
		{"not-an-array", `{"type":"function"}`},
		{"garbage", `not json`},
		{"empty-array", `[]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.ParseJSON([]byte(tc.json))
			if err == nil {
				t.Fatalf("ParseJSON(%q) accepted an invalid ABI", tc.json)
			}
			if got := codeOf(err); got != "usage.bad_abi" {
				t.Errorf("ParseJSON(%q) code = %q, want usage.bad_abi", tc.json, got)
			}
		})
	}
}

// ── ParseSig (cast forms) ──────────────────────────────────────────────────────────

func TestParseSigForms(t *testing.T) {
	var c Codec
	cases := []struct {
		sig        string
		wantName   string
		wantEvent  bool
		wantInputs int
		wantOuts   int
	}{
		{"earned(address)", "earned", false, 1, 0},
		{"earned(address)(uint256)", "earned", false, 1, 1},
		{"latestRoundData()(uint80,int256,uint256,uint256,uint80)", "latestRoundData", false, 0, 5},
		{"transfer(address to,uint256 amount)", "transfer", false, 2, 0},
		{"Staked(address indexed user,uint256 amount)", "Staked", true, 2, 0},
		{"stake(uint256)", "stake", false, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.sig, func(t *testing.T) {
			parsed, name, isEvent, err := c.ParseSig(tc.sig)
			if err != nil {
				t.Fatalf("ParseSig(%q): %v", tc.sig, err)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
			if isEvent != tc.wantEvent {
				t.Errorf("isEvent = %v, want %v", isEvent, tc.wantEvent)
			}
			if tc.wantEvent {
				ev, ok := parsed.Events[name]
				if !ok {
					t.Fatalf("event %q not in parsed ABI", name)
				}
				if len(ev.Inputs) != tc.wantInputs {
					t.Errorf("event inputs = %d, want %d", len(ev.Inputs), tc.wantInputs)
				}
			} else {
				m, ok := parsed.Methods[name]
				if !ok {
					t.Fatalf("method %q not in parsed ABI", name)
				}
				if len(m.Inputs) != tc.wantInputs {
					t.Errorf("method inputs = %d, want %d", len(m.Inputs), tc.wantInputs)
				}
				if len(m.Outputs) != tc.wantOuts {
					t.Errorf("method outputs = %d, want %d", len(m.Outputs), tc.wantOuts)
				}
			}
		})
	}
}

func TestParseSigIndexedKeyword(t *testing.T) {
	var c Codec
	parsed, name, isEvent, err := c.ParseSig("Transfer(address indexed from, address indexed to, uint256 value)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	if !isEvent {
		t.Fatal("Transfer not classified as event")
	}
	ev := parsed.Events[name]
	indexed := 0
	for _, in := range ev.Inputs {
		if in.Indexed {
			indexed++
		}
	}
	if indexed != 2 {
		t.Errorf("indexed args = %d, want 2", indexed)
	}
	// topic0 must equal the canonical Transfer hash (matches erc/ + cast).
	const want = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	if got := ev.ID.Hex(); got != want {
		t.Errorf("Transfer topic0 = %s, want %s", got, want)
	}
}

func TestParseSigRejectsMalformed(t *testing.T) {
	var c Codec
	bad := []string{
		"",
		"noparens",
		"missingclose(uint256",
		"2bad(uint256)",
		"f(uint256))",
		"f(uint256)(uint256)trailing",
		"f(address indexed)(uint256)", // outputs cannot be indexed -> but indexed makes it an event w/ outputs
	}
	for _, sig := range bad {
		t.Run(sig, func(t *testing.T) {
			_, _, _, err := c.ParseSig(sig)
			if err == nil {
				t.Fatalf("ParseSig(%q) accepted a malformed signature", sig)
			}
			if got := codeOf(err); got != "usage.bad_sig" {
				t.Errorf("ParseSig(%q) code = %q, want usage.bad_sig", sig, got)
			}
		})
	}
}

// ── UnpackReturns ──────────────────────────────────────────────────────────────────

func TestUnpackReturns(t *testing.T) {
	var c Codec
	parsed, _, _, err := c.ParseSig("earned(address)(uint256)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	// Return value: a uint256 far larger than int64 (proves the decimal-string rule).
	big1 := new(big.Int).Lsh(big.NewInt(1), 200) // 2^200
	ret := common.LeftPadBytes(big1.Bytes(), 32)

	vals, err := c.UnpackReturns(parsed, "earned", ret)
	if err != nil {
		t.Fatalf("UnpackReturns: %v", err)
	}
	if len(vals) != 1 {
		t.Fatalf("returns = %d, want 1", len(vals))
	}
	if vals[0].Type != "uint256" {
		t.Errorf("type = %q, want uint256", vals[0].Type)
	}
	if vals[0].Value != big1.String() {
		t.Errorf("value = %q, want %q", vals[0].Value, big1.String())
	}
}

func TestUnpackReturnsRequiresOutputs(t *testing.T) {
	var c Codec
	parsed, _, _, err := c.ParseSig("stake(uint256)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	_, err = c.UnpackReturns(parsed, "stake", make([]byte, 32))
	if err == nil {
		t.Fatal("UnpackReturns accepted a method with no outputs")
	}
	if got := codeOf(err); got != "usage.no_outputs" {
		t.Errorf("code = %q, want usage.no_outputs", got)
	}
}

// ── UnpackCalldata (the `contract decode` path) ────────────────────────────────────

func TestUnpackCalldata(t *testing.T) {
	var c Codec
	parsed, method, _, err := c.ParseSig("stake(uint256)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	// Build calldata via PackCall, then decode it back.
	coerced, _, err := c.CoerceArgs(parsed, method, []string{"1000000000000000000"}, nil)
	if err != nil {
		t.Fatalf("CoerceArgs: %v", err)
	}
	data, err := c.PackCall(parsed, method, coerced)
	if err != nil {
		t.Fatalf("PackCall: %v", err)
	}

	gotMethod, sel, args, err := c.UnpackCalldata(parsed, data)
	if err != nil {
		t.Fatalf("UnpackCalldata: %v", err)
	}
	if gotMethod != "stake" {
		t.Errorf("method = %q, want stake", gotMethod)
	}
	if sel != "0xa694fc3a" {
		t.Errorf("selector = %q, want 0xa694fc3a", sel)
	}
	if len(args) != 1 || args[0].Value != "1000000000000000000" {
		t.Fatalf("args = %+v, want [1000000000000000000]", args)
	}
}

func TestUnpackCalldataErrors(t *testing.T) {
	var c Codec
	parsed, _, _, err := c.ParseSig("stake(uint256)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}

	// Short (< 4 bytes).
	if _, _, _, err := c.UnpackCalldata(parsed, []byte{0x01, 0x02}); codeOf(err) != "usage.bad_calldata" {
		t.Errorf("short calldata code = %q, want usage.bad_calldata", codeOf(err))
	}

	// Unknown selector (0xdeadbeef + 32-byte arg word).
	unknown := append(mustHex(t, "0xdeadbeef"), make([]byte, 32)...)
	if _, _, _, err := c.UnpackCalldata(parsed, unknown); codeOf(err) != "usage.unknown_selector" {
		t.Errorf("unknown selector code = %q, want usage.unknown_selector", codeOf(err))
	}
}

// ── events: PackEvent + UnpackLog round-trip ──────────────────────────────────────

func TestEventTopicAndLogRoundTrip(t *testing.T) {
	var c Codec
	parsed, event, isEvent, err := c.ParseSig("Staked(address indexed user, uint256 amount)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	if !isEvent {
		t.Fatal("Staked not classified as event")
	}

	user := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	amount := big.NewInt(1_000_000)

	// PackEvent: a filter on the indexed `user` arg.
	topics, topic0, err := c.PackEvent(parsed, event, map[string]any{"user": user})
	if err != nil {
		t.Fatalf("PackEvent: %v", err)
	}
	wantTopic0 := "0x9e71bc8eea02a63969f509818f2dafb9254532904319f9dbda79b67bd34a5f3d"
	if topic0.Hex() != wantTopic0 {
		t.Errorf("Staked topic0 = %s, want %s", topic0.Hex(), wantTopic0)
	}
	if len(topics) < 2 || len(topics[0]) != 1 || topics[0][0] != topic0 {
		t.Fatalf("topics[0] = %v, want the signature topic", topics)
	}
	if len(topics[1]) != 1 || topics[1][0] != common.BytesToHash(user.Bytes()) {
		t.Errorf("topics[1] = %v, want the user filter word", topics[1])
	}

	// UnpackLog: reconstruct the same event from its on-chain log shape.
	logTopics := []common.Hash{topic0, common.BytesToHash(user.Bytes())}
	logData := common.LeftPadBytes(amount.Bytes(), 32)
	args, err := c.UnpackLog(parsed, event, logTopics, logData)
	if err != nil {
		t.Fatalf("UnpackLog: %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("log args = %d, want 2", len(args))
	}
	// Merged in ABI order: user (indexed) then amount (non-indexed).
	if args[0].Name != "user" || args[0].Value != user.Hex() {
		t.Errorf("arg0 = %+v, want user=%s", args[0], user.Hex())
	}
	if args[1].Name != "amount" || args[1].Value != amount.String() {
		t.Errorf("arg1 = %+v, want amount=%s", args[1], amount.String())
	}
}

func TestPackEventRejectsNonIndexedFilter(t *testing.T) {
	var c Codec
	parsed, event, _, err := c.ParseSig("Staked(address indexed user, uint256 amount)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	// Filtering the non-indexed `amount` arg is a usage error.
	_, _, err = c.PackEvent(parsed, event, map[string]any{"amount": big.NewInt(5)})
	if err == nil {
		t.Fatal("PackEvent accepted a filter on a non-indexed arg")
	}
	if got := codeOf(err); got != "usage.bad_arg" {
		t.Errorf("code = %q, want usage.bad_arg", got)
	}
	// Filtering an arg that does not exist is also a usage error.
	_, _, err = c.PackEvent(parsed, event, map[string]any{"nope": big.NewInt(5)})
	if codeOf(err) != "usage.bad_arg" {
		t.Errorf("unknown-arg code = %q, want usage.bad_arg", codeOf(err))
	}
}

// TestPackCallUnknownMethod confirms a bad method name is usage.unknown_method.
func TestPackCallUnknownMethod(t *testing.T) {
	var c Codec
	parsed, _, _, err := c.ParseSig("stake(uint256)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	if _, err := c.PackCall(parsed, "nope", nil); codeOf(err) != "usage.unknown_method" {
		t.Errorf("code = %q, want usage.unknown_method", codeOf(err))
	}
}
