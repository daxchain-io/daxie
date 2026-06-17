package abi

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// packVia is a helper: ParseSig(sig) → CoerceArgs(args) → PackCall, returning the
// 0x calldata, so a literal round-trips through the WHOLE encode path.
func packVia(t *testing.T, sig string, args ...string) string {
	t.Helper()
	var c Codec
	parsed, method, _, err := c.ParseSig(sig)
	if err != nil {
		t.Fatalf("ParseSig(%q): %v", sig, err)
	}
	coerced, _, err := c.CoerceArgs(parsed, method, args, nil)
	if err != nil {
		t.Fatalf("CoerceArgs(%q, %v): %v", sig, args, err)
	}
	data, err := c.PackCall(parsed, method, coerced)
	if err != nil {
		t.Fatalf("PackCall(%q): %v", sig, err)
	}
	return "0x" + hex.EncodeToString(data)
}

// decodeVia is the inverse: decode calldata back to labeled values.
func decodeVia(t *testing.T, sig, calldata string) []DecodedValue {
	t.Helper()
	var c Codec
	parsed, _, _, err := c.ParseSig(sig)
	if err != nil {
		t.Fatalf("ParseSig(%q): %v", sig, err)
	}
	_, _, args, err := c.UnpackCalldata(parsed, mustHex(t, calldata))
	if err != nil {
		t.Fatalf("UnpackCalldata(%q): %v", sig, err)
	}
	return args
}

// ── scalar coercion ─────────────────────────────────────────────────────────────

func TestCoerceScalars(t *testing.T) {
	// bool
	if got := packVia(t, "setPaused(bool)", "true"); !strings.HasSuffix(got, strings.Repeat("0", 63)+"1") {
		t.Errorf("bool true encoded wrong: %s", got)
	}
	// bytes32
	b32 := "0x" + strings.Repeat("ab", 32)
	got := packVia(t, "setRoot(bytes32)", b32)
	if !strings.HasSuffix(got, strings.Repeat("ab", 32)) {
		t.Errorf("bytes32 encoded wrong: %s", got)
	}
	// dynamic bytes "0x" (empty) — offset 0x20 + length 0.
	gotEmpty := packVia(t, "setData(bytes)", "0x")
	wantEmpty := "0x" + // selector +
		"" // checked below via suffix
	_ = wantEmpty
	if !strings.HasSuffix(gotEmpty, strings.Repeat("0", 64)) { // length word = 0
		t.Errorf("empty bytes encoded wrong: %s", gotEmpty)
	}
	// string verbatim
	gotStr := packVia(t, "setName(string)", "hi")
	if !strings.Contains(gotStr, hex.EncodeToString([]byte("hi"))) {
		t.Errorf("string not encoded verbatim: %s", gotStr)
	}
}

// TestCoerceLargeUint proves a uint256 LARGER than int64 round-trips (the ergonomic
// the plan calls out: large-uint decimal strings, no precision loss).
func TestCoerceLargeUint(t *testing.T) {
	// 2^200 — far beyond int64.
	big1 := new(big.Int).Lsh(big.NewInt(1), 200)
	got := packVia(t, "stake(uint256)", big1.String())
	want := "0x" + "a694fc3a" + hex.EncodeToString(common.LeftPadBytes(big1.Bytes(), 32))
	if got != want {
		t.Errorf("large uint256\n got: %s\nwant: %s", got, want)
	}
	// And via 0x-hex input form.
	gotHex := packVia(t, "stake(uint256)", "0x"+big1.Text(16))
	if gotHex != want {
		t.Errorf("large uint256 via hex\n got: %s\nwant: %s", gotHex, want)
	}

	// The unlimited sentinel (2^256-1) encodes as 32 0xff bytes.
	maxV := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	gotMax := packVia(t, "approve(address,uint256)", "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC", maxV.String())
	if !strings.HasSuffix(gotMax, strings.Repeat("ff", 32)) {
		t.Errorf("max uint256 not all-ff: %s", gotMax)
	}
}

// TestCoerceIntRange rejects out-of-range and malformed integers.
func TestCoerceIntRange(t *testing.T) {
	var c Codec
	cases := []struct {
		sig string
		arg string
	}{
		{"f(uint8)", "256"},   // > uint8 max
		{"f(uint8)", "-1"},    // negative for unsigned
		{"f(uint256)", "abc"}, // not an integer
		{"f(int8)", "128"},    // > int8 max
		{"f(int8)", "-129"},   // < int8 min
	}
	for _, tc := range cases {
		t.Run(tc.sig+"/"+tc.arg, func(t *testing.T) {
			parsed, method, _, err := c.ParseSig(tc.sig)
			if err != nil {
				t.Fatalf("ParseSig: %v", err)
			}
			_, _, err = c.CoerceArgs(parsed, method, []string{tc.arg}, nil)
			if err == nil {
				t.Fatalf("CoerceArgs accepted out-of-range %q for %s", tc.arg, tc.sig)
			}
			if got := codeOf(err); got != "usage.bad_arg" {
				t.Errorf("code = %q, want usage.bad_arg", got)
			}
		})
	}
}

func TestCoerceFixedBytesLength(t *testing.T) {
	var c Codec
	parsed, method, _, err := c.ParseSig("setRoot(bytes32)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	// 31 bytes is wrong length.
	_, _, err = c.CoerceArgs(parsed, method, []string{"0x" + strings.Repeat("ab", 31)}, nil)
	if codeOf(err) != "usage.bad_arg" {
		t.Errorf("short bytes32 code = %q, want usage.bad_arg", codeOf(err))
	}
}

// ── array literals ──────────────────────────────────────────────────────────────

func TestCoerceArrayLiteral(t *testing.T) {
	// address[] with two elements — the bracketed comma-separated address list the
	// plan explicitly calls out.
	a1 := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	a2 := "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
	got := packVia(t, "batch(address[])", "["+a1+","+a2+"]")

	// Decode it back and assert the two addresses survive.
	args := decodeVia(t, "batch(address[])", got)
	if len(args) != 1 {
		t.Fatalf("decoded args = %d, want 1", len(args))
	}
	val := strings.ToLower(args[0].Value)
	if !strings.Contains(val, strings.ToLower(a1[2:])) || !strings.Contains(val, strings.ToLower(a2[2:])) {
		t.Errorf("address[] round-trip lost an element: %s", args[0].Value)
	}
}

func TestCoerceUintArray(t *testing.T) {
	got := packVia(t, "amounts(uint256[])", "[1,2,3]")
	args := decodeVia(t, "amounts(uint256[])", got)
	if len(args) != 1 {
		t.Fatalf("decoded args = %d, want 1", len(args))
	}
	if args[0].Value != "[\"1\",\"2\",\"3\"]" {
		t.Errorf("uint256[] decoded = %q, want [\"1\",\"2\",\"3\"]", args[0].Value)
	}
}

func TestCoerceEmptyArray(t *testing.T) {
	got := packVia(t, "amounts(uint256[])", "[]")
	// An empty dynamic array: offset word (0x20) + length 0.
	if !strings.HasSuffix(got, strings.Repeat("0", 64)) {
		t.Errorf("empty array length word not zero: %s", got)
	}
	args := decodeVia(t, "amounts(uint256[])", got)
	if len(args) != 1 || args[0].Value != "[]" {
		t.Errorf("empty array decoded = %+v, want []", args)
	}
}

func TestCoerceFixedArrayWrongLen(t *testing.T) {
	var c Codec
	parsed, method, _, err := c.ParseSig("pair(uint256[2])")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	_, _, err = c.CoerceArgs(parsed, method, []string{"[1,2,3]"}, nil)
	if codeOf(err) != "usage.bad_arg" {
		t.Errorf("fixed-array wrong-len code = %q, want usage.bad_arg", codeOf(err))
	}
}

// ── tuple literals + nesting ──────────────────────────────────────────────────────

func TestCoerceTupleLiteral(t *testing.T) {
	// A tuple (address,uint256).
	addr := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	got := packVia(t, "submit((address,uint256))", "("+addr+",42)")
	args := decodeVia(t, "submit((address,uint256))", got)
	if len(args) != 1 {
		t.Fatalf("decoded args = %d, want 1", len(args))
	}
	// The tuple decodes to a JSON array [address, "42"].
	if !strings.Contains(strings.ToLower(args[0].Value), strings.ToLower(addr[2:])) {
		t.Errorf("tuple lost the address: %s", args[0].Value)
	}
	if !strings.Contains(args[0].Value, "\"42\"") {
		t.Errorf("tuple lost the amount: %s", args[0].Value)
	}
}

func TestCoerceNestedArray(t *testing.T) {
	// Nesting: uint256[][] = [[1,2],[3]].
	got := packVia(t, "grid(uint256[][])", "[[1,2],[3]]")
	args := decodeVia(t, "grid(uint256[][])", got)
	if len(args) != 1 {
		t.Fatalf("decoded args = %d, want 1", len(args))
	}
	want := `[["1","2"],["3"]]`
	if args[0].Value != want {
		t.Errorf("nested array decoded = %q, want %q", args[0].Value, want)
	}
}

func TestCoerceQuotedElement(t *testing.T) {
	// A string array element that itself contains a comma must be double-quoted so
	// the splitter does not treat the comma as a separator.
	got := packVia(t, "tags(string[])", `["a,b","c"]`)
	args := decodeVia(t, "tags(string[])", got)
	if len(args) != 1 {
		t.Fatalf("decoded args = %d, want 1", len(args))
	}
	want := `["a,b","c"]`
	if args[0].Value != want {
		t.Errorf("quoted element round-trip = %q, want %q", args[0].Value, want)
	}
}

func TestCoerceQuotedEscape(t *testing.T) {
	// \" and \\ escapes inside a quoted element.
	var c Codec
	parsed, method, _, err := c.ParseSig("tags(string[])")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	// Element value: a"b\c  (an embedded quote and backslash).
	coerced, _, err := c.CoerceArgs(parsed, method, []string{`["a\"b\\c"]`}, nil)
	if err != nil {
		t.Fatalf("CoerceArgs: %v", err)
	}
	got := coerced[0].([]string)
	if len(got) != 1 || got[0] != `a"b\c` {
		t.Errorf("escape decode = %#v, want [a\"b\\c]", got)
	}
}

// ── arg count ─────────────────────────────────────────────────────────────────────

func TestCoerceArgCountMismatch(t *testing.T) {
	var c Codec
	parsed, method, _, err := c.ParseSig("transfer(address,uint256)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	_, _, err = c.CoerceArgs(parsed, method, []string{"0x0000000000000000000000000000000000000001"}, nil)
	if codeOf(err) != "usage.bad_arg" {
		t.Errorf("arg-count code = %q, want usage.bad_arg", codeOf(err))
	}
}

// ── address resolver + provenance ─────────────────────────────────────────────────

func TestCoerceAddressResolver(t *testing.T) {
	var c Codec
	parsed, method, _, err := c.ParseSig("transfer(address,uint256)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	resolved := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	resolver := func(s string) (common.Address, AddrProvenance, error) {
		return resolved, AddrProvenance{Input: s, Addr: resolved, Via: "ens", ENSName: "alice.eth"}, nil
	}
	coerced, prov, err := c.CoerceArgs(parsed, method, []string{"alice.eth", "100"}, resolver)
	if err != nil {
		t.Fatalf("CoerceArgs: %v", err)
	}
	if coerced[0].(common.Address) != resolved {
		t.Errorf("resolved address = %v, want %v", coerced[0], resolved)
	}
	// The address arg (index 0) carries ENS provenance; the uint arg (index 1) does not.
	if prov[0].Via != "ens" || prov[0].ENSName != "alice.eth" || prov[0].Input != "alice.eth" {
		t.Errorf("prov[0] = %+v, want ens/alice.eth", prov[0])
	}
	if prov[1] != (AddrProvenance{}) {
		t.Errorf("prov[1] = %+v, want empty for a non-address arg", prov[1])
	}
}

func TestCoerceAddressLiteralPure(t *testing.T) {
	// Without a resolver, an address arg accepts a raw 0x literal only.
	var c Codec
	parsed, method, _, err := c.ParseSig("transfer(address,uint256)")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	addr := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	coerced, prov, err := c.CoerceArgs(parsed, method, []string{addr, "1"}, nil)
	if err != nil {
		t.Fatalf("CoerceArgs: %v", err)
	}
	if coerced[0].(common.Address) != common.HexToAddress(addr) {
		t.Errorf("literal address mismatch")
	}
	if prov[0].Via != "literal" {
		t.Errorf("prov[0].Via = %q, want literal", prov[0].Via)
	}

	// A non-0x value with no resolver is a usage error.
	_, _, err = c.CoerceArgs(parsed, method, []string{"alice.eth", "1"}, nil)
	if codeOf(err) != "usage.bad_arg" {
		t.Errorf("non-0x without resolver code = %q, want usage.bad_arg", codeOf(err))
	}
}

// ── ParseLiteral direct ─────────────────────────────────────────────────────────────

func TestParseLiteralDirect(t *testing.T) {
	var c Codec
	// Build a uint256[] type to parse "[1,2]" against.
	parsed, _, _, err := c.ParseSig("f(uint256[])")
	if err != nil {
		t.Fatalf("ParseSig: %v", err)
	}
	elemType := parsed.Methods["f"].Inputs[0].Type
	v, err := c.ParseLiteral(elemType, "[1,2]")
	if err != nil {
		t.Fatalf("ParseLiteral: %v", err)
	}
	arr, ok := v.([]*big.Int)
	if !ok {
		t.Fatalf("ParseLiteral returned %T, want []*big.Int", v)
	}
	if len(arr) != 2 || arr[0].Int64() != 1 || arr[1].Int64() != 2 {
		t.Errorf("ParseLiteral([1,2]) = %v", arr)
	}
}
