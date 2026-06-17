package erc

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// The golden vectors below are the EXACT output of foundry's `cast` for the same
// args (cast calldata "transfer(address,uint256)" 0x7099… 1000000, etc.). The
// test compares the builder's bytes byte-for-byte against these literals, so the
// hand-packed encoder is validated against foundry — not merely round-tripped
// (§2.9: "transfer/approve/safeTransferFrom match cast/foundry output
// byte-for-byte").
//
// Regenerate (and re-paste) with:
//
//	cast calldata "transfer(address,uint256)" 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 1000000
//	cast calldata "approve(address,uint256)"  0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC 1000000
//	cast calldata "approve(address,uint256)"  0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC <2^256-1>
//	cast calldata "approve(address,uint256)"  0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC 0
//	cast calldata "safeTransferFrom(address,address,uint256)" 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 42
//	cast calldata "safeTransferFrom(address,address,uint256,uint256,bytes)" 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 42 5 0x

const (
	addrRecipient = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" // anvil acct 1
	addrSpender   = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC" // anvil acct 2
	addrFrom      = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" // anvil acct 0

	goldenTransfer1USDC = "0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c800000000000000000000000000000000000000000000000000000000000f4240"
	goldenApprove1USDC  = "0x095ea7b30000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc00000000000000000000000000000000000000000000000000000000000f4240"
	goldenApproveMax    = "0x095ea7b30000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	goldenApproveZero   = "0x095ea7b30000000000000000000000003c44cdddb6a900fa2b585dd299e03d12fa4293bc0000000000000000000000000000000000000000000000000000000000000000"
	goldenStf721ID42    = "0x42842e0e000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000002a"
	goldenStf1155       = "0xf242432a000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8000000000000000000000000000000000000000000000000000000000000002a000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000"
)

// mustHex parses a 0x… string into bytes, failing the test on a bad literal.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad golden hex %q: %v", s, err)
	}
	return b
}

// hexEq asserts got equals the golden 0x… literal byte-for-byte.
func hexEq(t *testing.T, name string, got []byte, goldenHex string) {
	t.Helper()
	want := mustHex(t, goldenHex)
	if !equalBytes(got, want) {
		t.Errorf("%s calldata mismatch vs cast/foundry\n got: 0x%s\nwant: 0x%s", name, hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestTransferCalldataGolden pins transfer(address,uint256) byte-for-byte.
func TestTransferCalldataGolden(t *testing.T) {
	to := common.HexToAddress(addrRecipient)
	got := Ops{}.TransferCalldata(to, big.NewInt(1_000_000)) // 1 USDC (6 decimals)
	hexEq(t, "transfer", got, goldenTransfer1USDC)

	// Selector is exactly 0xa9059cbb and total length is 4 + 2*32.
	if len(got) != 4+2*32 {
		t.Fatalf("transfer calldata length = %d, want %d", len(got), 4+2*32)
	}
	if gotSel := hex.EncodeToString(got[:4]); gotSel != "a9059cbb" {
		t.Errorf("transfer selector = 0x%s, want 0xa9059cbb", gotSel)
	}
}

// TestApproveCalldataGolden pins approve(address,uint256) for a finite amount,
// the unlimited sentinel, and the revoke (zero) encoding — the three the policy
// ceremony depends on.
func TestApproveCalldataGolden(t *testing.T) {
	sp := common.HexToAddress(addrSpender)

	hexEq(t, "approve(finite)", Ops{}.ApproveCalldata(sp, big.NewInt(1_000_000)), goldenApprove1USDC)
	hexEq(t, "approve(max)", Ops{}.ApproveCalldata(sp, MaxUint256()), goldenApproveMax)
	hexEq(t, "approve(0)=revoke", Ops{}.ApproveCalldata(sp, big.NewInt(0)), goldenApproveZero)

	// A nil amount must encode as the revoke (zero) word, never panic.
	hexEq(t, "approve(nil)=revoke", Ops{}.ApproveCalldata(sp, nil), goldenApproveZero)

	// The unlimited sentinel encodes as 32 0xff bytes (the ceremony's match value).
	maxCall := Ops{}.ApproveCalldata(sp, MaxUint256())
	for i, b := range maxCall[len(maxCall)-32:] {
		if b != 0xff {
			t.Fatalf("unlimited amount word byte %d = 0x%02x, want 0xff", i, b)
		}
	}
}

// TestMaxUint256 confirms the sentinel is exactly 2^256-1 and is returned as a
// fresh copy a caller cannot mutate into the package.
func TestMaxUint256(t *testing.T) {
	want := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	got := MaxUint256()
	if got.Cmp(want) != 0 {
		t.Fatalf("MaxUint256 = %s, want %s", got, want)
	}
	// Mutating the returned value must not affect a subsequent call.
	got.SetInt64(0)
	if MaxUint256().Cmp(want) != 0 {
		t.Fatal("MaxUint256 returned a shared/mutable value")
	}
}

// TestUnlimitedSentinels confirms the §4.2 sentinel getters are exact and fresh,
// and that IsUnlimitedAmount matches the SINGLE set the approve builder + the policy
// ceremony share (2^256-1, uint160 max, uint96 max) — and nothing else.
func TestUnlimitedSentinels(t *testing.T) {
	max256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	max160 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	max96 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 96), big.NewInt(1))

	for name, pair := range map[string][2]*big.Int{
		"MaxUint256": {MaxUint256(), max256},
		"MaxUint160": {MaxUint160(), max160},
		"MaxUint96":  {MaxUint96(), max96},
	} {
		if pair[0].Cmp(pair[1]) != 0 {
			t.Fatalf("%s = %s, want %s", name, pair[0], pair[1])
		}
		// Returned fresh: mutating must not poison a subsequent call.
		pair[0].SetInt64(0)
	}
	if MaxUint256().Cmp(max256) != 0 || MaxUint160().Cmp(max160) != 0 || MaxUint96().Cmp(max96) != 0 {
		t.Fatal("a sentinel getter returned a shared/mutable value")
	}

	// Every sentinel is unlimited.
	for _, s := range []*big.Int{max256, max160, max96} {
		if !IsUnlimitedAmount(new(big.Int).Set(s)) {
			t.Fatalf("IsUnlimitedAmount(%s) = false, want true", s)
		}
	}
	// Near-misses and the bounded/zero/nil cases are NOT unlimited.
	for _, s := range []*big.Int{
		nil,
		big.NewInt(0),
		big.NewInt(1_000_000),
		new(big.Int).Sub(max256, big.NewInt(1)), // 2^256-2
		new(big.Int).Add(max96, big.NewInt(1)),  // 2^96
	} {
		if IsUnlimitedAmount(s) {
			t.Fatalf("IsUnlimitedAmount(%v) = true, want false", s)
		}
	}
}

// TestSafeTransferFromCalldataGolden pins the ERC-721 (amount nil) and ERC-1155
// (amount non-nil, empty data) encodings byte-for-byte. M6 is the consumer;
// pinned now so M6 inherits a foundry-validated encoder.
func TestSafeTransferFromCalldataGolden(t *testing.T) {
	from := common.HexToAddress(addrFrom)
	to := common.HexToAddress(addrRecipient)

	// ERC-721: amount nil → selector 0x42842e0e, three static words.
	got721 := Ops{}.SafeTransferFromCalldata(from, to, big.NewInt(42), nil)
	hexEq(t, "safeTransferFrom721", got721, goldenStf721ID42)
	if gotSel := hex.EncodeToString(got721[:4]); gotSel != "42842e0e" {
		t.Errorf("stf721 selector = 0x%s, want 0x42842e0e", gotSel)
	}

	// ERC-1155: amount non-nil → selector 0xf242432a, four static words + an
	// empty dynamic bytes (offset 0xa0, length 0).
	got1155 := Ops{}.SafeTransferFromCalldata(from, to, big.NewInt(42), big.NewInt(5))
	hexEq(t, "safeTransferFrom1155", got1155, goldenStf1155)
	if gotSel := hex.EncodeToString(got1155[:4]); gotSel != "f242432a" {
		t.Errorf("stf1155 selector = 0x%s, want 0xf242432a", gotSel)
	}
}

// TestSelectorsMatchSignatures re-derives each selector from its signature string
// and asserts the well-known 4-byte value, so a typo in a signature constant
// cannot pass silently (cast sig "transfer(address,uint256)" == 0xa9059cbb …).
func TestSelectorsMatchSignatures(t *testing.T) {
	cases := []struct {
		sig  string
		want string
	}{
		{sigTransfer, "a9059cbb"},
		{sigApprove, "095ea7b3"},
		{sigBalanceOf, "70a08231"},
		{sigAllowance, "dd62ed3e"},
		{sigDecimals, "313ce567"},
		{sigSymbol, "95d89b41"},
		{sigName, "06fdde03"},
		{sigOwnerOf, "6352211e"},
		{sigSafeTransferFrom721, "42842e0e"},
		{sigSafeTransferFrom1155, "f242432a"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(selector(c.sig)); got != c.want {
			t.Errorf("selector(%q) = 0x%s, want 0x%s", c.sig, got, c.want)
		}
	}
}

// TestTransferTopic0 pins the Transfer event signature hash to its well-known
// value (cast keccak "Transfer(address,address,uint256)").
func TestTransferTopic0(t *testing.T) {
	const want = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	if got := transferTopic0.Hex(); got != want {
		t.Fatalf("transferTopic0 = %s, want %s", got, want)
	}
}

// ── ParseTransfers ──

// makeTransferLog builds a well-formed ERC-20 Transfer log for the decode test.
func makeTransferLog(token, from, to common.Address, value *big.Int) types.Log {
	return types.Log{
		Address: token,
		Topics: []common.Hash{
			transferTopic0,
			common.BytesToHash(from.Bytes()),
			common.BytesToHash(to.Bytes()),
		},
		Data: common.LeftPadBytes(value.Bytes(), 32),
	}
}

// TestParseTransfers decodes a well-formed Transfer log and confirms the
// tolerant skipping of non-matching / malformed / reorg-removed / ERC-721 logs.
func TestParseTransfers(t *testing.T) {
	token := common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48") // USDC
	from := common.HexToAddress(addrFrom)
	to := common.HexToAddress(addrRecipient)

	good := makeTransferLog(token, from, to, big.NewInt(1_000_000))

	// A log with a non-Transfer topic0 (e.g. Approval) — skipped.
	otherTopic := common.HexToHash("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925")
	notTransfer := types.Log{Address: token, Topics: []common.Hash{otherTopic, common.BytesToHash(from.Bytes()), common.BytesToHash(to.Bytes())}, Data: make([]byte, 32)}

	// A would-be Transfer but with short data — malformed, skipped.
	shortData := makeTransferLog(token, from, to, big.NewInt(5))
	shortData.Data = shortData.Data[:16]

	// An ERC-721 Transfer: same topic0, but 4 topics (tokenId indexed) + empty
	// data — correctly skipped (ERC-721 is M6).
	erc721 := types.Log{
		Address: token,
		Topics: []common.Hash{
			transferTopic0,
			common.BytesToHash(from.Bytes()),
			common.BytesToHash(to.Bytes()),
			common.BigToHash(big.NewInt(42)),
		},
	}

	// A reorg-removed otherwise-valid Transfer — skipped.
	removed := makeTransferLog(token, from, to, big.NewInt(9))
	removed.Removed = true

	logs := []types.Log{notTransfer, good, shortData, erc721, removed}

	out, err := Ops{}.ParseTransfers(logs)
	if err != nil {
		t.Fatalf("ParseTransfers error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("ParseTransfers returned %d transfers, want 1 (only the well-formed one)", len(out))
	}
	got := out[0]
	if got.Token != token {
		t.Errorf("Token = %s, want %s", got.Token, token)
	}
	if got.From != from {
		t.Errorf("From = %s, want %s", got.From, from)
	}
	if got.To != to {
		t.Errorf("To = %s, want %s", got.To, to)
	}
	if got.Value.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Errorf("Value = %s, want 1000000", got.Value)
	}
}

// TestParseTransfersEmpty confirms a no-match / empty input yields a nil slice and
// nil error (the documented contract the M8 receive engine relies on).
func TestParseTransfersEmpty(t *testing.T) {
	out, err := Ops{}.ParseTransfers(nil)
	if err != nil || out != nil {
		t.Fatalf("ParseTransfers(nil) = (%v, %v), want (nil, nil)", out, err)
	}
}
