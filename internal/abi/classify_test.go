package abi

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/erc"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// selFromSig re-derives a 4-byte selector ("0x…") from a canonical signature, so the
// pinned const cannot drift from the real keccak[:4] (the erc/ golden convention).
func selFromSig(sig string) string {
	return "0x" + hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4])
}

// TestSelectorsMatchSignatures re-derives every recognizer selector from its
// signature and asserts it equals the pinned const, so a typo cannot pass silently.
func TestSelectorsMatchSignatures(t *testing.T) {
	cases := []struct {
		sig string
		sel string
	}{
		{sigApprove, selApprove},
		{sigIncreaseAllowance, selIncreaseAllowance},
		{sigTransfer, selTransfer},
		{sigTransferFrom, selTransferFrom},
		{sigSetApprovalForAll, selSetApprovalForAll},
		{sigSafeTransferFrom1, selSafeTransferFrom1},
		{sigSafeTransferFrom2, selSafeTransferFrom2},
		{sigSafeTransferFrom3, selSafeTransferFrom3},
		{sigSafeBatchTransfer, selSafeBatchTransfer},
		// EIP-2612 / DAI permit selectors.
		{"permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", selPermitEIP2612},
		{"permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)", selPermitDAI},
	}
	for _, c := range cases {
		if got := selFromSig(c.sig); got != c.sel {
			t.Errorf("selector(%q) = %s, want pinned %s", c.sig, got, c.sel)
		}
	}
}

// TestSentinelsLockStepWithERC asserts the §4.2 unlimited sentinels in abi equal the
// SAME three values erc.MaxUint256/160/96 encode — the single match set the calldata
// builder (erc), the typed-data recognizer (policy), and the calldata recognizer
// (abi) must all agree on (§4.2 line 1644). A drift here would let one path treat an
// approval as unlimited while another treats it as bounded.
func TestSentinelsLockStepWithERC(t *testing.T) {
	if sentinelUint256.Cmp(erc.MaxUint256()) != 0 {
		t.Errorf("sentinelUint256 != erc.MaxUint256()")
	}
	if sentinelUint160.Cmp(erc.MaxUint160()) != 0 {
		t.Errorf("sentinelUint160 != erc.MaxUint160()")
	}
	if sentinelUint96.Cmp(erc.MaxUint96()) != 0 {
		t.Errorf("sentinelUint96 != erc.MaxUint96()")
	}
}

// helpers to build calldata for the classify table.
func selBytes(t *testing.T, selHex string) []byte {
	t.Helper()
	return mustHex(t, selHex)
}

func addrWord(a common.Address) []byte { return common.LeftPadBytes(a.Bytes(), 32) }
func uintWord(v *big.Int) []byte {
	if v == nil {
		return make([]byte, 32)
	}
	return common.LeftPadBytes(v.Bytes(), 32)
}
func boolWord(b bool) []byte {
	w := make([]byte, 32)
	if b {
		w[31] = 1
	}
	return w
}

var (
	attacker  = common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	recipient = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	owner     = common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	maxV      = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
)

// TestClassifyApprove — the security crux: approve(attacker, MAX) is recognized as
// RecApprove with Spender=attacker (arg0, never the contract) and Unlimited=true.
func TestClassifyApprove(t *testing.T) {
	var c Codec
	// approve(attacker, MAX)
	data := append(selBytes(t, selApprove), addrWord(attacker)...)
	data = append(data, uintWord(maxV)...)

	cls, ok := c.ClassifySelector(data)
	if !ok {
		t.Fatal("approve not recognized")
	}
	if cls.Kind != RecApprove {
		t.Errorf("kind = %v, want RecApprove", cls.Kind)
	}
	if cls.Spender != attacker {
		t.Errorf("spender = %s, want %s (the DECODED arg0, never the contract)", cls.Spender.Hex(), attacker.Hex())
	}
	if !cls.Unlimited {
		t.Error("Unlimited = false, want true (the MAX sentinel)")
	}
	if cls.Amount == nil || cls.Amount.Cmp(maxV) != 0 {
		t.Errorf("amount = %v, want MAX", cls.Amount)
	}

	// A BOUNDED approve is recognized but not unlimited.
	bounded := append(selBytes(t, selApprove), addrWord(attacker)...)
	bounded = append(bounded, uintWord(big.NewInt(1_000_000))...)
	cls2, ok := c.ClassifySelector(bounded)
	if !ok || cls2.Unlimited {
		t.Errorf("bounded approve: ok=%v unlimited=%v, want ok=true unlimited=false", ok, cls2.Unlimited)
	}
}

func TestClassifyApproveSentinels(t *testing.T) {
	var c Codec
	for name, s := range map[string]*big.Int{
		"uint256max": erc.MaxUint256(),
		"uint160max": erc.MaxUint160(),
		"uint96max":  erc.MaxUint96(),
	} {
		data := append(selBytes(t, selApprove), addrWord(attacker)...)
		data = append(data, uintWord(s)...)
		cls, ok := c.ClassifySelector(data)
		if !ok || !cls.Unlimited {
			t.Errorf("%s: ok=%v unlimited=%v, want both true", name, ok, cls.Unlimited)
		}
	}
}

func TestClassifyIncreaseAllowance(t *testing.T) {
	var c Codec
	data := append(selBytes(t, selIncreaseAllowance), addrWord(attacker)...)
	data = append(data, uintWord(maxV)...)
	cls, ok := c.ClassifySelector(data)
	if !ok || cls.Kind != RecApprove || cls.Spender != attacker {
		t.Fatalf("increaseAllowance classify = %+v ok=%v", cls, ok)
	}
	// A delta is never "unlimited" in the sentinel sense even at MAX (it widens, not sets).
	if cls.Unlimited {
		t.Error("increaseAllowance Unlimited = true, want false")
	}
}

func TestClassifyTransfer(t *testing.T) {
	var c Codec
	data := append(selBytes(t, selTransfer), addrWord(recipient)...)
	data = append(data, uintWord(big.NewInt(500))...)
	cls, ok := c.ClassifySelector(data)
	if !ok || cls.Kind != RecTransfer {
		t.Fatalf("transfer classify = %+v ok=%v", cls, ok)
	}
	if cls.Recipient != recipient {
		t.Errorf("recipient = %s, want %s (arg0)", cls.Recipient.Hex(), recipient.Hex())
	}
	if cls.Unlimited {
		t.Error("transfer is never Unlimited")
	}
}

func TestClassifyTransferFrom(t *testing.T) {
	var c Codec
	// transferFrom(owner, recipient, amount) — recipient is arg1.
	data := append(selBytes(t, selTransferFrom), addrWord(owner)...)
	data = append(data, addrWord(recipient)...)
	data = append(data, uintWord(big.NewInt(500))...)
	cls, ok := c.ClassifySelector(data)
	if !ok || cls.Kind != RecTransfer || cls.Recipient != recipient {
		t.Fatalf("transferFrom classify = %+v ok=%v, want recipient=arg1", cls, ok)
	}
}

func TestClassifySetApprovalForAll(t *testing.T) {
	var c Codec
	// setApprovalForAll(operator, true) → unbounded operator grant.
	dataTrue := append(selBytes(t, selSetApprovalForAll), addrWord(attacker)...)
	dataTrue = append(dataTrue, boolWord(true)...)
	cls, ok := c.ClassifySelector(dataTrue)
	if !ok || cls.Kind != RecApprove || cls.Spender != attacker || !cls.Unlimited {
		t.Fatalf("setApprovalForAll(true) = %+v ok=%v, want RecApprove spender=op unlimited=true", cls, ok)
	}
	// approved=false is recognized but not unlimited (a revoke).
	dataFalse := append(selBytes(t, selSetApprovalForAll), addrWord(attacker)...)
	dataFalse = append(dataFalse, boolWord(false)...)
	cls2, ok := c.ClassifySelector(dataFalse)
	if !ok || cls2.Unlimited {
		t.Errorf("setApprovalForAll(false) ok=%v unlimited=%v, want ok=true unlimited=false", ok, cls2.Unlimited)
	}
}

func TestClassifySafeTransferFrom(t *testing.T) {
	var c Codec
	for _, sel := range []string{selSafeTransferFrom1, selSafeTransferFrom3} {
		// from, to, ... — recipient is arg1. Extra trailing words are ignored.
		data := append(selBytes(t, sel), addrWord(owner)...)
		data = append(data, addrWord(recipient)...)
		data = append(data, uintWord(big.NewInt(42))...) // tokenId / id
		data = append(data, uintWord(big.NewInt(1))...)  // amount (1155) — harmless extra for 721
		data = append(data, make([]byte, 64)...)         // dynamic tail words (offset+len) — ignored
		cls, ok := c.ClassifySelector(data)
		if !ok || cls.Kind != RecTransfer || cls.Recipient != recipient {
			t.Errorf("safeTransferFrom %s = %+v ok=%v, want recipient=arg1", sel, cls, ok)
		}
	}
}

func TestClassifyPermitEIP2612(t *testing.T) {
	var c Codec
	// permit(owner, spender, value=MAX, deadline, v, r, s) → Spender=arg1, Unlimited.
	data := append(selBytes(t, selPermitEIP2612), addrWord(owner)...)
	data = append(data, addrWord(attacker)...) // spender = arg1
	data = append(data, uintWord(maxV)...)     // value = MAX
	data = append(data, uintWord(big.NewInt(9999999999))...)
	data = append(data, make([]byte, 32*3)...) // v,r,s words
	cls, ok := c.ClassifySelector(data)
	if !ok || cls.Kind != RecApprove || cls.Spender != attacker || !cls.Unlimited {
		t.Fatalf("EIP-2612 permit = %+v ok=%v, want RecApprove spender=arg1 unlimited", cls, ok)
	}

	// Unlimited also fires when deadline is the max sentinel (value bounded).
	data2 := append(selBytes(t, selPermitEIP2612), addrWord(owner)...)
	data2 = append(data2, addrWord(attacker)...)
	data2 = append(data2, uintWord(big.NewInt(100))...) // bounded value
	data2 = append(data2, uintWord(maxV)...)            // deadline = MAX
	data2 = append(data2, make([]byte, 32*3)...)
	cls2, ok := c.ClassifySelector(data2)
	if !ok || !cls2.Unlimited {
		t.Errorf("permit with max deadline: ok=%v unlimited=%v, want unlimited", ok, cls2.Unlimited)
	}
}

func TestClassifyPermitDAI(t *testing.T) {
	var c Codec
	// permit(holder, spender, nonce, expiry, allowed=true, v, r, s) → Spender=arg1, Unlimited.
	data := append(selBytes(t, selPermitDAI), addrWord(owner)...)
	data = append(data, addrWord(attacker)...) // spender = arg1
	data = append(data, uintWord(big.NewInt(0))...)
	data = append(data, uintWord(big.NewInt(0))...)
	data = append(data, boolWord(true)...) // allowed = arg4
	data = append(data, make([]byte, 32*3)...)
	cls, ok := c.ClassifySelector(data)
	if !ok || cls.Kind != RecApprove || cls.Spender != attacker || !cls.Unlimited {
		t.Fatalf("DAI permit = %+v ok=%v, want RecApprove spender=arg1 unlimited", cls, ok)
	}
}

func TestClassifyPermit2IsApprove(t *testing.T) {
	var c Codec
	for _, sel := range []string{selPermit2Allowance, selPermit2Transfer} {
		data := append(selBytes(t, sel), make([]byte, 32*4)...)
		cls, ok := c.ClassifySelector(data)
		if !ok || cls.Kind != RecApprove {
			t.Errorf("Permit2 %s = %+v ok=%v, want RecApprove (conservative spend gate)", sel, cls, ok)
		}
	}
}

// TestClassifyUnknownAndShort confirms the §4.2 fail-direction: an unknown selector,
// a short selector, and a truncated body all return ok=false with NO partial Check.
func TestClassifyUnknownAndShort(t *testing.T) {
	var c Codec

	// Unknown selector (a random 4 bytes + a full arg word).
	unknown := append(mustHex(t, "0xdeadbeef"), make([]byte, 32)...)
	if cls, ok := c.ClassifySelector(unknown); ok {
		t.Errorf("unknown selector recognized: %+v", cls)
	}

	// Short: fewer than 4 bytes.
	if _, ok := c.ClassifySelector([]byte{0x01, 0x02, 0x03}); ok {
		t.Error("short calldata recognized")
	}
	if _, ok := c.ClassifySelector(nil); ok {
		t.Error("nil calldata recognized")
	}

	// A KNOWN selector with a TRUNCATED body (missing the second arg word) must NOT
	// produce a partial extraction.
	truncated := append(selBytes(t, selApprove), addrWord(attacker)...) // only arg0, no amount
	if cls, ok := c.ClassifySelector(truncated); ok {
		t.Errorf("truncated approve recognized (partial extraction): %+v", cls)
	}
}

// TestClassifyDirtyAddressWord rejects an address word whose high 12 bytes are
// non-zero (a dirty / over-long value is not a valid ABI address — no partial decode).
func TestClassifyDirtyAddressWord(t *testing.T) {
	var c Codec
	dirty := selBytes(t, selApprove)
	word := make([]byte, 32)
	word[0] = 0xff // non-zero high byte
	dirty = append(dirty, word...)
	dirty = append(dirty, uintWord(big.NewInt(1))...)
	if cls, ok := c.ClassifySelector(dirty); ok {
		t.Errorf("dirty address word recognized: %+v", cls)
	}
}

// TestClassifyDirtyBoolWord rejects a bool word that is neither 0 nor 1.
func TestClassifyDirtyBoolWord(t *testing.T) {
	var c Codec
	data := append(selBytes(t, selSetApprovalForAll), addrWord(attacker)...)
	w := make([]byte, 32)
	w[31] = 2 // not a canonical ABI bool
	data = append(data, w...)
	if cls, ok := c.ClassifySelector(data); ok {
		t.Errorf("non-canonical bool recognized: %+v", cls)
	}
}
