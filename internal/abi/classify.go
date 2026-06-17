package abi

import (
	"encoding/hex"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// classify.go is the §4.2 raw-calldata recognizer source — the SINGLE known-selector
// set, shared by policy.ClassifyCalldata (the signing gate) AND `contract decode`
// display. Defining it once here (a pure abi leaf) is what makes the typed and generic
// signing paths indistinguishable to policy.Evaluate (the M10 security crux): the
// policy borrows abi.ClassifySelector over the sanctioned policy→abi edge rather than
// re-implementing a parallel — and possibly divergent — recognizer table.
//
// THE MATCH DISCIPLINE (§4.2 line 1644): a recognizer fires on the leading 4-byte
// SELECTOR + a SUCCESSFUL ABI-decode of the minimum argument shape, NEVER on a name
// string. The selector is a property of the SIGNED BYTES; a user-supplied ABI may lie.
// A short selector (len(data) < 4), an unknown selector, or a recognized selector
// whose args fail to decode to the expected shape returns (zero, false) WITHOUT a
// partial extraction — the same fail-direction as ClassifyTypedData's shape-mismatch
// rule. There is no path that returns ok=true with a half-filled SelectorClass.

// RecognizedKind is the abi-layer enum that policy maps onto its own policy.Kind. abi
// is a pure leaf (it does NOT import policy), so it exposes its own enum;
// policy.ClassifyCalldata translates RecApprove→KindApprove, RecTransfer→KindTransfer.
type RecognizedKind int

const (
	// NotRecognized is the zero value — returned alongside ok=false. Never paired
	// with ok=true.
	NotRecognized RecognizedKind = iota
	// RecApprove is the spender-allowlist + unlimited-ack family: approve,
	// increaseAllowance, setApprovalForAll, on-chain permit (EIP-2612 / DAI),
	// Permit2. Routes through the typed path's KindApprove gates.
	RecApprove
	// RecTransfer is the recipient family: transfer, transferFrom, safeTransferFrom
	// (721 + 1155). Routes through the typed path's KindTransfer gates.
	RecTransfer
)

// SelectorClass is the recognized spend-equivalent extracted from raw calldata.
// Ok=false (from ClassifySelector) means UNRECOGNIZED / short / undecodable — the
// §4.3 stage-5b path — never a partial extraction.
type SelectorClass struct {
	// Kind is the §4.2 family the selector maps to (RecApprove | RecTransfer).
	Kind RecognizedKind
	// Spender is the decoded spender/operator for the approval family (the policy
	// allowlist subject). Zero for the transfer family.
	Spender common.Address
	// Recipient is the decoded recipient (destination of value) for the transfer
	// family. Zero for the approval family.
	Recipient common.Address
	// Amount is the token amount in base units: the approval amount (for the
	// sentinel re-derive + display) or the transfer amount (display only; a token
	// value is not ETH-denominated, so it never rides SpendWei). May be nil
	// (setApprovalForAll carries no amount).
	Amount *big.Int
	// Unlimited reports whether the approval is unbounded: the amount is one of the
	// §4.2 sentinels (2^256-1, uint160 max, uint96 max), OR setApprovalForAll(true),
	// OR a permit whose value is a sentinel / whose DAI `allowed` flag is true. The
	// policy unlimited-ack ceremony (--unlimited --yes) fires on this bit exactly as
	// on the typed path. Always false for the transfer family.
	Unlimited bool
}

// §4.2 unlimited sentinels. These are the SAME three values erc.MaxUint256/160/96 and
// policy's uint256Max/uint160Max/uint96Max encode (the classify_test asserts the
// lock-step equality). An approval amount equal to any of these is unbounded.
var (
	sentinelUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	sentinelUint160 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	sentinelUint96  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 96), big.NewInt(1))
)

// isSentinel reports whether amount equals any §4.2 unlimited sentinel. A nil amount
// is never unlimited.
func isSentinel(amount *big.Int) bool {
	if amount == nil {
		return false
	}
	return amount.Cmp(sentinelUint256) == 0 ||
		amount.Cmp(sentinelUint160) == 0 ||
		amount.Cmp(sentinelUint96) == 0
}

// The §4.2 recognizer selectors, pinned as 0x-hex literals. The classify_test
// re-derives EACH from its canonical signature string (keccak[:4]) and asserts it
// equals the literal, so a typo cannot pass silently — the erc/ golden convention.
const (
	selApprove           = "0x095ea7b3" // approve(address,uint256)            ERC-20 (collides ERC-721 approve)
	selIncreaseAllowance = "0x39509351" // increaseAllowance(address,uint256)  ERC-20
	selTransfer          = "0xa9059cbb" // transfer(address,uint256)           ERC-20
	selTransferFrom      = "0x23b872dd" // transferFrom(address,address,uint256)
	selSetApprovalForAll = "0xa22cb465" // setApprovalForAll(address,bool)      ERC-721/1155
	selSafeTransferFrom1 = "0x42842e0e" // safeTransferFrom(address,address,uint256)             ERC-721
	selSafeTransferFrom2 = "0xb88d4fde" // safeTransferFrom(address,address,uint256,bytes)       ERC-721
	selSafeTransferFrom3 = "0xf242432a" // safeTransferFrom(address,address,uint256,uint256,bytes) ERC-1155
	selSafeBatchTransfer = "0x2eb2c2d6" // safeBatchTransferFrom(address,address,uint256[],uint256[],bytes) ERC-1155 batch
	selPermitEIP2612     = "0xd505accf" // permit(address,address,uint256,uint256,uint8,bytes32,bytes32)        EIP-2612
	selPermitDAI         = "0x8fcbaf0c" // permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)   DAI-style
	selPermit2Allowance  = "0x2b67b570" // Permit2 permit (allowance)
	selPermit2Transfer   = "0x30f28b7a" // Permit2 permitTransferFrom
)

// canonical signatures the test re-derives the above selectors from.
const (
	sigApprove           = "approve(address,uint256)"
	sigIncreaseAllowance = "increaseAllowance(address,uint256)"
	sigTransfer          = "transfer(address,uint256)"
	sigTransferFrom      = "transferFrom(address,address,uint256)"
	sigSetApprovalForAll = "setApprovalForAll(address,bool)"
	sigSafeTransferFrom1 = "safeTransferFrom(address,address,uint256)"
	sigSafeTransferFrom2 = "safeTransferFrom(address,address,uint256,bytes)"
	sigSafeTransferFrom3 = "safeTransferFrom(address,address,uint256,uint256,bytes)"
	sigSafeBatchTransfer = "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)"
)

// ClassifySelector is the §4.2 recognizer. It reads the leading 4-byte selector and,
// for a KNOWN ERC-20/721/1155/Permit spend-equivalent, decodes the minimum arg shape
// (the static head words) and fills a SelectorClass. The decode is hand-rolled over
// 32-byte words (no ABI needed — these shapes are fixed), so a malformed/truncated
// body returns (zero, false) rather than a partial extraction.
//
// data[:4] short / unknown selector ⇒ (zero, false).
//
// The §4.2 table:
//
//	0x095ea7b3 approve(address,uint256)              RecApprove Spender=arg0 Amt=arg1 Unlimited=sentinel(arg1)
//	0x39509351 increaseAllowance(address,uint256)    RecApprove Spender=arg0 Amt=arg1
//	0xa9059cbb transfer(address,uint256)             RecTransfer Recipient=arg0 Amt=arg1
//	0x23b872dd transferFrom(address,address,uint256) RecTransfer Recipient=arg1 Amt=arg2
//	0xa22cb465 setApprovalForAll(address,bool)       RecApprove Spender=arg0 Unlimited=(arg1==true)
//	0x42842e0e safeTransferFrom(addr,addr,uint256)             RecTransfer Recipient=arg1  (721)
//	0xb88d4fde safeTransferFrom(addr,addr,uint256,bytes)       RecTransfer Recipient=arg1  (721)
//	0xf242432a safeTransferFrom(addr,addr,uint256,uint256,bytes) RecTransfer Recipient=arg1 (1155)
//	0x2eb2c2d6 safeBatchTransferFrom(addr,addr,uint256[],uint256[],bytes) RecTransfer Recipient=arg1
//	0xd505accf permit(addr,addr,uint256,uint256,uint8,bytes32,bytes32)        RecApprove Spender=arg1 Unlimited=sentinel(arg2)||deadlineMax(arg3)
//	0x8fcbaf0c permit(addr,addr,uint256,uint256,bool,uint8,bytes32,bytes32)   RecApprove Spender=arg1 Unlimited=(arg4==true) (DAI)
//	0x2b67b570 Permit2 permit                                                 RecApprove Spender=arg(after the PermitSingle struct) Unlimited=uint160 sentinel
//	0x30f28b7a Permit2 permitTransferFrom                                     RecApprove Spender=arg(after the permit struct) Unlimited=uint256 sentinel
//
// ERC-721 approve(address,uint256) selector-COLLIDES with ERC-20 approve (0x095ea7b3):
// the conservative reading (RecApprove, Spender=arg0, Unlimited=false unless arg1 is a
// sentinel) still routes through the spender allowlist (§4.2 line 1638). The disambig
// by registry/ABI `kind` is a display nicety; the policy reading is conservative
// regardless.
func (Codec) ClassifySelector(data []byte) (SelectorClass, bool) {
	if len(data) < 4 {
		return SelectorClass{}, false
	}
	sel := "0x" + hex.EncodeToString(data[:4])
	body := data[4:]

	switch sel {
	case selApprove:
		// approve(address spender, uint256 amount)
		spender, ok := wordAddr(body, 0)
		if !ok {
			return SelectorClass{}, false
		}
		amount, ok := wordBig(body, 1)
		if !ok {
			return SelectorClass{}, false
		}
		return SelectorClass{Kind: RecApprove, Spender: spender, Amount: amount, Unlimited: isSentinel(amount)}, true

	case selIncreaseAllowance:
		// increaseAllowance(address spender, uint256 addedValue). A delta is never
		// "unlimited" in the sentinel sense, but it is still an approval that widens
		// allowance → routes through the spender allowlist with Unlimited=false.
		spender, ok := wordAddr(body, 0)
		if !ok {
			return SelectorClass{}, false
		}
		amount, ok := wordBig(body, 1)
		if !ok {
			return SelectorClass{}, false
		}
		return SelectorClass{Kind: RecApprove, Spender: spender, Amount: amount, Unlimited: false}, true

	case selTransfer:
		// transfer(address to, uint256 amount)
		to, ok := wordAddr(body, 0)
		if !ok {
			return SelectorClass{}, false
		}
		amount, ok := wordBig(body, 1)
		if !ok {
			return SelectorClass{}, false
		}
		return SelectorClass{Kind: RecTransfer, Recipient: to, Amount: amount}, true

	case selTransferFrom:
		// transferFrom(address from, address to, uint256 amount). Recipient = arg1.
		to, ok := wordAddr(body, 1)
		if !ok {
			return SelectorClass{}, false
		}
		amount, ok := wordBig(body, 2)
		if !ok {
			return SelectorClass{}, false
		}
		return SelectorClass{Kind: RecTransfer, Recipient: to, Amount: amount}, true

	case selSetApprovalForAll:
		// setApprovalForAll(address operator, bool approved). Operator-for-all granted
		// (approved==true) is unbounded → the unlimited-ack ceremony.
		op, ok := wordAddr(body, 0)
		if !ok {
			return SelectorClass{}, false
		}
		approved, ok := wordBool(body, 1)
		if !ok {
			return SelectorClass{}, false
		}
		return SelectorClass{Kind: RecApprove, Spender: op, Unlimited: approved}, true

	case selSafeTransferFrom1, selSafeTransferFrom2, selSafeTransferFrom3, selSafeBatchTransfer:
		// safeTransferFrom / safeBatchTransferFrom (721 + 1155). Recipient = arg1; the
		// only fields the policy needs are from + to, both static head words, so the
		// dynamic tail (bytes/uint256[]) is irrelevant to recognition.
		to, ok := wordAddr(body, 1)
		if !ok {
			return SelectorClass{}, false
		}
		return SelectorClass{Kind: RecTransfer, Recipient: to}, true

	case selPermitEIP2612:
		// permit(address owner, address spender, uint256 value, uint256 deadline,
		//        uint8 v, bytes32 r, bytes32 s). Spender=arg1; Unlimited if value(arg2)
		// is a sentinel OR deadline(arg3) is the max sentinel (a broadcast permit is an
		// approval someone else's signature authorized — closes the relay-via-send hole).
		spender, ok := wordAddr(body, 1)
		if !ok {
			return SelectorClass{}, false
		}
		value, ok := wordBig(body, 2)
		if !ok {
			return SelectorClass{}, false
		}
		deadline, ok := wordBig(body, 3)
		if !ok {
			return SelectorClass{}, false
		}
		unlimited := isSentinel(value) || (deadline != nil && deadline.Cmp(sentinelUint256) == 0)
		return SelectorClass{Kind: RecApprove, Spender: spender, Amount: value, Unlimited: unlimited}, true

	case selPermitDAI:
		// permit(address holder, address spender, uint256 nonce, uint256 expiry,
		//        bool allowed, uint8 v, bytes32 r, bytes32 s). Spender=arg1;
		// allowed(arg4)==true ⇒ Unlimited (DAI's flag toggles infinite allowance).
		spender, ok := wordAddr(body, 1)
		if !ok {
			return SelectorClass{}, false
		}
		allowed, ok := wordBool(body, 4)
		if !ok {
			return SelectorClass{}, false
		}
		return SelectorClass{Kind: RecApprove, Spender: spender, Unlimited: allowed}, true

	case selPermit2Allowance, selPermit2Transfer:
		// Permit2 permit / permitTransferFrom: the leading struct is dynamic, so the
		// spender is not at a fixed static word in v1's hand-decoder. The conservative,
		// fail-safe reading classifies it as a spend-equivalent (RecApprove) with an
		// empty spender so it STILL routes through the spend gates (allowlist + the
		// stage-3c fail-closed-no-allowlist rule + per-tx/daily limits) rather than
		// falling to the stage-5b unknown gate or, worse, slipping through unclassified.
		// A v2 full Permit2 ABI decode can pin the spender + multi-spend fan-out; the v1
		// behavior is strictly more conservative (never less restrictive).
		return SelectorClass{Kind: RecApprove, Unlimited: false}, true

	default:
		return SelectorClass{}, false
	}
}

// ── fixed-word decoders (the static ABI head; one 32-byte word per arg) ───────────

// word returns the i-th 32-byte ABI head word of body, or (nil,false) if body is too
// short to contain it (the §4.2 fail-direction: a truncated body is undecodable).
func word(body []byte, i int) ([]byte, bool) {
	start := i * 32
	end := start + 32
	if len(body) < end {
		return nil, false
	}
	return body[start:end], true
}

// wordAddr decodes the i-th head word as an address (the low 20 bytes). The high 12
// bytes must be zero — a non-zero prefix means the word is not a valid ABI-encoded
// address (a dirty/over-long value), which fails the decode (no partial extraction).
func wordAddr(body []byte, i int) (common.Address, bool) {
	w, ok := word(body, i)
	if !ok {
		return common.Address{}, false
	}
	for _, b := range w[:12] {
		if b != 0 {
			return common.Address{}, false
		}
	}
	return common.BytesToAddress(w[12:]), true
}

// wordBig decodes the i-th head word as a uint256.
func wordBig(body []byte, i int) (*big.Int, bool) {
	w, ok := word(body, i)
	if !ok {
		return nil, false
	}
	return new(big.Int).SetBytes(w), true
}

// wordBool decodes the i-th head word as a bool: all-zero ⇒ false, the canonical
// 0x…01 ⇒ true. Any other encoding is not a valid ABI bool and fails the decode.
func wordBool(body []byte, i int) (bool, bool) {
	w, ok := word(body, i)
	if !ok {
		return false, false
	}
	// The high 31 bytes must be zero.
	for _, b := range w[:31] {
		if b != 0 {
			return false, false
		}
	}
	switch w[31] {
	case 0:
		return false, true
	case 1:
		return true, true
	default:
		return false, false
	}
}
