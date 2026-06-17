package policy

import (
	"math/big"
	"strings"

	"github.com/daxchain-io/daxie/internal/abi"
	"github.com/ethereum/go-ethereum/common"
)

// calldata.go is the §4.2 raw-calldata classifier — the twin of ClassifyTypedData
// (recognizers.go). It is the load-bearing M10 security piece: it keeps
// `daxie contract send` from bypassing the typed approval ceremonies by REWRITING
// recognized calldata into the SAME KindApprove/KindTransfer Check the typed path
// (`token approve`, `tx send`) emits — so Evaluate cannot tell the generic path from
// the typed one. An unrecognized selector returns ok=false and the caller applies the
// §4.3 stage-5b deny-by-default unknown-calldata gate (stageUnknownCalldata, below).
//
// Selector matching is DELEGATED to abi.ClassifySelector so the known-selector set is
// defined ONCE (in internal/abi) and shared with `contract decode`/display — the §4.2
// "one shared selector set" invariant. policy→abi is the sanctioned provider edge
// (arch_test). The match is on the 4-byte selector + a SUCCESSFUL decode of the arg
// shape, NEVER on a name string: the selector is a property of the SIGNED BYTES, and a
// user-supplied ABI may lie (§4.2 line 1644). Classification reads the calldata bytes,
// not the registry ABI claims, so a stored-ABI lie cannot change the classified spender.

// classifier is the stateless ABI selector recognizer the policy borrows from the abi
// provider. A single zero value serves every classification (it holds no state).
var classifier = abi.Codec{}

// ClassifyCalldata is the §4.2 raw-calldata classifier (the calldata twin of
// ClassifyTypedData). `to` is the resolved CONTRACT address; `data` is
// selector||abi-encoded-args; `value` is msg.value (nil == 0).
//
//	ok==true  → spend-equivalent Checks evaluated EXACTLY like the typed path
//	            (a Permit2 batch may yield >1; service signs only if ALL pass).
//	ok==false → unrecognized / short / undecodable: the caller applies the §4.3
//	            stage-5b contract_call.unknown gate (NOT harmless). No partial Check
//	            is returned (same fail-direction as ClassifyTypedData's shape rule).
//
// The emitted Check is BYTE-FOR-BYTE the shape `token approve` / `tx send` produce, so
// Evaluate cannot tell the generic path from the typed one (the M10 crux):
//   - RecApprove → Kind="approve" (→ KindApprove), Dest=Spender, Unlimited (re-derived
//     by abi from the ENCODED amount/sentinel, NOT a caller flag), Token=Asset=lower(to),
//     TokenAmt=Amount.
//   - RecTransfer → Kind="transfer" (→ KindTransfer), Dest=Recipient, Token=Asset=lower(to),
//     TokenAmt=Amount (a token value, NOT ETH — it never rides SpendWei).
//
// In BOTH cases `value` (msg.value) folds into SpendWei (§4.3 stage 2: every contract
// send, recognition-independent), so the per-tx/daily/gas ETH gates see the native debit.
// Network / Account / AccountNonce / MaxGasWei / MaxFeePerGas / Acked are filled by
// SERVICE (it owns the gas quote, the nonce, and the --unlimited --yes ceremony bit);
// ClassifyCalldata fills only the calldata-derived fields, so service overlays the rest
// exactly as it does today for a token op. This method does NOT call Evaluate — it
// returns the Checks; service runs Reserve/Evaluate on them (the same place authorize
// already does), so the gasless-vs-broadcast lifecycle stays service's call.
func (e *Engine) ClassifyCalldata(to common.Address, data []byte, value *big.Int) ([]Check, bool) {
	cls, ok := classifier.ClassifySelector(data)
	if !ok {
		// Unrecognized / short / undecodable: NO partial Check. The caller flips the
		// Check into the stage-5b unknown-calldata path.
		return nil, false
	}

	asset := lowerHex(to)
	chk := Check{
		Token:     asset,
		Asset:     asset,
		TokenAmt:  cls.Amount,
		Unlimited: cls.Unlimited,
		SpendWei:  value, // msg.value folds into SpendWei (recognition-independent)
	}

	switch cls.Kind {
	case abi.RecApprove:
		// approve / increaseAllowance / setApprovalForAll / on-chain permit / DAI-permit
		// / Permit2 — the spender allowlist + unlimited-ack ceremony path. Dest is the
		// DECODED spender (never the contract), so stage-3b gates the spender exactly as
		// `token approve --spender` does.
		chk.Kind = "approve"
		chk.KindEnum = KindApprove
		chk.Dest = cls.Spender
	case abi.RecTransfer:
		// transfer / transferFrom / safeTransferFrom (721+1155). Dest is the DECODED
		// recipient (the destination of value). The token value is NOT ETH-denominated
		// (no oracle in v1), so only msg.value rides SpendWei — TokenAmt is display-only.
		chk.Kind = "transfer"
		chk.KindEnum = KindTransfer
		chk.Dest = cls.Recipient
	default:
		// abi.ClassifySelector returned ok=true with an unmapped Kind — treat as
		// unrecognized (fail-closed: never emit an under-specified spend Check).
		return nil, false
	}

	return []Check{chk}, true
}

// SelectorHex renders the leading 4-byte selector of calldata as a 0x 10-char hex
// string ("0x" + 8 hex), or "0x" when fewer than 4 bytes are present. It is the
// stage-5b triple key + the §4.9 Data field; service sets Check.Selector from it so
// the policy layer (which owns the stage-5b semantics) defines the key rendering once.
func SelectorHex(data []byte) string {
	if len(data) < 4 {
		return "0x"
	}
	return "0x" + strings.ToLower(common.Bytes2Hex(data[:4]))
}
