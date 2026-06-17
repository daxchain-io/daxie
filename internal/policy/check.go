package policy

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Check is the Evaluate/Reserve input — the fully-built tx the verdict sees
// (§5.1: recipient, native value, classified calldata, worst-case gas). The
// service kernel builds exactly one Check per signing op AFTER the gas engine has
// resolved the limit and fees (so MaxGasWei = gasLimit × maxFeePerGas is final)
// and hands it to Evaluate (dry-run) or Reserve (the durable pre-sign path).
//
// M3 (the always-allow stub) reads only Account/Dest/SpendWei/MaxGasWei — enough
// to write a faithful durable reservation so the §5.1 ordering and the §5.1
// reconciliation lifecycle are exercised now. The remaining fields are populated
// by the service kernel today and CONSUMED by M4 without any signature change:
//
//   - MaxFeePerGas — the §4.3 stage-8 gas-cap check (policy.max-gas-price).
//   - Kind         — the classified journal.Kind string, for the §4.3 stage-3c
//     fail-closed token rule / approval handling.
//   - Token        — the token contract (lowercase 0x) for the token allowlist.
//   - IsRBFDelta   — speedup/cancel: only the positive gas delta counts toward
//     the rolling-24h window (the value is NOT re-counted, §5.5).
//   - Acked        — the --unlimited --yes / acknowledgeUnlimited ceremony bit.
//
// No float anywhere (§2.5): every amount is a *big.Int in wei.
type Check struct {
	Account   common.Address // the signing account (the spend bucket key in M4)
	Dest      common.Address // the resolved recipient/spender (the allowlist subject in M4)
	SpendWei  *big.Int       // native value moved; nil == zero
	MaxGasWei *big.Int       // worst-case gasLimit × maxFeePerGas; nil == zero

	// ── fields the kernel fills today, M4 consumes (no signature change) ──
	MaxFeePerGas *big.Int // for the M4 gas-cap check; M3 ignores
	Kind         string   // journal.Kind string (the classified kind); M4 uses it
	Token        string   // token contract (lowercase 0x); "" for ETH; M4 uses it
	IsRBFDelta   bool     // speedup/cancel: only the positive gas delta counts (M4)
	Acked        bool     // the unlimited-approval acknowledgement (M4)
}

// spendWei returns the native value as a non-nil big.Int (0 if unset).
func (c Check) spendWei() *big.Int {
	if c.SpendWei == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(c.SpendWei)
}

// maxGasWei returns the worst-case gas as a non-nil big.Int (0 if unset).
func (c Check) maxGasWei() *big.Int {
	if c.MaxGasWei == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(c.MaxGasWei)
}

// Decision is the policy verdict (§4.9). M3 always returns {Allowed:true}. When
// M4 denies, Code is the canonical policy.denied.* string (e.g.
// "policy.denied.day_limit", "policy.denied.gas_cap") and Reason is the human
// one-liner; the service kernel renders a denial as a domain.Error whose Code is
// Decision.Code (exit 3) — the numeric mapping already exists in domain (§5.7).
type Decision struct {
	Allowed bool
	Code    string // canonical policy.denied.* string; "" when allowed
	Reason  string // human reason; "" when allowed
}

// TypedDataClass is the §4.2 classification result for an EIP-712 typed message
// (sign typed). M3 ships a stub that recognizes nothing (isSpend=false), so the
// typed-data gate is the M4 / M9 concern; the type is declared now so the service
// signature that threads classification through authorize is stable.
type TypedDataClass struct {
	IsSpend bool   // true once M4's Permit/Permit2/DAI recognizers match
	Kind    string // the spend-equivalent kind when IsSpend (e.g. "approve")
	Spender string // the recognized spender (lowercase 0x) when IsSpend
}

// ClassifyTypedData is the §4.2 typed-data recognizer seam. M3 STUB: recognizes
// nothing and returns {IsSpend:false}. M4/M9 fill in the Permit / Permit2 / DAI
// permit recognizers here WITHOUT changing the signature — the service kernel's
// single classification step (one step, two sources: typed data + raw calldata,
// §4.3 stage 2) already calls through this shape.
func (e *Engine) ClassifyTypedData(primaryType string, domain map[string]any, message map[string]any) (TypedDataClass, error) {
	_ = e
	_ = primaryType
	_ = domain
	_ = message
	return TypedDataClass{IsSpend: false}, nil
}
