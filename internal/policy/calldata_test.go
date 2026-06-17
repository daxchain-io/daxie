package policy

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// calldata_test.go pins the §4.2 raw-calldata classifier (ClassifyCalldata) — the M10
// crux. The invariant under test: a `contract send` carrying recognized spend-equivalent
// calldata is REWRITTEN into the SAME Check the typed path emits (Dest = decoded
// spender/recipient, never the contract; Unlimited re-derived from the encoded sentinel;
// Token/Asset = the contract), so the IDENTICAL spender allowlist + --unlimited --yes
// ceremony + fail-closed gates fire. An unrecognized selector returns ok=false and falls
// to the stage-5b deny-by-default gate (stageUnknownCalldata).
//
// Calldata is hand-built here (selector || 32-byte words) so the test exercises the abi
// provider's ClassifySelector against the REAL signed bytes, never a mock — the
// typed/generic-paths-indistinguishable property is proven on the wire shape.

var (
	tokenC   = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48") // an ERC-20
	spenderA = common.HexToAddress("0x1111111111111111111111111111111111111111") // the "attacker" spender
	recipB   = common.HexToAddress("0x2222222222222222222222222222222222222222")
)

// maxUint256 / maxUint160 / maxUint96 are the §4.2 unlimited sentinels (the test re-derives
// them rather than borrowing the engine's so a drift in the engine constants is caught).
func maxUint256() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
}

// word left-pads b into a 32-byte ABI word.
func word(b []byte) []byte {
	w := make([]byte, 32)
	copy(w[32-len(b):], b)
	return w
}

// addrWord is the 32-byte ABI word for an address (right-aligned).
func addrWord(a common.Address) []byte { return word(a.Bytes()) }

// uintWord is the 32-byte ABI word for a uint.
func uintWord(v *big.Int) []byte { return word(v.Bytes()) }

// boolWord is the 32-byte ABI word for a bool.
func boolWord(b bool) []byte {
	w := make([]byte, 32)
	if b {
		w[31] = 1
	}
	return w
}

// approveCalldata builds approve(address,uint256) = 0x095ea7b3 || spender || amount.
func approveCalldata(spender common.Address, amount *big.Int) []byte {
	out := []byte{0x09, 0x5e, 0xa7, 0xb3}
	out = append(out, addrWord(spender)...)
	out = append(out, uintWord(amount)...)
	return out
}

// transferCalldata builds transfer(address,uint256) = 0xa9059cbb || to || amount.
func transferCalldata(to common.Address, amount *big.Int) []byte {
	out := []byte{0xa9, 0x05, 0x9c, 0xbb}
	out = append(out, addrWord(to)...)
	out = append(out, uintWord(amount)...)
	return out
}

// setApprovalForAllCalldata builds setApprovalForAll(address,bool) = 0xa22cb465.
func setApprovalForAllCalldata(operator common.Address, approved bool) []byte {
	out := []byte{0xa2, 0x2c, 0xb4, 0x65}
	out = append(out, addrWord(operator)...)
	out = append(out, boolWord(approved)...)
	return out
}

// TestClassifyCalldataApproveMaxRoutesToKindApprove is THE security crux: a contract send
// to an ERC-20 carrying approve(attacker, MAX) must be classified KindApprove with
// Dest=attacker (the decoded spender, NOT the contract) and Unlimited=true — the same
// Check `token approve --spender attacker --unlimited` produces.
func TestClassifyCalldataApproveMaxRoutesToKindApprove(t *testing.T) {
	e := &Engine{clock: fixedClock()}
	data := approveCalldata(spenderA, maxUint256())

	checks, ok := e.ClassifyCalldata(tokenC, data, nil)
	if !ok {
		t.Fatal("approve(spender,MAX) must be RECOGNIZED (ok=true), not routed to stage-5b")
	}
	if len(checks) != 1 {
		t.Fatalf("expected 1 Check, got %d", len(checks))
	}
	c := checks[0]
	if c.KindEnum != KindApprove {
		t.Fatalf("KindEnum = %v, want KindApprove", c.KindEnum)
	}
	if c.effectiveKind() != KindApprove {
		t.Fatalf("effectiveKind = %v, want KindApprove (the Kind string must map too)", c.effectiveKind())
	}
	if c.Dest != spenderA {
		t.Fatalf("Dest = %s, want the decoded spender %s (NEVER the contract %s)", c.Dest.Hex(), spenderA.Hex(), tokenC.Hex())
	}
	if !c.Unlimited {
		t.Fatal("approve(spender, 2^256-1) must set Unlimited=true (the sentinel re-derive)")
	}
	if c.Token != lowerHex(tokenC) || c.Asset != lowerHex(tokenC) {
		t.Fatalf("Token/Asset = %q/%q, want the contract %q (the underlying token for the per-token rule)", c.Token, c.Asset, lowerHex(tokenC))
	}
	if c.TokenAmt == nil || c.TokenAmt.Cmp(maxUint256()) != 0 {
		t.Fatalf("TokenAmt = %v, want the encoded MAX", c.TokenAmt)
	}
}

// TestClassifyCalldataApproveBoundedNotUnlimited confirms a bounded approve is recognized
// but NOT flagged unlimited (the ceremony does not fire for a finite allowance).
func TestClassifyCalldataApproveBoundedNotUnlimited(t *testing.T) {
	e := &Engine{clock: fixedClock()}
	data := approveCalldata(spenderA, big.NewInt(1000))
	checks, ok := e.ClassifyCalldata(tokenC, data, nil)
	if !ok || len(checks) != 1 {
		t.Fatalf("bounded approve must be recognized; ok=%v len=%d", ok, len(checks))
	}
	if checks[0].Unlimited {
		t.Fatal("a bounded approve(1000) must NOT be Unlimited")
	}
	if checks[0].Dest != spenderA {
		t.Fatalf("Dest = %s, want spender", checks[0].Dest.Hex())
	}
}

// TestClassifyCalldataTransferRoutesToKindTransfer confirms transfer(recipient,amount) →
// KindTransfer with Dest=recipient and the token value NOT folded into SpendWei.
func TestClassifyCalldataTransferRoutesToKindTransfer(t *testing.T) {
	e := &Engine{clock: fixedClock()}
	data := transferCalldata(recipB, big.NewInt(500))
	checks, ok := e.ClassifyCalldata(tokenC, data, nil)
	if !ok || len(checks) != 1 {
		t.Fatalf("transfer must be recognized; ok=%v len=%d", ok, len(checks))
	}
	c := checks[0]
	if c.effectiveKind() != KindTransfer {
		t.Fatalf("effectiveKind = %v, want KindTransfer", c.effectiveKind())
	}
	if c.Dest != recipB {
		t.Fatalf("Dest = %s, want the decoded recipient %s", c.Dest.Hex(), recipB.Hex())
	}
	// The token value is NOT ETH-denominated: with no --value, SpendWei must be nil/zero.
	if c.SpendWei != nil && c.SpendWei.Sign() != 0 {
		t.Fatalf("SpendWei = %v, want nil/0 (a token value never rides SpendWei)", c.SpendWei)
	}
	if c.TokenAmt == nil || c.TokenAmt.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("TokenAmt = %v, want 500 (display)", c.TokenAmt)
	}
}

// TestClassifyCalldataValueFoldsIntoSpendWei confirms --value folds into SpendWei for a
// RECOGNIZED call too (recognition-independent, §4.3 stage 2).
func TestClassifyCalldataValueFoldsIntoSpendWei(t *testing.T) {
	e := &Engine{clock: fixedClock()}
	val := big.NewInt(7_000_000_000_000_000) // 0.007 ETH msg.value on a payable approve
	data := approveCalldata(spenderA, big.NewInt(1))
	checks, ok := e.ClassifyCalldata(tokenC, data, val)
	if !ok || len(checks) != 1 {
		t.Fatalf("recognized; ok=%v len=%d", ok, len(checks))
	}
	if checks[0].SpendWei == nil || checks[0].SpendWei.Cmp(val) != 0 {
		t.Fatalf("SpendWei = %v, want msg.value %v folded in", checks[0].SpendWei, val)
	}
}

// TestClassifyCalldataSetApprovalForAllUnlimited confirms setApprovalForAll(op,true) →
// KindApprove Unlimited=true (operator-for-all is unbounded → takes the ack ceremony).
func TestClassifyCalldataSetApprovalForAllUnlimited(t *testing.T) {
	e := &Engine{clock: fixedClock()}
	data := setApprovalForAllCalldata(spenderA, true)
	checks, ok := e.ClassifyCalldata(tokenC, data, nil)
	if !ok || len(checks) != 1 {
		t.Fatalf("setApprovalForAll must be recognized; ok=%v len=%d", ok, len(checks))
	}
	if checks[0].effectiveKind() != KindApprove {
		t.Fatalf("kind = %v, want KindApprove", checks[0].effectiveKind())
	}
	if !checks[0].Unlimited {
		t.Fatal("setApprovalForAll(op,true) must be Unlimited (operator-for-all is unbounded)")
	}
	if checks[0].Dest != spenderA {
		t.Fatalf("Dest = %s, want the operator", checks[0].Dest.Hex())
	}
}

// TestClassifyCalldataUnknownSelectorOkFalse confirms an unrecognized selector returns
// ok=false with NO Checks (the fail-direction; caller applies stage-5b).
func TestClassifyCalldataUnknownSelectorOkFalse(t *testing.T) {
	e := &Engine{clock: fixedClock()}
	// stake(uint256) = 0xa694fc3a — NOT a recognized spend-equivalent.
	data := append([]byte{0xa6, 0x94, 0xfc, 0x3a}, uintWord(big.NewInt(42))...)
	checks, ok := e.ClassifyCalldata(tokenC, data, nil)
	if ok {
		t.Fatal("an unknown selector must return ok=false (it falls to stage-5b)")
	}
	if checks != nil {
		t.Fatalf("ok=false must return no Checks, got %d (no partial extraction)", len(checks))
	}
}

// TestClassifyCalldataShortDataOkFalse confirms short/undecodable calldata is ok=false.
func TestClassifyCalldataShortDataOkFalse(t *testing.T) {
	e := &Engine{clock: fixedClock()}
	if _, ok := e.ClassifyCalldata(tokenC, []byte{0x09, 0x5e}, nil); ok {
		t.Fatal("a <4-byte selector must return ok=false")
	}
	if _, ok := e.ClassifyCalldata(tokenC, nil, nil); ok {
		t.Fatal("empty calldata must return ok=false")
	}
}

// TestTypedAndGenericApprovePathsIndistinguishable proves the M10 invariant end-to-end at
// the engine level: the Check ClassifyCalldata produces for raw approve(attacker,MAX)
// yields the SAME Evaluate verdict as the equivalent typed Check the `token approve` path
// builds — both denied unlimited_unacked without the ack, both denied allowlist when the
// spender is off-allowlist, both allowed with ack + allowlisted spender.
func TestTypedAndGenericApprovePathsIndistinguishable(t *testing.T) {
	// A policy with an allowlist enabled + the attacker spender NOT on it.
	al := true
	p := Policy{
		Version:   bodyVersion,
		Messages:  "allow",
		Rules:     Rules{Default: Limits{AllowlistEnabled: &al, MaxTxWei: wei("1000000000000000000")}},
		TypedData: TypedDataCfg{Unknown: "deny"},
	}

	e := &Engine{clock: fixedClock()}
	genericChecks, ok := e.ClassifyCalldata(tokenC, approveCalldata(spenderA, maxUint256()), nil)
	if !ok || len(genericChecks) != 1 {
		t.Fatalf("classify approve; ok=%v len=%d", ok, len(genericChecks))
	}
	generic := genericChecks[0]
	generic.Network = "mainnet"
	generic.Account = selfAcc

	// The "typed" path Check the same op produces (what `token approve` builds).
	typed := Check{
		Network:   "mainnet",
		Account:   selfAcc,
		KindEnum:  KindApprove,
		Dest:      spenderA,
		Unlimited: true,
		Token:     lowerHex(tokenC),
		Asset:     lowerHex(tokenC),
		TokenAmt:  maxUint256(),
	}

	dg := Evaluate(p, generic, big.NewInt(0), now0())
	dt := Evaluate(p, typed, big.NewInt(0), now0())
	if dg.Allowed || dt.Allowed {
		t.Fatal("both paths must be denied (off-allowlist spender + unacked unlimited)")
	}
	if dg.Code != dt.Code {
		t.Fatalf("the generic (%q) and typed (%q) verdicts must be IDENTICAL", dg.Code, dt.Code)
	}
	// The denial subject must be the decoded attacker spender, never the ERC-20 contract.
	if got := dg.Data["address"]; got != nil && got != lowerHex(spenderA) {
		t.Fatalf("denial address = %v, want the decoded spender %q (never the contract)", got, lowerHex(spenderA))
	}

	// Now allowlist the spender + ack the unlimited: both paths allow.
	p.Allowlist = []PinEntry{{Source: "address", Address: lowerHex(spenderA)}}
	generic.Acked = true
	typed.Acked = true
	if ag := Evaluate(p, generic, big.NewInt(0), now0()); !ag.Allowed {
		t.Fatalf("generic path must allow with allowlisted spender + ack: %+v", ag)
	}
	if at := Evaluate(p, typed, big.NewInt(0), now0()); !at.Allowed {
		t.Fatalf("typed path must allow with allowlisted spender + ack: %+v", at)
	}
}

// ── stage-5b unknown-calldata gate ───────────────────────────────────────────

// unknownCheck builds the Check service sets for an unrecognized contract send: Dest =
// contract (so stage-3b also gates it), UnknownCalldata=true, ContractAddr/Selector set,
// --value folded into SpendWei.
func unknownCheck(contract common.Address, selector string, value *big.Int) Check {
	return Check{
		Account:         selfAcc,
		Network:         "mainnet",
		Dest:            contract,
		ContractAddr:    contract,
		Selector:        selector,
		UnknownCalldata: true,
		SpendWei:        value,
	}
}

// TestStage5bUnknownDeniedByDefault confirms an unrecognized selector to a non-allowlisted,
// non-opted-in contract while a policy is active is denied policy.denied.contract_call.
func TestStage5bUnknownDeniedByDefault(t *testing.T) {
	al := false
	p := Policy{
		Version:   bodyVersion,
		Messages:  "allow",
		Rules:     Rules{Default: Limits{MaxTxWei: wei("1000000000000000000"), AllowlistEnabled: &al}},
		TypedData: TypedDataCfg{Unknown: "deny"},
	}
	req := unknownCheck(tokenC, stakeSel, nil)
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Allowed {
		t.Fatal("an unrecognized selector to a non-allowlisted contract must be denied (stage-5b)")
	}
	if dec.Code != codeContractCall {
		t.Fatalf("code = %q, want %q", dec.Code, codeContractCall)
	}
	if dec.Data["reason"] != "not_allowed" {
		t.Fatalf("reason = %v, want not_allowed", dec.Data["reason"])
	}
	if dec.Data["contract"] != lowerHex(tokenC) {
		t.Fatalf("contract payload = %v, want %q", dec.Data["contract"], lowerHex(tokenC))
	}
}

// TestStage5bShortSelectorReasonUnknown confirms a short/undecodable selector reports the
// unknown_selector reason.
func TestStage5bShortSelectorReasonUnknown(t *testing.T) {
	al := false
	p := Policy{
		Version:  bodyVersion,
		Messages: "allow",
		Rules:    Rules{Default: Limits{MaxTxWei: wei("1000000000000000000"), AllowlistEnabled: &al}},
	}
	req := unknownCheck(tokenC, "0x", nil) // selectorHex of <4-byte data
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Code != codeContractCall || dec.Data["reason"] != "unknown_selector" {
		t.Fatalf("code/reason = %q/%v, want contract_call/unknown_selector", dec.Code, dec.Data["reason"])
	}
}

// TestStage5bAllowlistedContractPasses confirms an allowlisted contract address is trusted
// to receive arbitrary calldata even when allowlist_enabled is false (an operator opt-in).
func TestStage5bAllowlistedContractPasses(t *testing.T) {
	al := false
	p := Policy{
		Version:   bodyVersion,
		Messages:  "allow",
		Rules:     Rules{Default: Limits{MaxTxWei: wei("1000000000000000000"), AllowlistEnabled: &al}},
		Allowlist: []PinEntry{{Source: "address", Address: lowerHex(tokenC)}},
	}
	req := unknownCheck(tokenC, stakeSel, nil)
	if dec := Evaluate(p, req, big.NewInt(0), now0()); !dec.Allowed {
		t.Fatalf("an allowlisted contract must pass stage-5b: %+v", dec)
	}
}

// TestStage5bTriplePasses confirms the exact (network, contract, selector) triple in
// ContractsAllowed[] passes stage-5b, but a DIFFERENT selector to the same contract still
// denies (the ack is per-triple, not per-contract).
func TestStage5bTriplePasses(t *testing.T) {
	al := false
	p := Policy{
		Version:          bodyVersion,
		Messages:         "allow",
		Rules:            Rules{Default: Limits{MaxTxWei: wei("1000000000000000000"), AllowlistEnabled: &al}},
		ContractsAllowed: []ContractAllow{{Network: "mainnet", Contract: lowerHex(tokenC), Selector: stakeSel}},
	}
	if dec := Evaluate(p, unknownCheck(tokenC, stakeSel, nil), big.NewInt(0), now0()); !dec.Allowed {
		t.Fatalf("the opted-in triple must pass stage-5b: %+v", dec)
	}
	// A different selector to the same contract still denies.
	if dec := Evaluate(p, unknownCheck(tokenC, "0xdeadbeef", nil), big.NewInt(0), now0()); dec.Allowed {
		t.Fatal("a DIFFERENT selector to the same contract must still deny (per-triple ack)")
	}
}

// TestStage5bTriplePassesWithAllowlistOn confirms the §4.3 stage-5b "OR" path: with
// allowlist_enabled=ON and the contract NOT in the address allowlist, an unknown selector
// whose exact (network, contract, selector) triple is in ContractsAllowed[] still passes —
// stage-3b must not mask the per-triple opt-in (the contract-as-destination is governed by
// stage-5b, not stage-3b, for an unknown-calldata send). Deny-by-default is preserved: a
// triple that is NOT opted in still denies even though no other dest is allowlisted.
func TestStage5bTriplePassesWithAllowlistOn(t *testing.T) {
	al := true
	p := Policy{
		Version:          bodyVersion,
		Messages:         "allow",
		Rules:            Rules{Default: Limits{MaxTxWei: wei("1000000000000000000"), AllowlistEnabled: &al}},
		Allowlist:        []PinEntry{{Source: "address", Address: lowerHex(spenderA)}}, // some OTHER dest, NOT the contract
		ContractsAllowed: []ContractAllow{{Network: "mainnet", Contract: lowerHex(tokenC), Selector: stakeSel}},
	}
	// Opted-in triple passes even with allowlist on and the contract off the address allowlist.
	if dec := Evaluate(p, unknownCheck(tokenC, stakeSel, nil), big.NewInt(0), now0()); !dec.Allowed {
		t.Fatalf("opted-in triple must pass with allowlist_enabled=on: %+v", dec)
	}
	// A non-opted-in selector to the same (non-allowlisted) contract still denies.
	dec := Evaluate(p, unknownCheck(tokenC, "0xdeadbeef", nil), big.NewInt(0), now0())
	if dec.Allowed {
		t.Fatal("a non-opted-in unknown selector must still deny with allowlist on (deny-by-default)")
	}
	if dec.Code != codeContractCall {
		t.Fatalf("code = %q, want %q (stage-5b, not the stage-3b allowlist code)", dec.Code, codeContractCall)
	}
}

// TestStage5bEthGatesApplyAFortiori confirms --value on an unknown call still trips the
// per-tx ETH limit (the ETH gates apply a fortiori on the unknown path), AND the stage-5b
// deny rides too — the higher-precedence verdict is contract_call but tx_limit accumulates.
func TestStage5bEthGatesApplyAFortiori(t *testing.T) {
	al := false
	p := Policy{
		Version:  bodyVersion,
		Messages: "allow",
		Rules:    Rules{Default: Limits{MaxTxWei: wei("1000000000000000000"), AllowlistEnabled: &al}}, // 1 ETH cap
	}
	req := unknownCheck(tokenC, stakeSel, big.NewInt(2_000_000_000_000_000_000)) // 2 ETH --value
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Allowed {
		t.Fatal("must be denied")
	}
	// Both violations must be present.
	var sawContract, sawTxLimit bool
	for _, v := range dec.Violations {
		if v.Code == codeContractCall {
			sawContract = true
		}
		if v.Code == codeTxLimit {
			sawTxLimit = true
		}
	}
	if !sawContract || !sawTxLimit {
		t.Fatalf("both contract_call + tx_limit must accumulate; violations=%+v", dec.Violations)
	}
}

// TestStage5bNotFiredForRecognized confirms a recognized spend-equivalent never reaches
// stage-5b (UnknownCalldata is false), so it rides the typed gates only.
func TestStage5bNotFiredForRecognized(t *testing.T) {
	al := true
	p := Policy{
		Version:   bodyVersion,
		Messages:  "allow",
		Rules:     Rules{Default: Limits{AllowlistEnabled: &al}},
		Allowlist: []PinEntry{{Source: "address", Address: lowerHex(spenderA)}},
	}
	e := &Engine{clock: fixedClock()}
	checks, ok := e.ClassifyCalldata(tokenC, approveCalldata(spenderA, big.NewInt(1)), nil)
	if !ok {
		t.Fatal("recognized")
	}
	c := checks[0]
	c.Network = "mainnet"
	c.Account = selfAcc
	if c.UnknownCalldata {
		t.Fatal("a recognized spend-equivalent must NOT set UnknownCalldata")
	}
	if dec := Evaluate(p, c, big.NewInt(0), now0()); !dec.Allowed {
		t.Fatalf("a bounded approve to an allowlisted spender must allow (no stage-5b): %+v", dec)
	}
}

// TestStage5bDenylistBeatsAllowlistedContract confirms a denylisted contract is refused by
// stage-3a even when it is ALSO allowlisted (the denylist beats the stage-5b pass) — the
// denylist precedence holds for the unknown-calldata path too (defense in depth).
func TestStage5bDenylistBeatsAllowlistedContract(t *testing.T) {
	al := false
	p := Policy{
		Version:   bodyVersion,
		Messages:  "allow",
		Rules:     Rules{Default: Limits{MaxTxWei: wei("1000000000000000000"), AllowlistEnabled: &al}},
		Allowlist: []PinEntry{{Source: "address", Address: lowerHex(tokenC)}}, // contract allowlisted
		Denylist:  []PinEntry{{Source: "address", Address: lowerHex(tokenC)}}, // AND denylisted
	}
	dec := Evaluate(p, unknownCheck(tokenC, stakeSel, nil), big.NewInt(0), now0())
	if dec.Allowed {
		t.Fatal("a denylisted contract must be refused even when allowlisted (denylist beats stage-5b pass)")
	}
	if dec.Code != codeAllowlist {
		t.Fatalf("code = %q, want %q (the denylist code, rank 1, beats contract_call rank 3)", dec.Code, codeAllowlist)
	}
}

// stakeSel is the unrecognized stake(uint256) selector used by the stage-5b tests.
const stakeSel = "0xa694fc3a"
