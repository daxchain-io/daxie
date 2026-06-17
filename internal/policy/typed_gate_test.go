package policy

import (
	"math/big"
	"testing"
)

// typed_gate_test.go pins the §4.3 stage-5 typed-data gate for UNRECOGNIZED typed
// data over the PURE Evaluate (no I/O): deny-by-default once a policy is active, the
// per-network typed_data_unknown override, the per-domain Allowed[] triple match, and
// the chain-mismatch deny. (The recognized-permit chain-mismatch is exercised in
// recognizers_test/evaluate via the KindPermit path; this file covers the new
// unknown branch the M9 service builds.)

const orderContract = "0x00000000000000adc04c56bf30ac9d3c0aaf14dc"

// unknownTypedCheck builds the Check the M9 authorizeSignature emits for an
// UNRECOGNIZED EIP-712 message (no Dest, no SpendWei — only the typed fields).
func unknownTypedCheck(primary, verifying string, chainID int64) Check {
	return Check{
		Network:        "mainnet",
		ToInput:        primary,
		TypedUnknown:   true,
		TypedPrimary:   primary,
		TypedVerifying: verifying,
		TypedChainID:   chainID,
	}
}

// typedPolicy builds an active policy with the given typed_data.unknown disposition
// and (optionally) a per-domain allow registry.
func typedPolicy(unknown string, allowed ...TypedAllow) Policy {
	return Policy{
		Version:   bodyVersion,
		Messages:  "allow",
		Rules:     Rules{Default: Limits{}},
		TypedData: TypedDataCfg{Unknown: unknown, Allowed: allowed},
	}
}

// 1. Unknown typed data, no allow ⇒ deny-by-default (typed_data, reason unknown).
func TestStage5UnknownDeniedByDefault(t *testing.T) {
	p := typedPolicy("deny")
	req := unknownTypedCheck("OrderComponents", orderContract, 1)
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Allowed {
		t.Fatal("unrecognized typed data must be denied by default once a policy is active")
	}
	if dec.Code != codeTypedData {
		t.Fatalf("code = %q, want %q", dec.Code, codeTypedData)
	}
	if dec.Data["reason"] != "unknown" {
		t.Fatalf("reason = %v, want unknown", dec.Data["reason"])
	}
	// The denial must NOT be masked by a higher-precedence allowlist/etc. code: an
	// unknown typed message carries no ETH dest, so only stage 5 may fire.
	if len(dec.Violations) != 1 {
		t.Fatalf("violations = %d, want exactly 1 (only stage 5)", len(dec.Violations))
	}
}

// 2. typed_data.unknown == "allow" ⇒ unknown typed data passes.
func TestStage5UnknownAllowedBySwitch(t *testing.T) {
	p := typedPolicy("allow")
	req := unknownTypedCheck("OrderComponents", orderContract, 1)
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if !dec.Allowed {
		t.Fatalf("typed_data.unknown:allow must admit unrecognized typed data: %+v", dec)
	}
}

// 3. A per-domain Allowed[] triple match passes the gate even with unknown:deny.
func TestStage5AllowedTripleMatchPasses(t *testing.T) {
	p := typedPolicy("deny", TypedAllow{ChainID: 1, VerifyingContract: orderContract, PrimaryType: "OrderComponents", Label: "seaport"})
	req := unknownTypedCheck("OrderComponents", orderContract, 1)
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if !dec.Allowed {
		t.Fatalf("a pinned (chain, contract, primaryType) triple must pass the gate: %+v", dec)
	}

	// A near-miss (different primaryType) is still denied.
	miss := unknownTypedCheck("BulkOrder", orderContract, 1)
	if d := Evaluate(p, miss, big.NewInt(0), now0()); d.Allowed {
		t.Fatal("a different primaryType must NOT match the pinned triple")
	}
	// A near-miss (different chain) is still denied.
	missChain := unknownTypedCheck("OrderComponents", orderContract, 137)
	d := Evaluate(p, missChain, big.NewInt(0), now0())
	if d.Allowed {
		t.Fatal("a different chain_id must NOT match the pinned triple")
	}
	// The different-chain message is a chain mismatch (the service marks it); without
	// the marker it is still unknown-denied, but with the service marker it is
	// chain_mismatch — covered in test 4.
	_ = d
}

// 4. A chain mismatch on unknown typed data ⇒ deny (chain_mismatch), even with an
// allow switch. The service marks the mismatch via the Asset marker (the engine does
// not see the active chainId).
func TestStage5ChainMismatchDeniedEvenWithAllow(t *testing.T) {
	p := typedPolicy("allow")
	req := unknownTypedCheck("OrderComponents", orderContract, 1)
	req.Asset = "chain_mismatch:1" // service: domain.chainId 1 ≠ the active network
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Allowed {
		t.Fatal("a chain-mismatched typed message must be denied even when typed_data.unknown:allow")
	}
	if dec.Code != codeTypedData {
		t.Fatalf("code = %q, want %q", dec.Code, codeTypedData)
	}
	if dec.Data["reason"] != "chain_mismatch" {
		t.Fatalf("reason = %v, want chain_mismatch", dec.Data["reason"])
	}
}

// 5. A chain mismatch beats a matching allow entry (deny first): a pinned triple does
// NOT rescue a message signed for the wrong chain.
func TestStage5ChainMismatchBeatsAllowEntry(t *testing.T) {
	p := typedPolicy("deny", TypedAllow{ChainID: 1, VerifyingContract: orderContract, PrimaryType: "OrderComponents"})
	req := unknownTypedCheck("OrderComponents", orderContract, 1)
	req.Asset = "chain_mismatch:1"
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Allowed {
		t.Fatal("a chain mismatch must deny even when the triple is allow-listed")
	}
	if dec.Data["reason"] != "chain_mismatch" {
		t.Fatalf("reason = %v, want chain_mismatch (deny precedes the allow-triple check)", dec.Data["reason"])
	}
}
