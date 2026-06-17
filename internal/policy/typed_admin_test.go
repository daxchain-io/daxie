package policy

import (
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
)

// typed_admin_test.go pins the M9 typed-data allow registry admin surface
// (TypedAllow/TypedRemove): admin-gated upsert/remove, the wrong-passphrase refusal,
// the nonce bump + reseal, dedupe by the (chain_id, verifying_contract, primary_type)
// triple, and the malformed-entry rejection (fail-closed).

const seaportContract = "0x00000000000000adc04c56bf30ac9d3c0aaf14dc"

// TestTypedAllowAddsEntryAndBumpsNonce confirms an allow seals the triple into
// TypedData.Allowed[] under the admin passphrase, bumps the nonce + watermark, and
// reseals (the entry round-trips through load).
func TestTypedAllowAddsEntryAndBumpsNonce(t *testing.T) {
	e, anchor := sealedEngine(t, "admin-pass")
	pass := secret.NewString("admin-pass")
	defer pass.Zero()

	anchor2, err := e.TypedAllow(pass, TypedAllowEntry{
		ChainID:           1,
		VerifyingContract: seaportContract,
		PrimaryType:       "OrderComponents",
		Label:             "seaport",
		WrittenBy:         "test",
	})
	if err != nil {
		t.Fatalf("TypedAllow: %v", err)
	}
	if anchor2.NonceWatermark != anchor.NonceWatermark+1 {
		t.Fatalf("watermark = %d, want %d", anchor2.NonceWatermark, anchor.NonceWatermark+1)
	}

	res, err := loadPolicy(e.dir, anchor2, true)
	if err != nil {
		t.Fatalf("load after allow: %v", err)
	}
	if !res.status.Verified {
		t.Fatal("the resealed policy must verify under the new anchor")
	}
	got := res.policy.TypedData.Allowed
	if len(got) != 1 {
		t.Fatalf("Allowed[] len = %d, want 1 (%+v)", len(got), got)
	}
	a := got[0]
	if a.ChainID != 1 || a.PrimaryType != "OrderComponents" || a.Label != "seaport" {
		t.Fatalf("entry = %+v, want chain 1 / OrderComponents / seaport", a)
	}
	// The verifying contract is stored lowercased.
	if a.VerifyingContract != seaportContract {
		t.Fatalf("verifying_contract = %q, want lowercased %q", a.VerifyingContract, seaportContract)
	}
}

// TestTypedAllowWrongPassIsAdminAuth confirms the registry is admin-gated: a wrong
// passphrase is policy.admin_auth and seals nothing.
func TestTypedAllowWrongPassIsAdminAuth(t *testing.T) {
	e, _ := sealedEngine(t, "right-pass")
	wrong := secret.NewString("WRONG-pass")
	defer wrong.Zero()
	_, err := e.TypedAllow(wrong, TypedAllowEntry{
		ChainID:           1,
		VerifyingContract: seaportContract,
		PrimaryType:       "OrderComponents",
		WrittenBy:         "test",
	})
	assertCode(t, err, "policy.admin_auth", domain.ExitTimeoutPending)
}

// TestTypedAllowDedupesByTriple confirms a re-allow of the same triple updates the
// label in place (no duplicate row), while a different triple adds a new row.
func TestTypedAllowDedupesByTriple(t *testing.T) {
	e, _ := sealedEngine(t, "admin-pass")
	pass := secret.NewString("admin-pass")
	defer pass.Zero()

	base := TypedAllowEntry{ChainID: 1, VerifyingContract: seaportContract, PrimaryType: "OrderComponents", Label: "v1", WrittenBy: "test"}
	if _, err := e.TypedAllow(pass, base); err != nil {
		t.Fatalf("allow 1: %v", err)
	}
	// Same triple (mixed-case address), new label ⇒ update in place.
	dup := base
	dup.VerifyingContract = "0x00000000000000ADC04C56Bf30aC9d3c0aAF14dC"
	dup.Label = "v2"
	anchor, err := e.TypedAllow(pass, dup)
	if err != nil {
		t.Fatalf("allow 2 (dup): %v", err)
	}
	res, _ := loadPolicy(e.dir, anchor, true)
	if len(res.policy.TypedData.Allowed) != 1 {
		t.Fatalf("dup triple must update in place, got %d rows", len(res.policy.TypedData.Allowed))
	}
	if res.policy.TypedData.Allowed[0].Label != "v2" {
		t.Fatalf("label not updated: %q", res.policy.TypedData.Allowed[0].Label)
	}

	// A different primaryType ⇒ a new row.
	other := base
	other.PrimaryType = "BulkOrder"
	anchor2, err := e.TypedAllow(pass, other)
	if err != nil {
		t.Fatalf("allow 3 (new triple): %v", err)
	}
	res2, _ := loadPolicy(e.dir, anchor2, true)
	if len(res2.policy.TypedData.Allowed) != 2 {
		t.Fatalf("a new triple must add a row, got %d", len(res2.policy.TypedData.Allowed))
	}
}

// TestTypedRemoveDropsEntry confirms remove deletes the triple (and a remove of an
// absent triple is a clean no-op).
func TestTypedRemoveDropsEntry(t *testing.T) {
	e, _ := sealedEngine(t, "admin-pass")
	pass := secret.NewString("admin-pass")
	defer pass.Zero()

	add := TypedAllowEntry{ChainID: 1, VerifyingContract: seaportContract, PrimaryType: "OrderComponents", WrittenBy: "test"}
	if _, err := e.TypedAllow(pass, add); err != nil {
		t.Fatalf("allow: %v", err)
	}
	rm := add
	rm.Remove = true
	anchor, err := e.TypedAllow(pass, rm)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	res, _ := loadPolicy(e.dir, anchor, true)
	if len(res.policy.TypedData.Allowed) != 0 {
		t.Fatalf("remove must drop the entry, got %+v", res.policy.TypedData.Allowed)
	}

	// A second remove (absent triple) is a no-op that still verifies.
	anchor2, err := e.TypedAllow(pass, rm)
	if err != nil {
		t.Fatalf("remove of absent triple must be a clean no-op: %v", err)
	}
	res2, _ := loadPolicy(e.dir, anchor2, true)
	if !res2.status.Verified {
		t.Fatal("a no-op remove must still produce a verifying seal")
	}
}

// TestTypedAllowRejectsMalformed confirms a bad triple is rejected BEFORE the seal
// (fail-closed): a non-address contract, an empty primaryType, a non-positive chain.
func TestTypedAllowRejectsMalformed(t *testing.T) {
	e, _ := sealedEngine(t, "admin-pass")
	pass := secret.NewString("admin-pass")
	defer pass.Zero()

	cases := []struct {
		name  string
		entry TypedAllowEntry
	}{
		{"bad contract", TypedAllowEntry{ChainID: 1, VerifyingContract: "not-an-address", PrimaryType: "X", WrittenBy: "test"}},
		{"empty primary", TypedAllowEntry{ChainID: 1, VerifyingContract: seaportContract, PrimaryType: "  ", WrittenBy: "test"}},
		{"zero chain", TypedAllowEntry{ChainID: 0, VerifyingContract: seaportContract, PrimaryType: "X", WrittenBy: "test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.TypedAllow(pass, tc.entry); err == nil {
				t.Fatalf("malformed entry %+v must be rejected", tc.entry)
			} else if domain.AsError(err).Code != domain.CodeUsage+".bad_typed_allow" {
				t.Fatalf("code = %q, want usage.bad_typed_allow", domain.AsError(err).Code)
			}
		})
	}
}
