package policyseal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

// baseAnchorFor builds an anchor pinned to pass under fixedSalt with lightParams.
func baseAnchorFor(t *testing.T, pass []byte) Anchor {
	t.Helper()
	_, pk := mustDerive(t, pass, fixedSalt(), lightParams)
	return Anchor{
		VerifyKey:      EncodeKey(pk),
		Salt:           EncodeSalt(fixedSalt()),
		Scrypt:         lightParams,
		NonceWatermark: 5,
	}
}

// TestStageThenCommit: the full happy path. --stage derives a new key from a
// fresh salt; the operator records (verify_key_next, staged_salt); --commit
// re-derives from the staged salt with the SAME new passphrase and the derived
// key equals the staged verify_key_next.
func TestStageThenCommit(t *testing.T) {
	a := baseAnchorFor(t, []byte("old-admin-pass"))
	newPass := []byte("brand-new-admin-pass")

	newKey, stagedSalt, err := StageRotation(newPass, lightParams)
	if err != nil {
		t.Fatalf("StageRotation: %v", err)
	}
	// Operator records the staged rotation in the anchor.
	a.VerifyKeyNext = newKey
	a.StagedSalt = EncodeSalt(stagedSalt)

	fam, err := CommitRotation(newPass, a, lightParams)
	if err != nil {
		t.Fatalf("CommitRotation: %v", err)
	}
	defer zero(fam.Private)

	// The committed public key must equal the staged verify_key_next.
	if EncodeKey(fam.Public) != newKey {
		t.Fatal("committed public key != staged verify_key_next")
	}
	// The committed salt must equal the staged salt.
	if !bytes.Equal(fam.Salt, stagedSalt) {
		t.Fatal("committed salt != staged salt")
	}
	// The returned private key must actually sign verifiably under the new public.
	body := []byte(`{"version":1,"nonce":6}`)
	sig := Sign(body, fam.Private)
	if !Verify(body, sig, fam.Public) {
		t.Fatal("committed key family does not produce a verifiable seal")
	}
	// And the new key is genuinely different from the old pinned key.
	oldPK, _ := a.VerifyKeyBytes()
	if bytes.Equal(fam.Public, oldPK) {
		t.Fatal("rotation produced the same key as before")
	}
}

// TestCommitWrongNewPassphrase: committing with a passphrase different from the
// one --stage used (or a fat-fingered promoted key) re-derives a different key
// than verify_key_next ⇒ ErrRotationKeyMismatch, nothing committed. This is the
// canary that turns a typo into a refusal instead of a fleet-bricking reseal.
func TestCommitWrongNewPassphrase(t *testing.T) {
	a := baseAnchorFor(t, []byte("old-admin-pass"))

	_, stagedSalt, err := StageRotation([]byte("intended-new-pass"), lightParams)
	if err != nil {
		t.Fatalf("StageRotation: %v", err)
	}
	// Operator promotes the key --stage printed (for "intended-new-pass")...
	intendedKey, _, _ := StageRotation([]byte("intended-new-pass"), lightParams)
	_ = intendedKey // each StageRotation uses a fresh salt; use the staged one below

	// Record the staged salt but pin verify_key_next to the key derived FROM the
	// staged salt under the intended passphrase (what an honest --stage would set).
	_, pkIntended := mustDerive(t, []byte("intended-new-pass"), stagedSalt, lightParams)
	a.VerifyKeyNext = EncodeKey(pkIntended)
	a.StagedSalt = EncodeSalt(stagedSalt)

	// Now --commit is run with the WRONG new passphrase.
	_, err = CommitRotation([]byte("typo-new-pass"), a, lightParams)
	if !errors.Is(err, ErrRotationKeyMismatch) {
		t.Fatalf("CommitRotation with wrong passphrase: err = %v, want ErrRotationKeyMismatch", err)
	}
}

// TestCommitNoStaged: committing with no staged rotation recorded is a refusal.
func TestCommitNoStaged(t *testing.T) {
	a := baseAnchorFor(t, []byte("old-admin-pass")) // no VerifyKeyNext / StagedSalt
	_, err := CommitRotation([]byte("whatever"), a, lightParams)
	if !errors.Is(err, ErrNoStagedRotation) {
		t.Fatalf("CommitRotation with no staged rotation: err = %v, want ErrNoStagedRotation", err)
	}

	// Staged salt present but no next key (or vice versa) is also "no rotation".
	a.StagedSalt = EncodeSalt(fixedSalt())
	if _, err := CommitRotation([]byte("whatever"), a, lightParams); !errors.Is(err, ErrNoStagedRotation) {
		t.Fatalf("salt-only staged: err = %v, want ErrNoStagedRotation", err)
	}
}

// TestStageRotationProducesDistinctSalts: two stagings produce different salts
// (fresh crypto/rand each time), so a rotation never reuses the prior salt.
func TestStageRotationProducesDistinctSalts(t *testing.T) {
	_, s1, err := StageRotation([]byte("p"), lightParams)
	if err != nil {
		t.Fatalf("StageRotation: %v", err)
	}
	_, s2, err := StageRotation([]byte("p"), lightParams)
	if err != nil {
		t.Fatalf("StageRotation: %v", err)
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("two stagings reused the same salt")
	}
	if len(s1) != 32 {
		t.Fatalf("staged salt length = %d, want 32", len(s1))
	}
}

// TestCommitZeroesPrivateOnMismatch: a mismatch returns no live key material
// (the family is zero-valued, Private is nil).
func TestCommitZeroesPrivateOnMismatch(t *testing.T) {
	a := baseAnchorFor(t, []byte("old"))
	_, stagedSalt, _ := StageRotation([]byte("intended"), lightParams)
	_, pkIntended := mustDerive(t, []byte("intended"), stagedSalt, lightParams)
	a.VerifyKeyNext = EncodeKey(pkIntended)
	a.StagedSalt = EncodeSalt(stagedSalt)

	fam, err := CommitRotation([]byte("wrong"), a, lightParams)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if fam.Private != nil || fam.Public != nil || fam.Salt != nil {
		t.Fatal("a failed commit must return no key material")
	}
}

// TestRotatedKeyVerifiesUnderEither: after staging (before commit), the anchor
// carries verify_key (old) + verify_key_next (new); the loader is documented to
// accept either. This asserts both keys are present and decode, and that a body
// signed under the OLD key still verifies under verify_key during the window.
func TestRotatedKeyVerifiesUnderEither(t *testing.T) {
	oldPass := []byte("old-admin-pass")
	skOld, pkOld := mustDerive(t, oldPass, fixedSalt(), lightParams)
	a := Anchor{
		VerifyKey:      EncodeKey(pkOld),
		Salt:           EncodeSalt(fixedSalt()),
		Scrypt:         lightParams,
		NonceWatermark: 1,
	}
	newKey, stagedSalt, _ := StageRotation([]byte("new-admin-pass"), lightParams)
	a.VerifyKeyNext = newKey
	a.StagedSalt = EncodeSalt(stagedSalt)

	cur, err := a.VerifyKeyBytes()
	if err != nil {
		t.Fatalf("VerifyKeyBytes: %v", err)
	}
	next, hasNext, err := a.VerifyKeyNextBytes()
	if err != nil || !hasNext {
		t.Fatalf("VerifyKeyNextBytes: next=%v hasNext=%v err=%v", next, hasNext, err)
	}
	if len(next) != ed25519.PublicKeySize {
		t.Fatalf("next key length = %d", len(next))
	}
	// Old key still signs verifiably during the window.
	body := []byte(`{"version":1,"nonce":2}`)
	sig := Sign(body, skOld)
	if !Verify(body, sig, cur) {
		t.Fatal("old-key seal failed under anchor.VerifyKey during the rotation window")
	}
	if Verify(body, sig, next) {
		t.Fatal("old-key seal unexpectedly verified under the new staged key")
	}
}
