package policyseal

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
)

// Staged, zero-outage admin-passphrase rotation (design §4.6/§4.7
// change-admin-passphrase). The flow is two-phase so a fleet of agent pods never
// sees a window where no valid verify key matches the on-disk policy:
//
//	--stage:  authenticate the CURRENT passphrase against anchor.VerifyKey
//	          (the caller does that with DeriveSealKey + a constant-time compare),
//	          then derive the NEW key family from a freshly generated salt and
//	          record (verify_key_next, staged_salt) into the anchor. The loader
//	          already accepts a seal under verify_key OR verify_key_next, so the
//	          policy keeps signing under the old key the whole time.
//	  ...operator rolls verify_key_next into the ConfigMap, canaries with
//	     `policy pin --verify <new key>`...
//	--commit: re-derive from staged_salt, assert the derived public key equals
//	          the staged verify_key_next (proof the operator promoted exactly the
//	          key --stage printed, not a fat-fingered value), then return the
//	          rotated (sk, pk, salt) family so the caller reseals the body and
//	          promotes verify_key_next → verify_key, clearing staged_salt.
//
// These two functions are the cryptographic core; the anchor field bookkeeping
// (writing verify_key_next, clearing staged_salt, the K8s read-only blocking) is
// the engine's job — this package only derives and proves.

// ErrRotationKeyMismatch is returned by CommitRotation when the key re-derived
// from the staged salt does not equal the anchor's pinned verify_key_next. That
// means the new passphrase supplied to --commit differs from the one --stage used
// (or the operator promoted a different key into the ConfigMap) — committing would
// produce a body no one can verify, so it fails closed.
var ErrRotationKeyMismatch = errors.New("policyseal: staged rotation key mismatch (new passphrase or promoted key differs from --stage)")

// ErrNoStagedRotation is returned by CommitRotation when the anchor carries no
// staged rotation (verify_key_next or staged_salt absent) — there is nothing to
// commit.
var ErrNoStagedRotation = errors.New("policyseal: no staged rotation to commit")

// StageRotation generates a fresh salt, derives the new seal key family from
// newAdminPass under that salt with the given params, and returns the encoded
// verify key plus the staged salt for the caller to record as
// anchor.VerifyKeyNext / anchor.StagedSalt.
//
// newAdminPass is the REVEALED new admin passphrase bytes (caller passes
// next.Reveal()); it is read but never retained or logged. The returned sk is
// discarded here — it is re-derived deterministically at --commit time from the
// staged salt + the same passphrase — so StageRotation never holds private key
// material beyond DeriveSealKey's own zeroing. params is normally
// DefaultScryptParams(); the caller passes the anchor's current params so a
// rotation does not silently change the cost.
func StageRotation(newAdminPass []byte, params ScryptParams) (newVerifyKey string, stagedSalt []byte, err error) {
	salt, err := NewSalt()
	if err != nil {
		return "", nil, err
	}
	sk, pk, err := DeriveSealKey(newAdminPass, salt, params)
	if err != nil {
		return "", nil, err
	}
	// We only need the public key for staging; zero the private half immediately.
	zero(sk)
	return EncodeKey(pk), salt, nil
}

// RotatedFamily is the result of a committed rotation: the new key pair and the
// salt it derives from, which the caller writes back as the anchor's new
// VerifyKey + Salt (and uses sk to reseal the body). The caller MUST zero Private
// after resealing.
type RotatedFamily struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	Salt    []byte
}

// CommitRotation re-derives the seal key family from the anchor's staged salt and
// newAdminPass, then asserts the derived public key equals the anchor's pinned
// verify_key_next (constant-time). On match it returns the rotated family so the
// caller reseals the body under the new key and promotes the rotation; on
// mismatch it returns ErrRotationKeyMismatch and the caller commits nothing.
//
// newAdminPass is the REVEALED new admin passphrase bytes; it is read but never
// retained or logged. params is the anchor's current scrypt params (the rotation
// keeps the same cost unless the caller deliberately changes it before staging).
//
// On any error the returned family carries no live key material.
func CommitRotation(newAdminPass []byte, a Anchor, params ScryptParams) (RotatedFamily, error) {
	stagedSalt, hasSalt, err := a.StagedSaltBytes()
	if err != nil {
		return RotatedFamily{}, err
	}
	wantNext, hasNext, err := a.VerifyKeyNextBytes()
	if err != nil {
		return RotatedFamily{}, err
	}
	if !hasSalt || !hasNext {
		return RotatedFamily{}, ErrNoStagedRotation
	}

	sk, pk, err := DeriveSealKey(newAdminPass, stagedSalt, params)
	if err != nil {
		return RotatedFamily{}, err
	}
	// Constant-time compare so a near-miss key cannot be probed by timing. Both
	// are 32 bytes (DeriveSealKey always yields PublicKeySize; wantNext was
	// length-checked at decode), so the lengths match.
	if subtle.ConstantTimeCompare(pk, wantNext) != 1 {
		zero(sk)
		return RotatedFamily{}, ErrRotationKeyMismatch
	}
	return RotatedFamily{Private: sk, Public: pk, Salt: stagedSalt}, nil
}
