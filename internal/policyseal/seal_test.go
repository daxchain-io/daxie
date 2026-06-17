package policyseal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// lightParams is a deliberately cheap scrypt cost for tests: N=16, r=8, p=1.
// The production cost (N=2^17) is ~100ms+ per derivation and would make these
// table tests sluggish; the KDF WIRING (scrypt→HKDF→ed25519) is identical at any
// N, so a small N exercises the exact code path. TestDefaultScryptParams pins the
// real cost separately.
var lightParams = ScryptParams{N: 1 << 4, R: 8, P: 1}

func mustDerive(t *testing.T, pass, salt []byte, p ScryptParams) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	sk, pk, err := DeriveSealKey(pass, salt, p)
	if err != nil {
		t.Fatalf("DeriveSealKey: %v", err)
	}
	return sk, pk
}

func fixedSalt() []byte {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	return salt
}

// TestDefaultScryptParams pins the §3.4 canonical admin KDF cost. A change to
// these defaults is a security parameter change and must be deliberate.
func TestDefaultScryptParams(t *testing.T) {
	p := DefaultScryptParams()
	if p.N != 1<<17 || p.R != 8 || p.P != 1 {
		t.Fatalf("DefaultScryptParams = %+v, want {N:131072 R:8 P:1}", p)
	}
	if !p.Valid() {
		t.Fatal("DefaultScryptParams must be Valid")
	}
}

func TestScryptParamsValid(t *testing.T) {
	cases := []struct {
		p    ScryptParams
		want bool
	}{
		{ScryptParams{N: 1 << 17, R: 8, P: 1}, true},
		{ScryptParams{N: 16, R: 8, P: 1}, true},
		{ScryptParams{N: 2, R: 1, P: 1}, true},
		{ScryptParams{N: 1, R: 8, P: 1}, false},  // N<2
		{ScryptParams{N: 0, R: 8, P: 1}, false},  // N=0
		{ScryptParams{N: 17, R: 8, P: 1}, false}, // not power of two
		{ScryptParams{N: 16, R: 0, P: 1}, false}, // r<1
		{ScryptParams{N: 16, R: 8, P: 0}, false}, // p<1
	}
	for _, c := range cases {
		if got := c.p.Valid(); got != c.want {
			t.Errorf("%+v.Valid() = %v, want %v", c.p, got, c.want)
		}
	}
}

// TestDeriveDeterminism: the same (pass, salt, params) always yields the same
// keypair. This determinism is what lets a re-supplied admin passphrase
// re-derive the pinned verify key and authenticate a mutation with no stored
// verifier blob.
func TestDeriveDeterminism(t *testing.T) {
	pass := []byte("correct horse battery staple")
	salt := fixedSalt()
	sk1, pk1 := mustDerive(t, pass, salt, lightParams)
	sk2, pk2 := mustDerive(t, pass, salt, lightParams)
	if !bytes.Equal(pk1, pk2) {
		t.Fatal("same pass+salt+params produced different public keys")
	}
	if !bytes.Equal(sk1, sk2) {
		t.Fatal("same pass+salt+params produced different private keys")
	}
}

// TestSignVerifyRoundTrip: a seal produced by the derived sk verifies under the
// derived pk over the same body.
func TestSignVerifyRoundTrip(t *testing.T) {
	sk, pk := mustDerive(t, []byte("admin-pass"), fixedSalt(), lightParams)
	body := []byte(`{"version":1,"nonce":7,"messages":"allow"}`)
	sig := Sign(body, sk)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
	if !Verify(body, sig, pk) {
		t.Fatal("Verify returned false for a freshly signed body")
	}
}

// TestTamperFailsVerify: flipping any byte of the body invalidates the seal —
// editing policy.json on the volume must halt signing (§4.6 fail-closed).
func TestTamperFailsVerify(t *testing.T) {
	sk, pk := mustDerive(t, []byte("admin-pass"), fixedSalt(), lightParams)
	body := []byte(`{"version":1,"nonce":7,"max_tx_wei":"100"}`)
	sig := Sign(body, sk)

	// Flip a byte in the middle of the body.
	tampered := append([]byte(nil), body...)
	tampered[10] ^= 0x01
	if Verify(tampered, sig, pk) {
		t.Fatal("Verify accepted a tampered body")
	}

	// A truncated body (an attacker dropping a restriction field) must also fail.
	if Verify(body[:len(body)-1], sig, pk) {
		t.Fatal("Verify accepted a truncated body")
	}

	// A flipped signature byte must fail.
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0x80
	if Verify(body, badSig, pk) {
		t.Fatal("Verify accepted a tampered signature")
	}
}

// TestForgeResistance is the asymmetry proof: a key derived from a DIFFERENT
// admin passphrase cannot produce a seal that verifies under the original pinned
// key. This is the whole agent-safety story — a compromised agent that knows the
// public verify key (and even the salt + params, which live in plaintext in the
// anchor) still cannot forge a seal without the operator's passphrase.
func TestForgeResistance(t *testing.T) {
	salt := fixedSalt()
	_, pkOperator := mustDerive(t, []byte("operator-secret"), salt, lightParams)
	skAttacker, pkAttacker := mustDerive(t, []byte("attacker-guess"), salt, lightParams)

	if bytes.Equal(pkOperator, pkAttacker) {
		t.Fatal("different passphrases derived the same public key — KDF is broken")
	}

	body := []byte(`{"version":1,"nonce":999,"max_tx_wei":"99999999999999999999"}`)
	forgedSig := Sign(body, skAttacker) // attacker signs with its own derived key

	// The forged seal verifies under the attacker's own key (sanity)...
	if !Verify(body, forgedSig, pkAttacker) {
		t.Fatal("attacker's own seal should verify under the attacker's own key")
	}
	// ...but NOT under the operator's pinned key. This is the security boundary.
	if Verify(body, forgedSig, pkOperator) {
		t.Fatal("FORGE: an attacker-derived seal verified under the operator's pinned key")
	}
}

// TestWrongSaltDiffersKey: the salt is part of the derivation, so a different
// salt (e.g. a rotated anchor) yields a different key even for the same
// passphrase — the anti-rollback / rotation soundness depends on this.
func TestWrongSaltDiffersKey(t *testing.T) {
	pass := []byte("same-pass")
	_, pkA := mustDerive(t, pass, fixedSalt(), lightParams)
	otherSalt := fixedSalt()
	otherSalt[0] ^= 0xFF
	_, pkB := mustDerive(t, pass, otherSalt, lightParams)
	if bytes.Equal(pkA, pkB) {
		t.Fatal("different salts produced the same key")
	}
}

// TestEmptyPassphraseRefused: an empty admin passphrase must fail closed — it
// would derive a deterministic world-known keypair (no authentication at all).
func TestEmptyPassphraseRefused(t *testing.T) {
	if _, _, err := DeriveSealKey(nil, fixedSalt(), lightParams); err == nil {
		t.Fatal("DeriveSealKey accepted a nil passphrase")
	}
	if _, _, err := DeriveSealKey([]byte{}, fixedSalt(), lightParams); err == nil {
		t.Fatal("DeriveSealKey accepted an empty passphrase")
	}
}

// TestInvalidParamsRefused: a non-power-of-two N (or any invalid cost) fails
// closed in DeriveSealKey before reaching scrypt.
func TestInvalidParamsRefused(t *testing.T) {
	if _, _, err := DeriveSealKey([]byte("p"), fixedSalt(), ScryptParams{N: 17, R: 8, P: 1}); err == nil {
		t.Fatal("DeriveSealKey accepted a non-power-of-two N")
	}
}

// TestVerifyRejectsBadLengths: a corrupt anchor (short pk) or corrupt envelope
// (short sig) must verify false, never panic into the signing path.
func TestVerifyRejectsBadLengths(t *testing.T) {
	sk, pk := mustDerive(t, []byte("p"), fixedSalt(), lightParams)
	body := []byte("x")
	sig := Sign(body, sk)
	if Verify(body, sig, pk[:10]) {
		t.Fatal("Verify accepted a short public key")
	}
	if Verify(body, sig[:10], pk) {
		t.Fatal("Verify accepted a short signature")
	}
	if Verify(body, sig, nil) {
		t.Fatal("Verify accepted a nil public key")
	}
}

// TestGoldenVector pins a fixed (pass, salt, light-params) → (pk, sig) so a
// refactor that changes the KDF wiring (scrypt→HKDF→ed25519 order, the domain
// prefix, the seed info string) is caught even if round-trip tests still pass.
// The values were generated once from the canonical construction and frozen.
func TestGoldenVector(t *testing.T) {
	const (
		wantPK  = "ebc4dae47e44c91e144160b2cc712e1070efbc35664140918d78be5d68e4871e"
		wantSig = "599ff5a432475a443a60531c7046dca91e30967f0a59f105c76a54645b9053dd4b05e79107efa46e8674be4680793f157e3986a0fd70754c2c8fec1be9959808"
	)
	pass := []byte("correct horse battery staple")
	salt := fixedSalt()
	sk, pk := mustDerive(t, pass, salt, lightParams)

	if got := hex.EncodeToString(pk); got != wantPK {
		t.Fatalf("golden pk drift:\n got %s\nwant %s\n(the KDF wiring changed)", got, wantPK)
	}
	body := []byte(`{"version":1,"nonce":1}`)
	sig := Sign(body, sk)
	if got := hex.EncodeToString(sig); got != wantSig {
		t.Fatalf("golden sig drift:\n got %s\nwant %s\n(the seal domain or signing changed)", got, wantSig)
	}
}

// TestSealDomainIsLoadBearing: the domain prefix actually participates — a raw
// ed25519.Verify over the body WITHOUT the prefix must reject our seal. This pins
// that the seal subject is sealDomain||body, not bare body (a cross-protocol
// signature-reuse guard).
func TestSealDomainIsLoadBearing(t *testing.T) {
	sk, pk := mustDerive(t, []byte("p"), fixedSalt(), lightParams)
	body := []byte(`{"version":1}`)
	sig := Sign(body, sk)
	if ed25519.Verify(pk, body, sig) {
		t.Fatal("seal verified over bare body without the domain prefix — domain separation is not applied")
	}
}
