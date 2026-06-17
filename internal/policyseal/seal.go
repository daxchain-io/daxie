package policyseal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// sealDomain is the domain-separation prefix prepended to the stored policy body
// bytes before signing and verifying (design §4.5). The seal covers EXACTLY
//
//	sealDomain || base64decode(envelope.body_b64)
//
// — never a re-marshaled projection of the policy struct, so a binary of any
// version verifies a file written by any other and unknown fields can never
// produce a false seal failure. The trailing newline is part of the constant.
const sealDomain = "daxie/policy/v1\n"

// seedInfo domain-separates the HKDF-SHA256 expansion that turns the scrypt root
// into the Ed25519 seed (design §4.5). It is distinct from the keystore key
// derivation so the two KDFs can never collide on output even if (impossibly)
// the same passphrase and salt were used for both.
const seedInfo = "daxie/policy/sig-seed/v1"

// ScryptParams are the §3.4 admin-KDF cost parameters. They are INDEPENDENT of
// the keystore KDF — distinct salt (in the anchor, not the keystore manifest)
// and distinct N — so an agent holding the keystore secret or its derived key
// gains nothing toward forging a seal. The canonical defaults are N=2^17, r=8,
// p=1, dkLen fixed at 32 (the ed25519 seed size).
//
// The JSON tags match the anchor's "scrypt" object (§4.6).
type ScryptParams struct {
	N int `json:"n"`
	R int `json:"r"`
	P int `json:"p"`
}

// scryptDKLen is the scrypt output length: 32 bytes, fed as IKM into HKDF. It is
// fixed (not a tunable) because the downstream consumer is a fixed-width HKDF
// extract; only N/r/p are recorded in the anchor.
const scryptDKLen = 32

// DefaultScryptParams returns the canonical §3.4 admin-KDF cost: N=2^17, r=8,
// p=1. The first `policy set` bootstraps an anchor with exactly these.
func DefaultScryptParams() ScryptParams { return ScryptParams{N: 1 << 17, R: 8, P: 1} }

// Valid reports whether p is a usable scrypt cost. scrypt.Key itself rejects a
// non-power-of-two N, N<2, r<1, p<1, and r*p overflow; Valid is a cheap
// pre-check so callers can return policy.state_error / admin_auth deterministically
// rather than surfacing the library's error text.
func (p ScryptParams) Valid() bool {
	if p.N < 2 || p.R < 1 || p.P < 1 {
		return false
	}
	// N must be a power of two (scrypt requirement).
	return p.N&(p.N-1) == 0
}

// errEmptyPassphrase guards DeriveSealKey: an empty admin passphrase would derive
// a deterministic, world-known keypair (scrypt of "" is a fixed value), which is
// no authentication at all. The acquisition layer (internal/secret) already
// refuses an empty secret, but DeriveSealKey is the security boundary and must
// fail closed regardless of caller.
var errEmptyPassphrase = errors.New("policyseal: empty admin passphrase")

// DeriveSealKey runs scrypt → HKDF-SHA256 → ed25519.NewKeyFromSeed to produce the
// seal keypair from the admin passphrase (design §4.5 seal construction):
//
//	K_master = scrypt(adminPass, salt, N, r, p, dkLen=32)
//	K_seed   = HKDF-SHA256(K_master, info="daxie/policy/sig-seed/v1", L=32)
//	(sk, pk) = ed25519.NewKeyFromSeed(K_seed)
//
// adminPass is the REVEALED passphrase bytes (the caller holds the secret.Bytes
// and passes adminPass.Reveal(); see the package doc on why this package does not
// import secret). adminPass is read but never retained, never copied into an
// error, never logged. The scrypt root and the HKDF seed are zeroed before
// return — only the (sk, pk) pair escapes. The returned sk is itself sensitive:
// the single caller (policy admin mutations) zeroes it after signing.
//
// Deterministic: the same (adminPass, salt, params) always yields the same
// keypair — that determinism is exactly what lets a re-supplied admin passphrase
// re-derive the pinned verify key and authenticate a mutation without any stored
// verifier blob.
func DeriveSealKey(adminPass, salt []byte, p ScryptParams) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if len(adminPass) == 0 {
		return nil, nil, errEmptyPassphrase
	}
	if !p.Valid() {
		return nil, nil, errors.New("policyseal: invalid scrypt params")
	}
	kMaster, err := scrypt.Key(adminPass, salt, p.N, p.R, p.P, scryptDKLen)
	if err != nil {
		// Do not wrap: scrypt's error text never contains the passphrase, but we
		// keep the surface minimal and deterministic.
		return nil, nil, errors.New("policyseal: scrypt derivation failed")
	}
	defer zero(kMaster)

	seed := make([]byte, ed25519.SeedSize) // 32
	if _, err := io.ReadFull(hkdf.New(sha256.New, kMaster, nil, []byte(seedInfo)), seed); err != nil {
		zero(seed)
		return nil, nil, errors.New("policyseal: hkdf expansion failed")
	}
	defer zero(seed)

	sk := ed25519.NewKeyFromSeed(seed)
	pk := sk.Public().(ed25519.PublicKey)
	return sk, pk, nil
}

// Sign produces the detached 64-byte Ed25519 signature over sealDomain || body
// (design §4.5). body is the EXACT stored policy body bytes (the same bytes the
// envelope stores in body_b64); the domain prefix is applied here, never stored.
func Sign(body []byte, sk ed25519.PrivateKey) []byte {
	return ed25519.Sign(sk, signSubject(body))
}

// Verify checks a detached signature over sealDomain || body against pk. It is the
// ONLY check the agent-facing process performs on every signing op, and it is
// asymmetric from forging: the agent has pk, never sk. A wrong-length pk or sig
// is a hard false (never a panic into the signing path), so a corrupt anchor or
// envelope fails closed.
func Verify(body, sig []byte, pk ed25519.PublicKey) bool {
	if len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pk, signSubject(body), sig)
}

// signSubject builds sealDomain || body without aliasing the caller's body slice
// (a bare append(prefix, body...) onto a prefix []byte allocates fresh, but we
// size it exactly to avoid a second growth and to make the construction obvious).
func signSubject(body []byte) []byte {
	subject := make([]byte, len(sealDomain)+len(body))
	n := copy(subject, sealDomain)
	copy(subject[n:], body)
	return subject
}

// zero overwrites a byte slice with zeros. Used on every intermediate key buffer
// before it leaves scope; defense in depth alongside the caller zeroing sk.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
