// Package policyseal is the asymmetric trust primitive under the M4 guardrail
// engine (design §4.5/§4.6/§3.4). It derives an Ed25519 seal keypair from the
// admin passphrase (scrypt → HKDF-SHA256 → ed25519 seed), produces and verifies
// the detached signature over the sealed policy body bytes, (de)serializes the
// config-class trust root (policy-anchor.json), and runs the staged,
// zero-outage admin-passphrase rotation.
//
// THE ONE INVARIANT THE WHOLE AGENT-SAFETY STORY RESTS ON (design §4.5, L7):
// the seal is an ASYMMETRIC Ed25519 SIGNATURE, never a symmetric MAC. The
// agent-facing host holds only the pinned PUBLIC verify key, so it can VERIFY a
// seal on every signing op but CANNOT FORGE one — forging needs the private key,
// which only the operator can re-derive from the admin passphrase. A symmetric
// MAC is WRONG and FORBIDDEN here: any MAC key the host can read to verify with
// is a key a compromised agent can re-seal with, which collapses verify and
// forge into the same capability. There is exactly ONE primitive over the bytes.
//
// THE SECOND INVARIANT (design §3.4): the admin KDF is INDEPENDENT of the
// keystore KDF — a distinct salt and distinct scrypt params (N=2^17, r=8, p=1)
// live in the anchor, not the keystore manifest. An agent that holds the
// keystore passphrase or its derived key gains NOTHING toward forging a seal.
//
// Architectural note: this package is a provider leaf. It deliberately does NOT
// import internal/secret — the arch matrix (internal/arch_test.go) does not
// sanction a policyseal→secret edge, and the seal primitive is naturally
// body-agnostic and key-material-agnostic. DeriveSealKey therefore takes the
// REVEALED passphrase bytes ([]byte), and the single caller that holds the
// secret.Bytes (internal/policy, which IS sanctioned to import secret) passes
// adminPass.Reveal(). The revealed slice is read but never retained, copied into
// an error, or logged; intermediate key material derived here (the scrypt root
// and the HKDF seed) is zeroed before return.
//
// Pure-Go throughout: golang.org/x/crypto/{scrypt,hkdf}, crypto/ed25519,
// crypto/rand, crypto/sha256 — no CGO, so the CGO_ENABLED=0 ship build is clean.
package policyseal
