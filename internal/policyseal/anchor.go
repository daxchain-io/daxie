package policyseal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// Anchor is the config-class trust root (policy-anchor.json, design §4.6). It pins
// the verify key (the agent host can VERIFY but cannot FORGE), the scrypt salt and
// params (independent of the keystore KDF, §3.4), and the monotonic anti-rollback
// nonce watermark. verify_key_next carries the staged, zero-outage rotation key.
//
// It is read DIRECTLY by internal/config — never via a Viper key, env var, or
// flag (§4.6: an env-settable verify key would let any agent pair a self-forged
// policy.json with a key it generated, "verify" it, and sign anything). config
// hands the raw bytes to ParseAnchor for the typed decode, keeping config free of
// the policyseal import.
//
// Keys are encoded "ed25519:base64(32B)"; salts as bare base64(32B). The
// nonce_watermark is a JSON number that MUST round-trip exactly: it is decoded as
// a uint64 (not float64) via the strict decoder, and emitted by the hand-built
// canonical marshaler as a plain integer.
type Anchor struct {
	VerifyKey      string       `json:"verify_key"`            // "ed25519:base64(32B)"
	VerifyKeyNext  string       `json:"verify_key_next"`       // staged-rotation key; "" / null when none
	Salt           string       `json:"salt"`                  // base64(32B)
	Scrypt         ScryptParams `json:"scrypt"`                // §3.4 admin KDF cost
	NonceWatermark uint64       `json:"nonce_watermark"`       // monotonic anti-rollback floor
	StagedSalt     string       `json:"staged_salt,omitempty"` // set by --stage, cleared by --commit
}

// keyPrefix is the algorithm tag on a serialized verify key.
const keyPrefix = "ed25519:"

var (
	// ErrAnchorMalformed is returned by ParseAnchor when the JSON is structurally
	// invalid or carries unknown fields (the anchor is machine-managed; an unknown
	// field is a version/tamper signal, not a forward-compatible extension).
	ErrAnchorMalformed = errors.New("policyseal: malformed anchor")
	// ErrKeyMalformed is returned by the key decoders when a verify key is not a
	// well-formed "ed25519:base64(32B)" string.
	ErrKeyMalformed = errors.New("policyseal: malformed verify key")
	// ErrSaltMalformed is returned by SaltBytes when the salt is not valid base64.
	ErrSaltMalformed = errors.New("policyseal: malformed salt")
)

// anchorWire mirrors Anchor but makes verify_key_next a *string so the loader can
// distinguish JSON null / absent (no staged key) from "" (also no staged key) on
// decode. Decode is strict (DisallowUnknownFields): the anchor is not a
// version-skew surface like the sealed body — it is regenerated wholesale by every
// mutation, so an unknown field is a hard refusal.
type anchorWire struct {
	VerifyKey      string       `json:"verify_key"`
	VerifyKeyNext  *string      `json:"verify_key_next"`
	Salt           string       `json:"salt"`
	Scrypt         ScryptParams `json:"scrypt"`
	NonceWatermark uint64       `json:"nonce_watermark"`
	StagedSalt     string       `json:"staged_salt,omitempty"`
}

// ParseAnchor strictly decodes the anchor JSON. A missing verify_key, missing
// salt, or zero/invalid scrypt cost is a refusal — a structurally incomplete
// anchor is no trust root at all and must fail closed rather than silently
// verifying nothing.
func ParseAnchor(b []byte) (Anchor, error) {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var w anchorWire
	if err := dec.Decode(&w); err != nil {
		return Anchor{}, ErrAnchorMalformed
	}
	// Reject trailing garbage after the object (a single JSON value is expected).
	if dec.More() {
		return Anchor{}, ErrAnchorMalformed
	}
	a := Anchor{
		VerifyKey:      w.VerifyKey,
		Salt:           w.Salt,
		Scrypt:         w.Scrypt,
		NonceWatermark: w.NonceWatermark,
		StagedSalt:     w.StagedSalt,
	}
	if w.VerifyKeyNext != nil {
		a.VerifyKeyNext = *w.VerifyKeyNext
	}
	if a.VerifyKey == "" || a.Salt == "" || !a.Scrypt.Valid() {
		return Anchor{}, ErrAnchorMalformed
	}
	// Fail closed on a structurally bad verify key now, not at signing time.
	if _, err := decodeKey(a.VerifyKey); err != nil {
		return Anchor{}, ErrKeyMalformed
	}
	if a.VerifyKeyNext != "" {
		if _, err := decodeKey(a.VerifyKeyNext); err != nil {
			return Anchor{}, ErrKeyMalformed
		}
	}
	if _, err := base64.StdEncoding.DecodeString(a.Salt); err != nil {
		return Anchor{}, ErrSaltMalformed
	}
	if a.StagedSalt != "" {
		if _, err := base64.StdEncoding.DecodeString(a.StagedSalt); err != nil {
			return Anchor{}, ErrSaltMalformed
		}
	}
	return a, nil
}

// Marshal renders the anchor as canonical ordered JSON for fsx.WriteAtomic. The
// key order is fixed (verify_key, verify_key_next, salt, scrypt{n,r,p},
// nonce_watermark, [staged_salt]); verify_key_next is emitted as JSON null when
// empty (matching the §4.6 example) and staged_salt is omitted when empty. The
// watermark is emitted as a plain integer (never a float). Two anchors with the
// same field values marshal to byte-identical output — a reproducibility/diff
// convenience; the anchor's integrity comes from the config-class mount + the
// Viper carve-out, not from a seal over itself.
func (a Anchor) Marshal() ([]byte, error) {
	if a.VerifyKey == "" || a.Salt == "" || !a.Scrypt.Valid() {
		return nil, errors.New("policyseal: refusing to marshal an incomplete anchor")
	}
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString("  \"verify_key\": ")
	b.WriteString(jsonString(a.VerifyKey))
	b.WriteString(",\n")

	b.WriteString("  \"verify_key_next\": ")
	if a.VerifyKeyNext == "" {
		b.WriteString("null")
	} else {
		b.WriteString(jsonString(a.VerifyKeyNext))
	}
	b.WriteString(",\n")

	b.WriteString("  \"salt\": ")
	b.WriteString(jsonString(a.Salt))
	b.WriteString(",\n")

	b.WriteString("  \"scrypt\": { \"n\": ")
	b.WriteString(strconv.Itoa(a.Scrypt.N))
	b.WriteString(", \"r\": ")
	b.WriteString(strconv.Itoa(a.Scrypt.R))
	b.WriteString(", \"p\": ")
	b.WriteString(strconv.Itoa(a.Scrypt.P))
	b.WriteString(" },\n")

	b.WriteString("  \"nonce_watermark\": ")
	b.WriteString(strconv.FormatUint(a.NonceWatermark, 10))

	if a.StagedSalt != "" {
		b.WriteString(",\n  \"staged_salt\": ")
		b.WriteString(jsonString(a.StagedSalt))
	}
	b.WriteString("\n}\n")
	return []byte(b.String()), nil
}

// VerifyKeyBytes decodes the pinned current verify key to its 32 raw bytes.
func (a Anchor) VerifyKeyBytes() (ed25519.PublicKey, error) {
	return decodeKey(a.VerifyKey)
}

// VerifyKeyNextBytes decodes the staged-rotation verify key. The bool reports
// whether a staged key is present; when false the key bytes are nil and err is
// nil (an absent staged key is not an error). A present-but-malformed staged key
// is a hard error.
func (a Anchor) VerifyKeyNextBytes() (ed25519.PublicKey, bool, error) {
	if a.VerifyKeyNext == "" {
		return nil, false, nil
	}
	k, err := decodeKey(a.VerifyKeyNext)
	if err != nil {
		return nil, true, err
	}
	return k, true, nil
}

// SaltBytes decodes the base64 admin scrypt salt.
func (a Anchor) SaltBytes() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(a.Salt)
	if err != nil {
		return nil, ErrSaltMalformed
	}
	return b, nil
}

// StagedSaltBytes decodes the base64 staged-rotation salt. The bool reports
// whether a staged salt is present.
func (a Anchor) StagedSaltBytes() ([]byte, bool, error) {
	if a.StagedSalt == "" {
		return nil, false, nil
	}
	b, err := base64.StdEncoding.DecodeString(a.StagedSalt)
	if err != nil {
		return nil, true, ErrSaltMalformed
	}
	return b, true, nil
}

// EncodeKey renders an ed25519 public key as "ed25519:base64(32B)".
func EncodeKey(pk ed25519.PublicKey) string {
	return keyPrefix + base64.StdEncoding.EncodeToString(pk)
}

// EncodeSalt renders a salt as bare base64.
func EncodeSalt(salt []byte) string {
	return base64.StdEncoding.EncodeToString(salt)
}

// decodeKey parses the "ed25519:base64(32B)" verify-key form into raw bytes,
// enforcing the prefix and the exact 32-byte length.
func decodeKey(s string) (ed25519.PublicKey, error) {
	rest, ok := strings.CutPrefix(s, keyPrefix)
	if !ok {
		return nil, ErrKeyMalformed
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, ErrKeyMalformed
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, ErrKeyMalformed
	}
	return ed25519.PublicKey(raw), nil
}

// saltSize is the §3.4/§4.6 admin scrypt salt length: 32 random bytes.
const saltSize = 32

// NewSalt returns 32 cryptographically random bytes for a fresh anchor or a
// staged rotation. The provider leaf that bootstraps or rotates an anchor uses
// it; the pure pipeline never calls it.
func NewSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// jsonString encodes s as a JSON string. The values we emit (base64 alphabet +
// the "ed25519:" prefix) contain no characters needing escaping, but routing
// through strconv.Quote keeps the output strictly valid for any future value and
// avoids encoding/json's HTML escaping of '<','>','&'.
func jsonString(s string) string {
	return strconv.Quote(s)
}
