package policyseal

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

func sampleAnchorJSON() string {
	return `{
  "verify_key": "ed25519:6sTa5H5EyR4UQWCyzHEuEHDvvDVmQUCRjXi+XWjkhx4=",
  "verify_key_next": null,
  "salt": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
  "scrypt": { "n": 16, "r": 8, "p": 1 },
  "nonce_watermark": 12
}
`
}

func TestParseAnchorRoundTrip(t *testing.T) {
	a, err := ParseAnchor([]byte(sampleAnchorJSON()))
	if err != nil {
		t.Fatalf("ParseAnchor: %v", err)
	}
	if a.NonceWatermark != 12 {
		t.Fatalf("watermark = %d, want 12", a.NonceWatermark)
	}
	if a.Scrypt.N != 16 || a.Scrypt.R != 8 || a.Scrypt.P != 1 {
		t.Fatalf("scrypt = %+v", a.Scrypt)
	}
	if a.VerifyKeyNext != "" {
		t.Fatalf("verify_key_next should be empty for JSON null, got %q", a.VerifyKeyNext)
	}
	pk, err := a.VerifyKeyBytes()
	if err != nil {
		t.Fatalf("VerifyKeyBytes: %v", err)
	}
	if len(pk) != ed25519.PublicKeySize {
		t.Fatalf("verify key length = %d, want %d", len(pk), ed25519.PublicKeySize)
	}
	salt, err := a.SaltBytes()
	if err != nil {
		t.Fatalf("SaltBytes: %v", err)
	}
	if len(salt) != 32 {
		t.Fatalf("salt length = %d, want 32", len(salt))
	}
}

// TestMarshalParseStable: Marshal then ParseAnchor reproduces the same struct,
// and Marshal is byte-stable (same struct → identical bytes).
func TestMarshalParseStable(t *testing.T) {
	a, err := ParseAnchor([]byte(sampleAnchorJSON()))
	if err != nil {
		t.Fatalf("ParseAnchor: %v", err)
	}
	b1, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	b2, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal (2nd): %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("Marshal is not byte-stable")
	}
	a2, err := ParseAnchor(b1)
	if err != nil {
		t.Fatalf("re-ParseAnchor: %v", err)
	}
	r1, _ := a.Marshal()
	r2, _ := a2.Marshal()
	if !bytes.Equal(r1, r2) {
		t.Fatal("round-trip through Marshal/Parse changed the anchor")
	}
}

// TestMarshalEmitsNullNext: when there is no staged key, verify_key_next is the
// JSON literal null (matching the §4.6 example), and staged_salt is omitted.
func TestMarshalEmitsNullNext(t *testing.T) {
	a, _ := ParseAnchor([]byte(sampleAnchorJSON()))
	b, _ := a.Marshal()
	s := string(b)
	if !strings.Contains(s, `"verify_key_next": null`) {
		t.Fatalf("expected verify_key_next: null, got:\n%s", s)
	}
	if strings.Contains(s, "staged_salt") {
		t.Fatalf("staged_salt should be omitted when empty, got:\n%s", s)
	}
}

// TestMarshalEmitsStagedSalt: when a staged rotation is recorded, both
// verify_key_next and staged_salt appear.
func TestMarshalEmitsStagedSalt(t *testing.T) {
	a, _ := ParseAnchor([]byte(sampleAnchorJSON()))
	a.VerifyKeyNext = "ed25519:6sTa5H5EyR4UQWCyzHEuEHDvvDVmQUCRjXi+XWjkhx4="
	a.StagedSalt = "EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8="
	b, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(b)
	if strings.Contains(s, `"verify_key_next": null`) {
		t.Fatal("verify_key_next should carry the staged key, not null")
	}
	if !strings.Contains(s, "staged_salt") {
		t.Fatal("staged_salt should be present")
	}
	a2, err := ParseAnchor(b)
	if err != nil {
		t.Fatalf("re-parse with staged: %v", err)
	}
	if a2.VerifyKeyNext != a.VerifyKeyNext || a2.StagedSalt != a.StagedSalt {
		t.Fatal("staged fields did not round-trip")
	}
}

// TestParseAnchorRejectsUnknownField: the anchor is machine-managed; an unknown
// field is a tamper/version signal and a hard refusal (DisallowUnknownFields).
func TestParseAnchorRejectsUnknownField(t *testing.T) {
	bad := `{"verify_key":"ed25519:6sTa5H5EyR4UQWCyzHEuEHDvvDVmQUCRjXi+XWjkhx4=","salt":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","scrypt":{"n":16,"r":8,"p":1},"nonce_watermark":1,"injected_key":"oops"}`
	if _, err := ParseAnchor([]byte(bad)); err == nil {
		t.Fatal("ParseAnchor accepted an unknown field")
	}
}

// TestParseAnchorRejectsIncomplete: missing verify_key / salt / scrypt all fail
// closed — a structurally incomplete anchor is no trust root.
func TestParseAnchorRejectsIncomplete(t *testing.T) {
	cases := map[string]string{
		"no verify_key": `{"salt":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","scrypt":{"n":16,"r":8,"p":1},"nonce_watermark":1}`,
		"no salt":       `{"verify_key":"ed25519:6sTa5H5EyR4UQWCyzHEuEHDvvDVmQUCRjXi+XWjkhx4=","scrypt":{"n":16,"r":8,"p":1},"nonce_watermark":1}`,
		"bad scrypt N":  `{"verify_key":"ed25519:6sTa5H5EyR4UQWCyzHEuEHDvvDVmQUCRjXi+XWjkhx4=","salt":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","scrypt":{"n":17,"r":8,"p":1},"nonce_watermark":1}`,
		"bad key form":  `{"verify_key":"notakey","salt":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","scrypt":{"n":16,"r":8,"p":1},"nonce_watermark":1}`,
		"empty":         `{}`,
		"garbage":       `not json`,
	}
	for name, js := range cases {
		if _, err := ParseAnchor([]byte(js)); err == nil {
			t.Errorf("%s: ParseAnchor accepted an invalid anchor", name)
		}
	}
}

// TestMarshalRefusesIncomplete: Marshal will not write a half-built anchor.
func TestMarshalRefusesIncomplete(t *testing.T) {
	if _, err := (Anchor{}).Marshal(); err == nil {
		t.Fatal("Marshal accepted an empty anchor")
	}
}

// TestEncodeDecodeKeyRoundTrip: EncodeKey / decodeKey are inverse.
func TestEncodeDecodeKeyRoundTrip(t *testing.T) {
	_, pk := mustDerive(t, []byte("p"), fixedSalt(), lightParams)
	enc := EncodeKey(pk)
	if !strings.HasPrefix(enc, "ed25519:") {
		t.Fatalf("EncodeKey missing prefix: %s", enc)
	}
	a := Anchor{VerifyKey: enc, Salt: EncodeSalt(fixedSalt()), Scrypt: lightParams}
	got, err := a.VerifyKeyBytes()
	if err != nil {
		t.Fatalf("VerifyKeyBytes: %v", err)
	}
	if !bytes.Equal(got, pk) {
		t.Fatal("key did not round-trip through EncodeKey/VerifyKeyBytes")
	}
}

func TestNewSaltLength(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	if len(salt) != 32 {
		t.Fatalf("NewSalt length = %d, want 32", len(salt))
	}
	salt2, _ := NewSalt()
	if bytes.Equal(salt, salt2) {
		t.Fatal("NewSalt returned identical salts (not random)")
	}
}
