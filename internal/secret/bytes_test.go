package secret

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBytesRevealLen(t *testing.T) {
	b := NewString("hunter2")
	if b.Len() != 7 {
		t.Fatalf("Len() = %d, want 7", b.Len())
	}
	if string(b.Reveal()) != "hunter2" {
		t.Fatalf("Reveal() = %q, want hunter2", b.Reveal())
	}
}

func TestBytesNewTakesOwnership(t *testing.T) {
	src := []byte("secret")
	b := New(src)
	if string(b.Reveal()) != "secret" {
		t.Fatalf("Reveal() = %q", b.Reveal())
	}
	// Zero wipes the original backing array since New took ownership.
	b.Zero()
	for i, c := range src {
		if c != 0 {
			t.Fatalf("byte %d not zeroed after Zero(): %d", i, c)
		}
	}
}

func TestBytesZeroIdempotentAndWipes(t *testing.T) {
	b := NewString("topsecret")
	raw := b.Reveal()
	b.Zero()
	// After Zero, the buffer reports empty and the old slice is wiped.
	if b.Len() != 0 {
		t.Errorf("Len() after Zero = %d, want 0", b.Len())
	}
	if b.Reveal() != nil {
		t.Errorf("Reveal() after Zero = %v, want nil", b.Reveal())
	}
	for i, c := range raw {
		if c != 0 {
			t.Errorf("backing byte %d = %d after Zero, want 0", i, c)
		}
	}
	// Idempotent: a second Zero must not panic.
	b.Zero()
}

func TestBytesNilReceiver(t *testing.T) {
	var b *Bytes
	if b.Len() != 0 {
		t.Errorf("nil Len() = %d, want 0", b.Len())
	}
	if b.Reveal() != nil {
		t.Errorf("nil Reveal() != nil")
	}
	b.Zero() // must not panic
	if !strings.Contains(b.String(), "redacted") {
		t.Errorf("nil String() = %q, want redaction", b.String())
	}
}

func TestStringRedacts(t *testing.T) {
	b := NewString("super-secret-passphrase")
	s := b.String()
	if strings.Contains(s, "super-secret-passphrase") {
		t.Fatalf("String() leaked the secret: %q", s)
	}
	if !strings.Contains(s, "redacted") {
		t.Fatalf("String() = %q, want a redaction marker", s)
	}
	// Length is exposed in the human string (shape, not content).
	if !strings.Contains(s, "len=23") {
		t.Errorf("String() = %q, want len=23", s)
	}
}

// TestMarshalJSONMethodLiteral asserts the §2.8 method contract directly: the
// MarshalJSON method returns the exact literal "\"<redacted>\"". (json.Marshal
// applied to the value re-escapes "<"/">" to </> per encoding/json's
// default HTML escaping — that is the encoder's behavior, not the method's.)
func TestMarshalJSONMethodLiteral(t *testing.T) {
	b := NewString("super-secret")
	out, err := b.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if string(out) != `"<redacted>"` {
		t.Fatalf("MarshalJSON() = %s, want \"<redacted>\"", out)
	}
}

func TestMarshalJSONRedacts(t *testing.T) {
	b := NewString("super-secret")
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// The secret must never appear in the output regardless of HTML escaping.
	if strings.Contains(string(out), "super-secret") {
		t.Fatalf("MarshalJSON leaked the secret: %s", out)
	}
	// It must decode back to the redaction placeholder (escaping is transparent
	// to a JSON decoder).
	var s string
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if s != "<redacted>" {
		t.Fatalf("decoded = %q, want <redacted>", s)
	}
}

func TestMarshalJSONInStruct(t *testing.T) {
	type holder struct {
		Name string `json:"name"`
		Pass *Bytes `json:"pass"`
	}
	out, err := json.Marshal(holder{Name: "alice", Pass: NewString("pw")})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(out), `"pw"`) || strings.Contains(string(out), "pw\"") {
		t.Fatalf("struct marshal leaked the secret: %s", out)
	}
	// Round-trip the pass field back through a decoder to confirm it is the
	// redaction placeholder, independent of HTML escaping.
	var decoded struct {
		Name string `json:"name"`
		Pass string `json:"pass"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Name != "alice" || decoded.Pass != "<redacted>" {
		t.Fatalf("decoded = %+v, want {alice <redacted>}", decoded)
	}
}

func TestEmptyBytes(t *testing.T) {
	b := New(nil)
	if b.Len() != 0 {
		t.Errorf("empty Len() = %d", b.Len())
	}
	b.Zero() // no-op, no panic
}
