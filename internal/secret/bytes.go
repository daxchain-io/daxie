// Package secret holds the zeroing, redacting secret buffer (secret.Bytes) and
// the §3.6 secret-acquisition resolver (stdin > file > *_FILE-env > env > TTY
// prompt > deterministic error). The buffer redacts on String()/MarshalJSON()
// and best-effort mlocks its backing memory; the resolver is generic over the
// flag/env names so the keystore, admin, and mnemonic inputs reuse it (§3.7).
//
// secret is a provider (a leaf): it imports domain for typed errors and nothing
// in service or a frontend. The §2.3 determinism guard does not apply here.
package secret

// redactedPlaceholder is what MarshalJSON emits — a fixed string, never the
// length, so a marshaled struct containing a *Bytes leaks nothing.
const redactedPlaceholder = "<redacted>"

// Bytes is a secret buffer. The raw value is reachable only via Reveal(); every
// other accessor (String, MarshalJSON) returns a redaction placeholder. On
// construction it best-effort locks its backing memory into RAM (mlock /
// VirtualLock); Zero() wipes and unlocks and is idempotent.
//
// A nil *Bytes is a valid empty secret: Len()==0, Reveal()==nil, String()
// redacts, Zero() is a no-op.
type Bytes struct {
	b      []byte
	locked bool // whether memlock succeeded (so Zero unlocks symmetrically)
	zeroed bool
}

// New takes ownership of b (the caller must not retain or mutate it afterwards)
// and best-effort locks it into RAM. Pass a copy if the source slice is reused.
func New(b []byte) *Bytes {
	s := &Bytes{b: b}
	if len(b) > 0 {
		s.locked = memlock(b)
	}
	return s
}

// NewString copies s into a fresh buffer and takes ownership of the copy. The
// original string cannot be wiped (Go strings are immutable), so callers holding
// a sensitive string should prefer New over a []byte they control.
func NewString(s string) *Bytes {
	return New([]byte(s))
}

// Reveal returns the raw secret bytes. The caller MUST NOT retain the slice
// beyond immediate use and must not append to it. Returns nil for a nil or
// zeroed buffer.
func (b *Bytes) Reveal() []byte {
	if b == nil || b.zeroed {
		return nil
	}
	return b.b
}

// Len returns the secret length in bytes (0 for nil/zeroed).
func (b *Bytes) Len() int {
	if b == nil || b.zeroed {
		return 0
	}
	return len(b.b)
}

// Zero wipes the backing memory (overwrite with zeros) and unlocks it. It is
// idempotent and safe on a nil receiver.
func (b *Bytes) Zero() {
	if b == nil || b.zeroed {
		return
	}
	for i := range b.b {
		b.b[i] = 0
	}
	if b.locked {
		memunlock(b.b)
		b.locked = false
	}
	b.b = nil
	b.zeroed = true
}

// String returns a redaction placeholder including the length, so a debug print
// reveals shape but never content: "secret.Bytes(<redacted len=N>)".
func (b *Bytes) String() string {
	n := 0
	if b != nil && !b.zeroed {
		n = len(b.b)
	}
	return "secret.Bytes(<redacted len=" + itoa(n) + ">)"
}

// GoString mirrors String so %#v also redacts.
func (b *Bytes) GoString() string { return b.String() }

// MarshalJSON emits the constant placeholder "<redacted>" so a struct embedding
// a *Bytes never serializes the secret (the length is deliberately omitted from
// the JSON form). We return the bytes directly rather than via json.Marshal
// because encoding/json HTML-escapes the angle brackets ("<redacted>");
// the placeholder is a fixed, JSON-safe literal so emitting it verbatim is exact
// and the §2.8 contract requires the literal "<redacted>".
func (b *Bytes) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedPlaceholder + `"`), nil
}

// itoa is a tiny non-allocating-ish integer formatter to avoid pulling strconv
// into the redaction path (keeps the surface minimal).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
