package journal

import (
	"crypto/rand"
	"io"
	"time"
)

// ── ULID generation (the ONE entropy site in this package) ──────────────────────
//
// A ULID (§5.6) is a 128-bit value: a 48-bit big-endian millisecond Unix timestamp
// followed by 80 bits of randomness, rendered as a 26-character Crockford base32
// string (lexicographically sortable, so a string sort on `id` is a time sort).
//
// The journal is a provider (NOT guarded by the determinism test, which scans only
// service + domain), so crypto/rand and time are allowed here. We implement ULID
// in-package rather than pulling in oklog/ulid: the encoding is fully specified and
// tiny, and keeping it local keeps the journal's dependency surface to fsx + secret
// + domain + the go-ethereum value types only.

// crockford is Crockford's base32 alphabet (no I, L, O, U) used by the ULID spec.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ulidLen is the canonical ULID string length (10 timestamp chars + 16 random
// chars). 26 base32 symbols carry 130 bits; the high two bits of the first symbol
// are always zero (a 48-bit timestamp uses 50 bits of the leading 10-symbol field).
const ulidLen = 26

// randReader is the entropy source, swappable in tests so ID generation can be made
// deterministic without touching the rest of the package. Defaults to crypto/rand.
var randReader io.Reader = rand.Reader

// nowFn is the wall-clock source for the timestamp half. Production passes the
// service's injected clock through Record.TS for the record's `ts`; the ULID's own
// 48-bit timestamp uses this, swappable in tests. It is NOT the record timestamp —
// it only orders IDs — so a provider-local time read here is acceptable.
var nowFn = time.Now

// newULID returns a fresh ULID string (§5.6). The timestamp is the current Unix
// time in milliseconds; the 80-bit suffix is crypto-random. A read failure from the
// entropy source returns the error so the caller can fail the append rather than
// emit a low-entropy id.
func newULID() (string, error) {
	return newULIDAt(nowFn())
}

// newULIDAt is newULID with an explicit time, used by tests to pin the timestamp
// half deterministically.
func newULIDAt(t time.Time) (string, error) {
	ms := uint64(t.UnixMilli())

	// 16 bytes: 6 timestamp bytes (48 bits) + 10 random bytes (80 bits). The
	// explicit & 0xFF masks make the byte truncation intentional (silences gosec
	// G115; taking the low 8 bits of each shifted group is the ULID encoding).
	var b [16]byte
	b[0] = byte((ms >> 40) & 0xFF)
	b[1] = byte((ms >> 32) & 0xFF)
	b[2] = byte((ms >> 24) & 0xFF)
	b[3] = byte((ms >> 16) & 0xFF)
	b[4] = byte((ms >> 8) & 0xFF)
	b[5] = byte(ms & 0xFF)
	if _, err := io.ReadFull(randReader, b[6:]); err != nil {
		return "", err
	}

	return encodeULID(b), nil
}

// encodeULID renders the 16-byte ULID value as 26 Crockford base32 symbols. The
// standard ULID layout packs the 128 bits into 26 5-bit groups (the first group
// carries only 3 significant bits). This is the canonical reference encoding.
func encodeULID(b [16]byte) string {
	var dst [ulidLen]byte

	// Timestamp: 48 bits -> 10 symbols.
	dst[0] = crockford[(b[0]&0xE0)>>5]
	dst[1] = crockford[b[0]&0x1F]
	dst[2] = crockford[(b[1]&0xF8)>>3]
	dst[3] = crockford[((b[1]&0x07)<<2)|((b[2]&0xC0)>>6)]
	dst[4] = crockford[(b[2]&0x3E)>>1]
	dst[5] = crockford[((b[2]&0x01)<<4)|((b[3]&0xF0)>>4)]
	dst[6] = crockford[((b[3]&0x0F)<<1)|((b[4]&0x80)>>7)]
	dst[7] = crockford[(b[4]&0x7C)>>2]
	dst[8] = crockford[((b[4]&0x03)<<3)|((b[5]&0xE0)>>5)]
	dst[9] = crockford[b[5]&0x1F]

	// Entropy: 80 bits -> 16 symbols.
	dst[10] = crockford[(b[6]&0xF8)>>3]
	dst[11] = crockford[((b[6]&0x07)<<2)|((b[7]&0xC0)>>6)]
	dst[12] = crockford[(b[7]&0x3E)>>1]
	dst[13] = crockford[((b[7]&0x01)<<4)|((b[8]&0xF0)>>4)]
	dst[14] = crockford[((b[8]&0x0F)<<1)|((b[9]&0x80)>>7)]
	dst[15] = crockford[(b[9]&0x7C)>>2]
	dst[16] = crockford[((b[9]&0x03)<<3)|((b[10]&0xE0)>>5)]
	dst[17] = crockford[b[10]&0x1F]
	dst[18] = crockford[(b[11]&0xF8)>>3]
	dst[19] = crockford[((b[11]&0x07)<<2)|((b[12]&0xC0)>>6)]
	dst[20] = crockford[(b[12]&0x3E)>>1]
	dst[21] = crockford[((b[12]&0x01)<<4)|((b[13]&0xF0)>>4)]
	dst[22] = crockford[((b[13]&0x0F)<<1)|((b[14]&0x80)>>7)]
	dst[23] = crockford[(b[14]&0x7C)>>2]
	dst[24] = crockford[((b[14]&0x03)<<3)|((b[15]&0xE0)>>5)]
	dst[25] = crockford[b[15]&0x1F]

	return string(dst[:])
}
