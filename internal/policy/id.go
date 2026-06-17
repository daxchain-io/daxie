package policy

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// ulid generates a 26-character Crockford-base32 ULID (48-bit big-endian
// millisecond timestamp || 80 bits of entropy), lexicographically sortable by
// creation time. We hand-roll it (rather than pulling oklog/ulid) so policy adds
// no new module dependency; policy is a provider so crypto/rand is allowed (the
// determinism guard covers only service + domain, §2.3).
//
// The id is the durable reservation key the journal stores in reservation_id and
// the §5.1 reconciliation resolves back, so it only needs to be unique and
// stable — the time prefix is a convenience for human-sortable on-disk records.
//
// ts comes from the injected clock so reservation ids are reproducible in tests.
func ulid(ts time.Time) string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	ms := uint64(ts.UTC().UnixMilli())

	var ent [10]byte
	// crypto/rand.Read never returns a short read without an error on supported
	// platforms; a failure here is unrecoverable for id generation, so panic —
	// it can only happen if the OS RNG is unavailable.
	if _, err := rand.Read(ent[:]); err != nil {
		panic("policy: entropy source unavailable: " + err.Error())
	}

	// Pack the 48-bit time + 80-bit entropy into a 16-byte big-endian buffer, then
	// emit 26 base32 chars over 130 bits (the top 2 bits are always zero).
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], ms<<16) // time in the high 48 bits of the first 8 bytes
	copy(b[6:16], ent[:])

	// Encode 16 bytes (128 bits) as 26 Crockford chars: the standard ULID layout.
	dst := make([]byte, 26)
	dst[0] = crockford[(b[0]&224)>>5]
	dst[1] = crockford[b[0]&31]
	dst[2] = crockford[(b[1]&248)>>3]
	dst[3] = crockford[((b[1]&7)<<2)|((b[2]&192)>>6)]
	dst[4] = crockford[(b[2]&62)>>1]
	dst[5] = crockford[((b[2]&1)<<4)|((b[3]&240)>>4)]
	dst[6] = crockford[((b[3]&15)<<1)|((b[4]&128)>>7)]
	dst[7] = crockford[(b[4]&124)>>2]
	dst[8] = crockford[((b[4]&3)<<3)|((b[5]&224)>>5)]
	dst[9] = crockford[b[5]&31]
	dst[10] = crockford[(b[6]&248)>>3]
	dst[11] = crockford[((b[6]&7)<<2)|((b[7]&192)>>6)]
	dst[12] = crockford[(b[7]&62)>>1]
	dst[13] = crockford[((b[7]&1)<<4)|((b[8]&240)>>4)]
	dst[14] = crockford[((b[8]&15)<<1)|((b[9]&128)>>7)]
	dst[15] = crockford[(b[9]&124)>>2]
	dst[16] = crockford[((b[9]&3)<<3)|((b[10]&224)>>5)]
	dst[17] = crockford[b[10]&31]
	dst[18] = crockford[(b[11]&248)>>3]
	dst[19] = crockford[((b[11]&7)<<2)|((b[12]&192)>>6)]
	dst[20] = crockford[(b[12]&62)>>1]
	dst[21] = crockford[((b[12]&1)<<4)|((b[13]&240)>>4)]
	dst[22] = crockford[((b[13]&15)<<1)|((b[14]&128)>>7)]
	dst[23] = crockford[(b[14]&124)>>2]
	dst[24] = crockford[((b[14]&3)<<3)|((b[15]&224)>>5)]
	dst[25] = crockford[b[15]&31]
	return string(dst)
}
