package keys

import "errors"

// codec is the string-free encoder/decoder for the decrypted wallet plaintext
// (§3.3/§3.10):
//
//	{ "v": 1, "mnemonic": "abandon … about", "bip39_passphrase": "" }
//
// The whole point is to keep the mnemonic and 25th word OFF the Go string heap:
// encoding/json would unmarshal them into immutable strings we could never zero.
// So we hand-roll a tiny decoder that returns []byte slices we own and zero, and
// an encoder that assembles the plaintext from []byte inputs. The mnemonic is
// stored verbatim (NFKD-normalized by the caller before sealing); the value
// strings here contain only the BIP-39 charset plus spaces, which need no JSON
// string escaping — but the decoder still handles the escapes JSON permits so a
// hand-edited or geth-foreign blob never silently mis-decodes.

const walletPlaintextVersion = 1

var (
	errBadPlaintext = errors.New("wallet plaintext is malformed")
)

// encodePlaintext builds the wallet-blob plaintext bytes from a mnemonic and an
// optional BIP-39 passphrase. The result is the caller's to seal and then zero.
// Inputs are not retained.
func encodePlaintext(mnemonic, bip39pass []byte) []byte {
	// {"v":1,"mnemonic":"...","bip39_passphrase":"..."}
	out := make([]byte, 0, len(mnemonic)+len(bip39pass)+48)
	out = append(out, `{"v":`...)
	out = append(out, byte('0'+walletPlaintextVersion))
	out = append(out, `,"mnemonic":`...)
	out = appendJSONString(out, mnemonic)
	out = append(out, `,"bip39_passphrase":`...)
	out = appendJSONString(out, bip39pass)
	out = append(out, '}')
	return out
}

// appendJSONString appends a JSON-encoded string of b to dst, escaping the
// characters JSON requires (", \, and control bytes). The BIP-39 charset never
// triggers an escape, but standalone-safety wants a correct encoder.
func appendJSONString(dst, b []byte) []byte {
	dst = append(dst, '"')
	for _, c := range b {
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				const hexd = "0123456789abcdef"
				dst = append(dst, '\\', 'u', '0', '0', hexd[c>>4], hexd[c&0xf])
			} else {
				dst = append(dst, c)
			}
		}
	}
	return append(dst, '"')
}

// decodePlaintext extracts the mnemonic and bip39_passphrase byte slices from the
// wallet plaintext WITHOUT producing any Go string. The returned slices are fresh
// copies the caller owns and must zero. It tolerates a missing bip39_passphrase
// (treats it as empty).
func decodePlaintext(p []byte) (mnemonic, bip39pass []byte, err error) {
	d := &scanner{src: p}
	d.ws()
	if !d.byteIs('{') {
		return nil, nil, errBadPlaintext
	}
	var haveMnemonic bool
	for {
		d.ws()
		if d.byteIs('}') {
			break
		}
		key, kerr := d.stringBytes()
		if kerr != nil {
			return nil, nil, errBadPlaintext
		}
		d.ws()
		if !d.byteIs(':') {
			return nil, nil, errBadPlaintext
		}
		d.ws()
		switch string(key) {
		case "mnemonic":
			val, verr := d.stringBytes()
			if verr != nil {
				return nil, nil, errBadPlaintext
			}
			mnemonic = val
			haveMnemonic = true
		case "bip39_passphrase":
			val, verr := d.stringBytes()
			if verr != nil {
				return nil, nil, errBadPlaintext
			}
			bip39pass = val
		case "v":
			// numeric version; skip the number token.
			if !d.skipNumber() {
				return nil, nil, errBadPlaintext
			}
		default:
			// Unknown field (forward-compat superset): skip its value.
			if !d.skipValue() {
				return nil, nil, errBadPlaintext
			}
		}
		d.ws()
		if d.byteIs(',') {
			continue
		}
		if d.byteIs('}') {
			break
		}
		return nil, nil, errBadPlaintext
	}
	if !haveMnemonic || len(mnemonic) == 0 {
		return nil, nil, errBadPlaintext
	}
	if bip39pass == nil {
		bip39pass = []byte{}
	}
	return mnemonic, bip39pass, nil
}

// scanner is a minimal forward JSON reader over a byte slice.
type scanner struct {
	src []byte
	i   int
}

func (s *scanner) ws() {
	for s.i < len(s.src) {
		switch s.src[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

func (s *scanner) byteIs(c byte) bool {
	if s.i < len(s.src) && s.src[s.i] == c {
		s.i++
		return true
	}
	return false
}

// stringBytes reads a JSON string and returns a freshly-allocated, unescaped byte
// slice the caller owns. It is the only token type that allocates secret-bearing
// memory; callers zero the result.
func (s *scanner) stringBytes() ([]byte, error) {
	if s.i >= len(s.src) || s.src[s.i] != '"' {
		return nil, errBadPlaintext
	}
	s.i++
	out := make([]byte, 0, 16)
	for s.i < len(s.src) {
		c := s.src[s.i]
		s.i++
		switch c {
		case '"':
			return out, nil
		case '\\':
			if s.i >= len(s.src) {
				return nil, errBadPlaintext
			}
			e := s.src[s.i]
			s.i++
			switch e {
			case '"':
				out = append(out, '"')
			case '\\':
				out = append(out, '\\')
			case '/':
				out = append(out, '/')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'u':
				if s.i+4 > len(s.src) {
					return nil, errBadPlaintext
				}
				r, ok := parseHex4(s.src[s.i : s.i+4])
				if !ok {
					return nil, errBadPlaintext
				}
				s.i += 4
				out = appendRune(out, r)
			default:
				return nil, errBadPlaintext
			}
		default:
			out = append(out, c)
		}
	}
	return nil, errBadPlaintext
}

// skipNumber advances past a JSON number token (digits, sign, '.', 'e').
func (s *scanner) skipNumber() bool {
	start := s.i
	for s.i < len(s.src) {
		c := s.src[s.i]
		if (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' {
			s.i++
			continue
		}
		break
	}
	return s.i > start
}

// skipValue skips an arbitrary JSON value (string/number/bool/null/object/array)
// for forward-compat fields. It does not allocate secret memory.
func (s *scanner) skipValue() bool {
	s.ws()
	if s.i >= len(s.src) {
		return false
	}
	switch s.src[s.i] {
	case '"':
		_, err := s.stringBytes()
		return err == nil
	case '{', '[':
		return s.skipContainer()
	case 't':
		return s.skipLiteral("true")
	case 'f':
		return s.skipLiteral("false")
	case 'n':
		return s.skipLiteral("null")
	default:
		return s.skipNumber()
	}
}

func (s *scanner) skipContainer() bool {
	open := s.src[s.i]
	closeCh := byte('}')
	if open == '[' {
		closeCh = ']'
	}
	depth := 0
	for s.i < len(s.src) {
		c := s.src[s.i]
		switch c {
		case '"':
			if _, err := s.stringBytes(); err != nil {
				return false
			}
			continue
		case open:
			depth++
		case closeCh:
			depth--
			s.i++
			if depth == 0 {
				return true
			}
			continue
		}
		s.i++
	}
	return false
}

func (s *scanner) skipLiteral(lit string) bool {
	if s.i+len(lit) > len(s.src) {
		return false
	}
	if string(s.src[s.i:s.i+len(lit)]) != lit {
		return false
	}
	s.i += len(lit)
	return true
}

func parseHex4(b []byte) (rune, bool) {
	var r rune
	for _, c := range b {
		var d rune
		switch {
		case c >= '0' && c <= '9':
			d = rune(c - '0')
		case c >= 'a' && c <= 'f':
			d = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = rune(c-'A') + 10
		default:
			return 0, false
		}
		r = r<<4 | d
	}
	return r, true
}

// appendRune appends r as UTF-8 without importing unicode/utf8 (keeps the codec
// dependency-free). The BIP-39 English wordlist is ASCII, so this path is only
// for a foreign/hand-edited blob; it handles the BMP correctly (no surrogate
// pairing, which a v1 blob never needs). Each emitted byte is explicitly masked to
// 8 bits so the rune→byte conversions are provably in range.
func appendRune(dst []byte, r rune) []byte {
	if r < 0 {
		r = 0xFFFD // replacement char; a \u escape never yields a negative rune
	}
	u := uint32(r) // #nosec G115 -- r is non-negative here (guarded above)
	switch {
	case u < 0x80:
		return append(dst, byte(u&0xFF))
	case u < 0x800:
		return append(dst, byte((0xC0|u>>6)&0xFF), byte((0x80|u&0x3F)&0xFF))
	default:
		return append(dst, byte((0xE0|u>>12)&0xFF), byte((0x80|(u>>6)&0x3F)&0xFF), byte((0x80|u&0x3F)&0xFF))
	}
}
