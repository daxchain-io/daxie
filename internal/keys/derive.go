package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"math/big"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	bip39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The fixed BIP-44 Ethereum path prefix (cli-spec §1): m/44'/60'/0'/0/{index}.
// Stored per wallet (path_prefix) so a future --path flag is a metadata change.
const defaultPathPrefix = "m/44'/60'/0'/0"

// hardened is the BIP-32 hardened-key offset (2^31). 44', 60', 0' use it.
const hardened = hdkeychain.HardenedKeyStart

// purposeETH/coinETH/account0/change0 are the fixed BIP-44 levels for
// m/44'/60'/0'/0 (Ethereum, account 0, external chain).
const (
	purposeETH = 44
	coinETH    = 60
	bip44Acct0 = 0
	bip44Chg0  = 0
)

// ── BIP-39 mnemonic generation / validation (§3.5) ─────────────────────────────

// wordsToEntropyBits maps a word count to its BIP-39 entropy size. v1 supports 12
// and 24 words only.
func wordsToEntropyBits(words int) (int, bool) {
	switch words {
	case 12:
		return 128, true
	case 24:
		return 256, true
	default:
		return 0, false
	}
}

// generateMnemonic produces a fresh English BIP-39 mnemonic at the given word
// count, NFKD-normalized, returned as bytes the caller owns and zeroes. Entropy
// comes from crypto/rand (keys is a provider, exempt from the determinism guard).
func generateMnemonic(words int) ([]byte, error) {
	bits, ok := wordsToEntropyBits(words)
	if !ok {
		return nil, errKeysf(CodeUsageWords, "unsupported word count %d (use 12 or 24)", words)
	}
	entropy := make([]byte, bits/8)
	if _, err := rand.Read(entropy); err != nil {
		return nil, errWrap(CodeStateCorrupt, "cannot read entropy for the mnemonic", err)
	}
	defer zeroBytes(entropy)

	m, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "cannot generate the mnemonic", err)
	}
	// Store the CANONICAL BIP-39 sentence (§3.3): NFKD-normalized and whitespace-
	// collapsed. NewMnemonic returns a Go string; canonicalizeMnemonic copies its
	// canonical bytes into a slice we own and lets the string fall out of scope.
	// The generated mnemonic is already single-space-separated ASCII, but we route
	// it through the SAME canonicalizer as import so there is exactly one code path
	// and one seed-derivation surface.
	return canonicalizeMnemonic([]byte(m)), nil
}

// validateMnemonic canonicalizes (NFKD + whitespace-collapse) and checksum-
// validates a candidate mnemonic (English wordlist, checksum-hard, §3.3). It
// returns the CANONICAL bytes the caller owns and zeroes — the exact bytes that
// are stored AND seed-derived from, so a non-canonical input (stray/leading/
// trailing/double whitespace) can never silently derive a different (and
// effectively unrecoverable) address than every other BIP-39 wallet. A bad
// checksum / unknown word is usage.bad_mnemonic.
func validateMnemonic(raw []byte) ([]byte, error) {
	m := canonicalizeMnemonic(raw)
	// go-bip39 validates against the English wordlist + checksum. It is
	// string-only on this boundary (§3.10 honest residual): the transient string
	// is immutable and cannot be zeroed, but it carries the SAME secret we already
	// hold in m, and falls out of scope immediately. Because m is already
	// canonical, IsMnemonicValid's own whitespace leniency is irrelevant here.
	if !bip39.IsMnemonicValid(string(m)) {
		zeroBytes(m)
		return nil, errKeys(CodeUsageBadMnemonic, "the mnemonic is not a valid BIP-39 English phrase (checksum or word-list failure)")
	}
	return m, nil
}

// canonicalizeMnemonic returns the BIP-39 canonical form of raw as a fresh slice
// the caller owns and zeroes: NFKD-normalized (BIP-39 §2.4), then whitespace-
// collapsed — leading/trailing whitespace trimmed and every internal run of
// Unicode whitespace replaced with a single ASCII space. This is exactly
// bytes.Join(bytes.Fields(nfkd), " ") but performed on the OWNED []byte so no Go
// string ever carries the secret (§3.10). It is whitespace-sensitive seed
// derivation made safe: a mnemonic with a trailing newline, a leading space, or
// double spaces now derives the SAME seed/address as its canonical form rather
// than a divergent one. The intermediate NFKD slice is zeroed.
//
// IMPORTANT: this is ONLY for the mnemonic SENTENCE. The BIP-39 passphrase (25th
// word) whitespace is meaningful by spec and is NEVER passed through here.
func canonicalizeMnemonic(raw []byte) []byte {
	nfkd := nfkdBytes(raw)
	// bytes.Fields splits on Unicode whitespace (unicode.IsSpace over decoded
	// runes) and drops empty fields, so leading/trailing/multiple/odd-width
	// whitespace all collapse. Join with a single ASCII space — the BIP-39
	// canonical separator.
	out := bytes.Join(bytes.Fields(nfkd), []byte{' '})
	// Zero the intermediate NFKD bytes (they held the secret). bytes.Fields
	// returns sub-slices aliasing nfkd, and Join copied them into out, so out is
	// independent and nfkd is safe to wipe. Skip the wipe if Fields returned no
	// fields and nfkd is the same empty slice as out (no secret to wipe).
	if len(nfkd) > 0 {
		zeroBytes(nfkd)
	}
	return out
}

// nfkdBytes returns the NFKD-normalized form of b as a fresh slice we own. BIP-39
// (§2.4) normalizes the mnemonic and passphrase to NFKD before seed derivation.
// Empty input yields a fresh empty slice (never an alias of the caller's).
func nfkdBytes(b []byte) []byte {
	if len(b) == 0 {
		return []byte{}
	}
	out := norm.NFKD.Bytes(b)
	if len(out) > 0 && len(b) > 0 && &out[0] == &b[0] {
		// norm may return the input unchanged; copy so we own the memory.
		cp := make([]byte, len(out))
		copy(cp, out)
		return cp
	}
	return out
}

// ── BIP-39 seed (string-free, §3.10) ───────────────────────────────────────────

// seedFromMnemonic derives the 64-byte BIP-39 seed WITHOUT crossing the Go string
// boundary: it replicates go-bip39's NewSeed (pbkdf2(mnemonic, "mnemonic"+pass,
// 2048, 64, sha512)) on []byte inputs. Both inputs are NFKD-normalized (the
// mnemonic is stored NFKD; the passphrase is normalized here). The returned seed
// is the caller's to zero.
func seedFromMnemonic(mnemonic, bip39pass []byte) []byte {
	normPass := nfkdBytes(bip39pass)
	defer zeroBytes(normPass)
	salt := make([]byte, 0, len("mnemonic")+len(normPass))
	salt = append(salt, "mnemonic"...)
	salt = append(salt, normPass...)
	defer zeroBytes(salt)
	return pbkdf2.Key(mnemonic, salt, 2048, 64, sha512.New)
}

// ── BIP-44 derivation (§3.5) ───────────────────────────────────────────────────

// deriveAddress derives the address at m/44'/60'/0'/0/index from a seed, with NO
// signing key materialized beyond what address derivation needs (the btcec key is
// zeroed before return). Used for the public-address caching path (create/derive).
func deriveAddress(seed []byte, index uint32) (common.Address, error) {
	priv, err := derivePrivateKey(seed, index)
	if err != nil {
		return common.Address{}, err
	}
	addr := crypto.PubkeyToAddress(priv.PublicKey)
	zeroECDSA(priv)
	return addr, nil
}

// derivePrivateKey derives the geth *ecdsa.PrivateKey at m/44'/60'/0'/0/index from
// a BIP-39 seed. The caller MUST zeroECDSA the result the instant it is done. The
// HD intermediate keys are released to the GC; the final scalar bytes are zeroed
// after the bridge to geth.
func derivePrivateKey(seed []byte, index uint32) (*ecdsa.PrivateKey, error) {
	// Master key. chaincfg.MainNetParams supplies only the HD version bytes, which
	// never reach any chain (§3.5).
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "cannot derive the HD master key", err)
	}
	// m/44'/60'/0'/0/index
	levels := []uint32{
		hardened + purposeETH,
		hardened + coinETH,
		hardened + bip44Acct0,
		bip44Chg0,
		index,
	}
	k := master
	for _, lvl := range levels {
		next, derr := k.Derive(lvl)
		if derr != nil {
			return nil, errWrap(CodeStateCorrupt, "cannot derive the HD child key", derr)
		}
		k = next
	}

	ecpriv, err := k.ECPrivKey() // *btcec.PrivateKey (= secp256k1.PrivateKey)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "cannot extract the EC private key", err)
	}
	// Bridge btcec -> geth *ecdsa.PrivateKey through the 32-byte scalar so the geth
	// crypto path (curve = the pure-Go btcec secp256k1) owns the key. Zero the
	// transient scalar bytes immediately.
	d := ecpriv.Serialize()
	defer zeroBytes(d)
	priv, err := crypto.ToECDSA(d)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "the derived key is not a valid secp256k1 key", err)
	}
	return priv, nil
}

// pathString renders m/44'/60'/0'/0/index for display (§3.2 show output).
func pathString(index uint32) string {
	return defaultPathPrefix + "/" + uitoa(uint64(index))
}

// privateKeyHex serializes a geth private key to 0x-prefixed lowercase hex bytes
// the caller owns and zeroes. Used only by account export (the freshly-authed,
// stdout-only path, §3.9). The 32-byte scalar is left-padded.
func privateKeyHex(priv *ecdsa.PrivateKey) []byte {
	raw := crypto.FromECDSA(priv) // 32 bytes, big-endian
	defer zeroBytes(raw)
	const hexd = "0123456789abcdef"
	out := make([]byte, 2+2*len(raw))
	out[0] = '0'
	out[1] = 'x'
	for i, b := range raw {
		out[2+2*i] = hexd[b>>4]
		out[2+2*i+1] = hexd[b&0xf]
	}
	return out
}

// ── standalone raw-key validation (§3.5) ───────────────────────────────────────

// curveN is the secp256k1 group order N; a valid private key is in [1, n-1].
var curveN = crypto.S256().Params().N

// privateKeyFromRaw parses a raw 32-byte private key (provided as hex bytes OR raw
// 32 bytes) into a geth *ecdsa.PrivateKey, validating it is in [1, n-1] (§3.5).
// rawKey is the secret bytes (the file/stdin payload). The caller zeroes rawKey;
// this function zeroes its own transient copies and the caller zeroECDSA's the
// result. A malformed/out-of-range key is usage.bad_key.
func privateKeyFromRaw(rawKey []byte) (*ecdsa.PrivateKey, error) {
	b, err := decodeKeyBytes(rawKey)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(b)
	if len(b) != 32 {
		return nil, errKeysf(CodeUsageBadKey, "a private key must be 32 bytes (got %d)", len(b))
	}
	// Validate range [1, n-1] BEFORE handing to geth (ToECDSA also checks, but we
	// want the canonical usage.bad_key code and an explicit range check).
	d := new(big.Int).SetBytes(b)
	if d.Sign() == 0 || d.Cmp(curveN) >= 0 {
		d.SetInt64(0)
		return nil, errKeys(CodeUsageBadKey, "the private key is out of range (must be in [1, n-1] for secp256k1)")
	}
	d.SetInt64(0)
	priv, err := crypto.ToECDSA(b)
	if err != nil {
		return nil, errKeys(CodeUsageBadKey, "the private key is not a valid secp256k1 key")
	}
	return priv, nil
}

// decodeKeyBytes accepts either a 0x-prefixed / bare hex string of the key, or
// raw 32 bytes, and returns the 32 raw bytes (caller-owned). It tolerates
// surrounding whitespace the resolver may not have stripped.
func decodeKeyBytes(raw []byte) ([]byte, error) {
	s := trimSpace(raw)
	// Strip an optional 0x/0X prefix.
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	// If it looks like hex (even length, all hex digits) decode it; else, if it is
	// exactly 32 raw bytes, use it directly.
	if len(s) > 0 && isHexBytes(s) {
		if len(s)%2 != 0 {
			return nil, errKeys(CodeUsageBadKey, "the private key hex has an odd length")
		}
		out := make([]byte, len(s)/2)
		for i := 0; i < len(out); i++ {
			hi, ok1 := hexNibble(s[2*i])
			lo, ok2 := hexNibble(s[2*i+1])
			if !ok1 || !ok2 {
				return nil, errKeys(CodeUsageBadKey, "the private key hex is malformed")
			}
			out[i] = hi<<4 | lo
		}
		return out, nil
	}
	if len(raw) == 32 {
		out := make([]byte, 32)
		copy(out, raw)
		return out, nil
	}
	return nil, errKeys(CodeUsageBadKey, "the private key must be 32-byte hex (with or without 0x)")
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isHexBytes(b []byte) bool {
	for _, c := range b {
		if _, ok := hexNibble(c); !ok {
			return false
		}
	}
	return len(b) > 0
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
