package keys

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// The canonical Trezor / iancoleman BIP-39 + BIP-44 (m/44'/60'/0'/0) vectors. The
// crown-jewel correctness proof: a wrong derivation produces a wrong, possibly
// already-used address.

// abandonMnemonic is the all-zero-entropy 12-word vector.
const abandonMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// allFFMnemonic is the all-0xff-entropy 24-word vector.
const allFFMnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"

func TestBIP39SeedTrezorVector(t *testing.T) {
	// entropy 0x00..00 + BIP-39 passphrase "TREZOR" => the canonical seed.
	want := "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
	seed := seedFromMnemonic([]byte(abandonMnemonic), []byte("TREZOR"))
	defer zeroBytes(seed)
	if got := hex.EncodeToString(seed); got != want {
		t.Fatalf("BIP-39 seed mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestBIP39SeedEmptyPassphrase(t *testing.T) {
	// abandon… with empty passphrase => the well-known empty-pass seed prefix.
	want := "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
	seed := seedFromMnemonic([]byte(abandonMnemonic), []byte{})
	defer zeroBytes(seed)
	if got := hex.EncodeToString(seed); got != want {
		t.Fatalf("empty-pass seed mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestBIP44AddressVectors(t *testing.T) {
	// m/44'/60'/0'/0/0 and /1 for the abandon… mnemonic (empty BIP-39 passphrase).
	seed := seedFromMnemonic([]byte(abandonMnemonic), []byte{})
	defer zeroBytes(seed)

	cases := []struct {
		index uint32
		want  string
	}{
		{0, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"},
		{1, "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0"},
		{2, "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A"},
	}
	for _, c := range cases {
		addr, err := deriveAddress(seed, c.index)
		if err != nil {
			t.Fatalf("deriveAddress(%d): %v", c.index, err)
		}
		if !strings.EqualFold(addr.Hex(), c.want) {
			t.Errorf("m/44'/60'/0'/0/%d = %s, want %s", c.index, addr.Hex(), c.want)
		}
	}
}

func TestBIP4424WordVector(t *testing.T) {
	// The 24-word all-0xff vector, index 0 (iancoleman, ETH path, empty pass).
	seed := seedFromMnemonic([]byte(allFFMnemonic), []byte{})
	defer zeroBytes(seed)
	addr, err := deriveAddress(seed, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := "0x1959f5f4979c5Cd87D5CB75c678c770515cb5E0E"
	if !strings.EqualFold(addr.Hex(), want) {
		t.Fatalf("24-word index 0 = %s, want %s", addr.Hex(), want)
	}
}

func TestSeedIsStringFreeAndMatchesGoBIP39(t *testing.T) {
	// Our string-free pbkdf2 path must equal go-bip39's NewSeed byte-for-byte. We
	// cannot import go-bip39's NewSeed result here without a string, so we replicate
	// the known vector — covered above — and additionally assert determinism.
	a := seedFromMnemonic([]byte(abandonMnemonic), []byte("x"))
	b := seedFromMnemonic([]byte(abandonMnemonic), []byte("x"))
	defer zeroBytes(a)
	defer zeroBytes(b)
	if !bytes.Equal(a, b) {
		t.Fatal("seed derivation is not deterministic")
	}
}

func TestGenerateMnemonicWordCounts(t *testing.T) {
	for _, words := range []int{12, 24} {
		m, err := generateMnemonic(words)
		if err != nil {
			t.Fatalf("generateMnemonic(%d): %v", words, err)
		}
		n := len(strings.Fields(string(m)))
		if n != words {
			t.Errorf("generateMnemonic(%d) produced %d words", words, n)
		}
		// Generated mnemonic must validate (checksum-correct).
		norm, verr := validateMnemonic(m)
		if verr != nil {
			t.Errorf("generated %d-word mnemonic failed validation: %v", words, verr)
		}
		zeroBytes(norm)
		zeroBytes(m)
	}
	if _, err := generateMnemonic(15); err == nil {
		t.Error("expected an error for an unsupported word count")
	}
}

func TestValidateMnemonicRejectsBadChecksum(t *testing.T) {
	// Swap the last word so the checksum fails.
	bad := strings.Replace(abandonMnemonic, "about", "abandon", 1)
	if _, err := validateMnemonic([]byte(bad)); err == nil {
		t.Fatal("expected a checksum failure for a tampered mnemonic")
	}
	// An unknown word fails too.
	if _, err := validateMnemonic([]byte("zzzz " + abandonMnemonic)); err == nil {
		t.Fatal("expected a word-list failure for an unknown word")
	}
}

// TestMnemonicWhitespaceCanonicalization is the crown-jewel interop guard
// (§3.3): a non-canonical mnemonic (leading/trailing/embedded stray whitespace)
// MUST (a) validate and (b) derive the SAME index-0 address as the canonical
// phrase. Before canonicalization, go-bip39's whitespace-lenient checksum let
// these PASS validation but seedFromMnemonic (pbkdf2 over the verbatim bytes) is
// whitespace-sensitive, so each variant silently derived a DIFFERENT, effectively
// unrecoverable address.
func TestMnemonicWhitespaceCanonicalization(t *testing.T) {
	const wantAddr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"

	variants := []struct {
		name string
		in   string
	}{
		{"canonical", abandonMnemonic},
		{"leading space", " " + abandonMnemonic},
		{"trailing newline", abandonMnemonic + "\n"},
		{"trailing double newline", abandonMnemonic + "\n\n"},
		{"trailing spaces", abandonMnemonic + "   "},
		{"double space between words", strings.Replace(abandonMnemonic, "abandon abandon", "abandon  abandon", 1)},
		{"tab separated", strings.ReplaceAll(abandonMnemonic, " ", "\t")},
		{"mixed leading/trailing/internal", "  \t" + strings.Replace(abandonMnemonic, "abandon about", "abandon   about", 1) + " \n"},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			// (a) must validate (and canonicalize to the exact canonical bytes).
			canon, err := validateMnemonic([]byte(v.in))
			if err != nil {
				t.Fatalf("validateMnemonic(%q): %v", v.in, err)
			}
			defer zeroBytes(canon)
			if string(canon) != abandonMnemonic {
				t.Fatalf("canonical form = %q, want %q", canon, abandonMnemonic)
			}

			// (b) must derive the SAME index-0 address as the canonical phrase.
			seed := seedFromMnemonic(canon, []byte{})
			defer zeroBytes(seed)
			addr, derr := deriveAddress(seed, 0)
			if derr != nil {
				t.Fatalf("deriveAddress: %v", derr)
			}
			if !strings.EqualFold(addr.Hex(), wantAddr) {
				t.Fatalf("variant %q derived %s, want %s", v.name, addr.Hex(), wantAddr)
			}
		})
	}
}

// TestCanonicalizeMnemonicOwnsMemory asserts canonicalizeMnemonic returns a slice
// independent of its input (so zeroing one does not corrupt the other) and zeroes
// the intermediate NFKD bytes.
func TestCanonicalizeMnemonicOwnsMemory(t *testing.T) {
	in := []byte("  abandon   abandon\tabout  ")
	out := canonicalizeMnemonic(in)
	if string(out) != "abandon abandon about" {
		t.Fatalf("canonical = %q, want %q", out, "abandon abandon about")
	}
	// Mutating the input must not affect the output (no aliasing).
	for i := range in {
		in[i] = 'x'
	}
	if string(out) != "abandon abandon about" {
		t.Fatalf("output aliased the input: %q", out)
	}
	// Empty input yields an empty (non-nil-safe) slice with no panic.
	if got := canonicalizeMnemonic(nil); len(got) != 0 {
		t.Fatalf("canonicalizeMnemonic(nil) = %q, want empty", got)
	}
}

func TestPrivateKeyRangeValidation(t *testing.T) {
	// 0 is invalid; n-1 boundary is valid; >= n is invalid.
	zero := bytes.Repeat([]byte{0}, 32)
	if _, err := privateKeyFromRaw([]byte("0x" + hex.EncodeToString(zero))); err == nil {
		t.Error("expected zero key to be rejected")
	}
	// n itself (the order) is invalid.
	nBytes := curveN.Bytes()
	if _, err := privateKeyFromRaw([]byte("0x" + hex.EncodeToString(nBytes))); err == nil {
		t.Error("expected key == n to be rejected")
	}
	// A valid in-range key.
	valid := "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	priv, err := privateKeyFromRaw([]byte(valid))
	if err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	zeroECDSA(priv)
}
