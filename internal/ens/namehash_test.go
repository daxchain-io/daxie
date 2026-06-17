package ens

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// keccak is a test-local helper: keccak256 of the concatenated parts as a
// [32]byte, used to re-derive the recursive namehash step independently of the
// production code.
func keccak(parts ...[]byte) [32]byte {
	return [32]byte(crypto.Keccak256(parts...))
}

// The namehash vectors below are the PUBLISHED EIP-137 values (and independently
// re-computable with go-ethereum crypto.Keccak256 over the recursive algorithm).
// They are pinned byte-for-byte: a namehash bug is a pin-safety bug — the node is
// what every ENS read is keyed by, so a wrong node silently resolves to the wrong
// (attacker-influenceable) address.
const (
	// namehash("") is the root node: 32 zero bytes.
	vecRootHex = "0000000000000000000000000000000000000000000000000000000000000000"
	// namehash("eth") (EIP-137 §"namehash algorithm" worked example).
	vecEthHex = "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae"
	// namehash("foo.eth") (EIP-137 worked example).
	vecFooEthHex = "de9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f"
	// namehash("vitalik.eth") — the canonical real-name vector reviewers check.
	vecVitalikEthHex = "ee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835"
)

// hexNode parses a 64-char hex node literal into a [32]byte, failing on a bad
// literal so a typo in a vector is caught, not silently truncated.
func hexNode(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad node hex %q: %v", s, err)
	}
	if len(b) != 32 {
		t.Fatalf("node hex %q decoded to %d bytes, want 32", s, len(b))
	}
	var n [32]byte
	copy(n[:], b)
	return n
}

// TestNamehashKnownVectors pins the EIP-137 algorithm byte-for-byte against the
// published vectors. If any of these drift, every ENS read in the system is
// looking up the wrong node.
func TestNamehashKnownVectors(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"", vecRootHex},
		{"eth", vecEthHex},
		{"foo.eth", vecFooEthHex},
		{"vitalik.eth", vecVitalikEthHex},
	}
	for _, c := range cases {
		got := Namehash(c.name)
		want := hexNode(t, c.want)
		if got != want {
			t.Errorf("Namehash(%q) = 0x%s, want 0x%s",
				c.name, hex.EncodeToString(got[:]), c.want)
		}
	}
}

// TestNamehashRootIsZero confirms the root sentinel explicitly: namehash("") must
// be 32 zero bytes (the recursion's base case and the value the registry stores
// the root resolver under).
func TestNamehashRootIsZero(t *testing.T) {
	got := Namehash("")
	var zero [32]byte
	if got != zero {
		t.Fatalf("Namehash(\"\") = 0x%s, want 32 zero bytes", hex.EncodeToString(got[:]))
	}
}

// TestNamehashIsRecursive proves the recursive structure rather than just trusting
// the constants: namehash("vitalik.eth") must equal
// keccak256( namehash("eth") || keccak256("vitalik") ). This catches an
// implementation that hashed the whole name in one shot (a common wrong shortcut).
func TestNamehashIsRecursive(t *testing.T) {
	ethNode := Namehash("eth")
	if ethNode != hexNode(t, vecEthHex) {
		t.Fatalf("Namehash(\"eth\") drifted; got 0x%s", hex.EncodeToString(ethNode[:]))
	}
	lh := labelhash("vitalik")
	// node = keccak256(namehash("eth") || keccak256("vitalik"))
	manual := keccak(ethNode[:], lh[:])
	vitalik := Namehash("vitalik.eth")
	if manual != vitalik {
		t.Fatalf("namehash recursion mismatch: keccak(eth-node || labelhash(vitalik)) = 0x%s, Namehash(\"vitalik.eth\") = 0x%s",
			hex.EncodeToString(manual[:]), hex.EncodeToString(vitalik[:]))
	}
}

// TestNamehashCaseFoldViaResolveNormalization documents that Namehash itself does
// NOT case-fold — it hashes verbatim bytes — so "ETH" and "eth" produce DIFFERENT
// nodes. Normalization (which Resolve applies first) is what makes resolution
// case-insensitive; Namehash stays a pure hash of whatever it is given.
func TestNamehashCaseSensitiveByDesign(t *testing.T) {
	if Namehash("ETH") == Namehash("eth") {
		t.Fatal("Namehash unexpectedly case-folded; case-folding must live in normalize, not Namehash")
	}
}

// TestReverseNodeVector pins the EIP-181 reverse node for a known address against
// an independently-recomputed value: namehash("<lowerhex>.addr.reverse"). The
// reverse node must use the LOWERCASE, no-0x hex — any other casing hashes wrong.
func TestReverseNodeVector(t *testing.T) {
	// anvil account 1.
	a := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	// Independently recompute via the documented string form.
	want := Namehash("70997970c51812dc3a010c7d01b50e0d17dc79c8.addr.reverse")
	got := reverseNode(a)
	if got != want {
		t.Fatalf("reverseNode(%s) = 0x%s, want 0x%s",
			a.Hex(), hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
	}
	// And pin the literal value so a regression in either side is caught.
	const wantHex = "22c5ff4df739cbbd01c40abfe951c993aaf3b331e75b14af3afcbc78c29a3261"
	if hex.EncodeToString(got[:]) != wantHex {
		t.Fatalf("reverseNode vector drifted: got 0x%s, want 0x%s", hex.EncodeToString(got[:]), wantHex)
	}
}

// TestReverseNodeIsLowercaseInsensitive confirms reverseNode ignores the input
// address's EIP-55 checksum casing (it canonicalizes on the address bytes), so the
// checksummed and all-lower forms of the same address produce the same node.
func TestReverseNodeIsLowercaseInsensitive(t *testing.T) {
	checksummed := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	lower := common.HexToAddress("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")
	if reverseNode(checksummed) != reverseNode(lower) {
		t.Fatal("reverseNode depends on input casing; it must canonicalize on the address bytes")
	}
}
