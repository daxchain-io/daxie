package ens

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestSelectorsMatchSignatures re-derives each ENS read selector from its
// signature string and asserts the well-known 4-byte value, so a typo in a
// signature constant cannot pass silently (cast sig "resolver(bytes32)" ==
// 0x0178b8bf …). These are the exact selectors the registry/resolver expect on
// the wire.
func TestSelectorsMatchSignatures(t *testing.T) {
	cases := []struct {
		sig  string
		want string
	}{
		{sigResolver, "0178b8bf"},
		{sigAddr, "3b3b57de"},
		{sigName, "691f3431"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(selector(c.sig)); got != c.want {
			t.Errorf("selector(%q) = 0x%s, want 0x%s", c.sig, got, c.want)
		}
	}
}

// TestDecodeAddressBounds confirms the address decoder: a full 32-byte word
// yields the low-20-byte address; a short/empty return is rejected (ok=false) so
// the caller maps it to ErrUnresolved rather than a bogus zero address.
func TestDecodeAddressBounds(t *testing.T) {
	want := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	word := common.LeftPadBytes(want.Bytes(), 32)
	got, ok := decodeAddress(word)
	if !ok || got != want {
		t.Fatalf("decodeAddress(full word) = (%s, %v), want (%s, true)", got.Hex(), ok, want.Hex())
	}

	// Empty and short returns are not decodable.
	for _, bad := range [][]byte{nil, {}, make([]byte, 31)} {
		if _, ok := decodeAddress(bad); ok {
			t.Fatalf("decodeAddress(len=%d) ok=true, want false", len(bad))
		}
	}

	// A zero word decodes ok=true but to the zero address; the resolver layer
	// (resolveNode) is what treats zero as ErrUnresolved, not the decoder.
	zero, ok := decodeAddress(make([]byte, 32))
	if !ok || (zero != common.Address{}) {
		t.Fatalf("decodeAddress(zero word) = (%s, %v), want (0x0, true)", zero.Hex(), ok)
	}
}

// abiString builds a canonical ABI dynamic-string return (offset=0x20, length,
// then padded UTF-8 bytes) for the decode test.
func abiString(s string) []byte {
	out := make([]byte, 0, 64+len(s)+32)
	out = append(out, common.LeftPadBytes(big.NewInt(0x20).Bytes(), 32)...)          // offset
	out = append(out, common.LeftPadBytes(big.NewInt(int64(len(s))).Bytes(), 32)...) // length
	body := []byte(s)
	out = append(out, body...)
	if pad := (32 - len(body)%32) % 32; pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

// TestDecodeStringBounds confirms the ABI string decoder round-trips a well-formed
// name() return and rejects malformed/short returns (ok=false) without panicking.
func TestDecodeStringBounds(t *testing.T) {
	got, ok := decodeString(abiString("vitalik.eth"))
	if !ok || got != "vitalik.eth" {
		t.Fatalf("decodeString(abi(\"vitalik.eth\")) = (%q, %v), want (\"vitalik.eth\", true)", got, ok)
	}

	// Empty string is a valid encoding (length 0) → "" with ok=true; the Reverse
	// layer treats "" as "no primary name".
	empty, ok := decodeString(abiString(""))
	if !ok || empty != "" {
		t.Fatalf("decodeString(abi(\"\")) = (%q, %v), want (\"\", true)", empty, ok)
	}

	// Too-short and empty returns are not decodable.
	for _, bad := range [][]byte{nil, {}, make([]byte, 63)} {
		if _, ok := decodeString(bad); ok {
			t.Fatalf("decodeString(len=%d) ok=true, want false", len(bad))
		}
	}

	// A return claiming a length that runs past the buffer is rejected (no panic).
	hostile := make([]byte, 64)
	copy(hostile[:32], common.LeftPadBytes(big.NewInt(0x20).Bytes(), 32))   // offset 0x20
	copy(hostile[32:64], common.LeftPadBytes(big.NewInt(1024).Bytes(), 32)) // length 1024 ≫ buffer
	if _, ok := decodeString(hostile); ok {
		t.Fatal("decodeString accepted an out-of-bounds length; must reject")
	}
}
