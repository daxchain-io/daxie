package ens

import (
	"context"
	"math/big"

	"github.com/daxchain-io/daxie/internal/chain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// The four ENS reads this package performs are plain eth_calls with a 4-byte
// selector followed by a single bytes32 node argument (and, for name(), an ABI
// string return). The selectors are pinned as literal signature strings AND
// independently re-derived from the string in the test (abi_test.go) so a typo
// cannot pass silently — exactly the erc.go discipline. The well-known values
// (golden in the test): resolver(bytes32)=0x0178b8bf, addr(bytes32)=0x3b3b57de,
// name(bytes32)=0x691f3431.
const (
	// sigResolver is ENS registry resolver(bytes32 node) → address (0x0178b8bf).
	// Returns the resolver contract responsible for a node, or the zero address
	// when the node has no resolver.
	sigResolver = "resolver(bytes32)"
	// sigAddr is the public-resolver addr(bytes32 node) → address (0x3b3b57de):
	// the EIP-137 forward record, the address a name points at. Zero means "no
	// address record" (the name does not resolve).
	sigAddr = "addr(bytes32)"
	// sigName is the public-resolver name(bytes32 node) → string (0x691f3431):
	// the EIP-181 reverse record, the primary name claimed for an address. It is
	// NOT trusted until forward-verified (Reverse re-resolves it back to the
	// address) — a reverse record is unauthenticated on its own.
	sigName = "name(bytes32)"
)

// selector returns the 4-byte function selector for a canonical signature string
// (the first 4 bytes of its keccak256), matching solc/cast and the erc package's
// derivation so the golden-byte test's expected values line up.
func selector(sig string) []byte {
	return crypto.Keccak256([]byte(sig))[:4]
}

// callNode builds `selector(sig) || node` and performs one read-only eth_call
// against `to`, returning the raw ABI return bytes. A non-nil client error is
// propagated UNCHANGED so the §5.7 rpc.* taxonomy (exit 6, retryable hint) is
// preserved — resolution-layer "not resolved" decisions are made by the caller on
// a clean (empty/zero) return, never by relabeling a transport failure.
func callNode(ctx context.Context, cc chain.Client, to common.Address, sig string, node [32]byte) ([]byte, error) {
	data := make([]byte, 0, 4+32)
	data = append(data, selector(sig)...)
	data = append(data, node[:]...)
	toAddr := to
	msg := ethereum.CallMsg{To: &toAddr, Data: data}
	return cc.CallContract(ctx, msg, nil)
}

// decodeAddress decodes a 32-byte ABI address return (the low 20 bytes of the
// first word). An empty/short return (a contract that returned nothing, e.g. a
// node with no record) yields ok=false so the caller maps it to ErrUnresolved
// rather than a bogus zero address that looks like a real (burn) destination.
func decodeAddress(out []byte) (common.Address, bool) {
	if len(out) < 32 {
		return common.Address{}, false
	}
	return common.BytesToAddress(out[:32]), true
}

// decodeString decodes a canonical ABI dynamic-string return (name()): a 32-byte
// offset word, a 32-byte length word at that offset, then `length` UTF-8 bytes.
// Every index is bounds-checked so a malformed/hostile return cannot panic; a
// failure (empty/short/out-of-bounds) yields ok=false. ENS name() always returns
// the canonical dynamic-string encoding (unlike legacy ERC-20 bytes32 symbols),
// so this does NOT special-case a bare 32-byte word.
func decodeString(out []byte) (string, bool) {
	if len(out) < 64 {
		return "", false
	}
	off := new(big.Int).SetBytes(out[:32])
	if !off.IsUint64() {
		return "", false
	}
	o := off.Uint64()
	if o > uint64(len(out)) || uint64(len(out))-o < 32 {
		return "", false
	}
	ln := new(big.Int).SetBytes(out[o : o+32])
	if !ln.IsUint64() {
		return "", false
	}
	l := ln.Uint64()
	start := o + 32
	if l > uint64(len(out)) || uint64(len(out))-start < l {
		return "", false
	}
	return string(out[start : start+l]), true
}
