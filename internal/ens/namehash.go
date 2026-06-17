package ens

import (
	"encoding/hex"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Namehash computes the EIP-137 node hash for an ENS name. It is the recursive
// keccak that turns a dot-separated name into the 32-byte node every ENS read
// (registry.resolver / resolver.addr / resolver.name) is keyed by:
//
//	namehash("")     = 0x0000…0000 (32 zero bytes — the root node)
//	namehash(a.b.c)  = keccak256( namehash(b.c) || keccak256("a") )
//
// processed RIGHT-to-LEFT over the dot-split labels. Each label is folded in as
// its labelhash (keccak256 of the raw label bytes), NOT as a re-hash of the whole
// remaining suffix — the running node accumulates one label per step. Pure: no
// network, no state.
//
// The caller is responsible for normalizing the name first (see normalize.go);
// Namehash hashes whatever label bytes it is given verbatim, so "Vitalik.eth"
// and "vitalik.eth" produce DIFFERENT nodes. Resolve/Reverse normalize before
// calling this; the known-vector test pins the algorithm against the published
// EIP-137 values (vitalik.eth → 0xee6c…5835, eth → 0x93cd…c4ae, "" → all-zero).
func Namehash(name string) [32]byte {
	var node [32]byte // all-zero == the root node
	if name == "" {
		return node
	}
	labels := strings.Split(name, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		lh := labelhash(labels[i])
		// node = keccak256(node || labelhash(label))
		node = [32]byte(crypto.Keccak256(node[:], lh[:]))
	}
	return node
}

// labelhash is keccak256 of a single (already-normalized) label's raw bytes — the
// per-label component EIP-137 folds into the running node. Exposed unexported so
// Namehash and reverseNode share exactly one definition.
func labelhash(label string) [32]byte {
	return [32]byte(crypto.Keccak256([]byte(label)))
}

// reverseNode returns the EIP-181 reverse-resolution node for an address:
//
//	namehash("<lowerhex(addr) without 0x>.addr.reverse")
//
// e.g. address 0x7099…79C8 → namehash("70997970…79c8.addr.reverse"). This is the
// node Reverse queries registry.resolver / resolver.name against. The hex is the
// 20 address bytes, lowercased, with NO 0x prefix and NO EIP-55 checksum casing —
// the ENS reverse registrar canonicalizes on the lowercase hex, so any other
// casing would hash to the wrong node and silently fail to resolve.
func reverseNode(a common.Address) [32]byte {
	name := hex.EncodeToString(a.Bytes()) + ".addr.reverse" // hex is already lowercase
	return Namehash(name)
}
