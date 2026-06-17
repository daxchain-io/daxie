package erc

// nft.go holds the M6 ERC-721/1155 metadata reads — the per-request reads that
// take a chain.Client per call (§2.8), kept in their own file so the M6 NFT erc
// surface is reviewable in isolation. They share the same package internals as
// metadata.go (callRead, decodeUint, addrWord, uintWord, selector) and the same
// stateless Ops value receiver. The pure 721/1155 safeTransferFrom calldata
// builder lives in erc.go (SafeTransferFromCalldata); ownerOf lives in
// metadata.go. This file adds: ERC-165 detection (SupportsInterface/DetectKind)
// and the ERC-1155 balance read (BalanceOf1155).
//
// ANTI-SPOOFING (§7.8): DetectKind is the ONLY place daxie decides 721-vs-1155
// from the chain, and it runs at `nft add` ONLY. The detected kind is STORED in
// the registry; alias resolution thereafter is registry-only and NEVER re-probes
// the chain — identical to the token symbol() wall. erc returns a bare token
// standard string (Kind721/Kind1155); service maps it to the registry kind const,
// so there is no erc→registry import edge.

import (
	"context"
	"math/big"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/ethereum/go-ethereum/common"
)

// The bare token-standard strings DetectKind returns. They deliberately match
// the registry kind vocabulary (registry.KindERC721 / KindERC1155) by VALUE so
// service can pass the result straight through, but erc does not import registry
// (the value coupling is documented, not compiled — no edge).
const (
	// KindUnknown is the zero value (neither 721 nor 1155).
	KindUnknown = ""
	// Kind721 is the ERC-721 standard string.
	Kind721 = "erc721"
	// Kind1155 is the ERC-1155 standard string.
	Kind1155 = "erc1155"
)

// SupportsInterface calls ERC-165 supportsInterface(bytes4) (selector 0x01ffc9a7)
// for the given interface id and decodes the bool return.
//
// A revert / empty / undecodable return is reported as (false, nil) — NOT an
// error — so DetectKind can fall through to ErrNotNFT: a contract that does not
// implement ERC-165 simply "does not support" the interface, which is a
// caller-input condition, not a transport failure. A genuine TRANSPORT error
// (the client itself errors) is propagated UNCHANGED, preserving the §5.7 rpc.*
// taxonomy and retryable hint (identical to the metadata.go reads).
//
// The bytes4 argument is LEFT-aligned in its 32-byte ABI word (the high 4 bytes
// carry the id, the low 28 are zero), per the ABI encoding of a fixed `bytesN`.
func (Ops) SupportsInterface(ctx context.Context, cc chain.Client, contract common.Address, id [4]byte) (bool, error) {
	data := make([]byte, 0, 4+32)
	data = append(data, selector(sigSupportsInterface)...)
	var word [32]byte
	copy(word[:4], id[:]) // bytes4 is LEFT-aligned in its ABI word
	data = append(data, word[:]...)

	out, err := callRead(ctx, cc, contract, data)
	if err != nil {
		return false, err // transport error → propagate (preserve retryable hint)
	}
	b, ok := decodeBool(out)
	if !ok {
		return false, nil // non-165 / undecodable → "not supported", not an error
	}
	return b, nil
}

// DetectKind probes a contract with ERC-165 and returns Kind721 / Kind1155, or
// ErrNotNFT when it is neither (an EOA, a plain ERC-20, a non-165 contract). It
// is the §10.1 "ERC-165 detection at `nft add`" check: 721 is tried first
// (0x80ac58cd), then 1155 (0xd9b67a26). A TRANSPORT error from either probe is
// propagated (so `nft add` fails retryable, not "not an NFT"). This is the ONLY
// place daxie decides 721-vs-1155 from the chain; the result is STORED at add and
// resolution thereafter is registry-only (the anti-spoofing wall — DetectKind is
// never used to resolve an alias).
func (o Ops) DetectKind(ctx context.Context, cc chain.Client, contract common.Address) (string, error) {
	is721, err := o.SupportsInterface(ctx, cc, contract, iface721)
	if err != nil {
		return KindUnknown, err
	}
	if is721 {
		return Kind721, nil
	}
	is1155, err := o.SupportsInterface(ctx, cc, contract, iface1155)
	if err != nil {
		return KindUnknown, err
	}
	if is1155 {
		return Kind1155, nil
	}
	return KindUnknown, ErrNotNFT
}

// BalanceOf1155 reads ERC-1155 balanceOf(address owner,uint256 id) (selector
// 0x00fdd58e) and decodes the uint256 quantity. DISTINCT from the ERC-20
// BalanceOf(token,owner) in metadata.go (a different selector and a second id
// arg). A revert / empty / undecodable return is ErrNotNFT (not a conforming
// 1155). tokenID nil is treated as zero (the EVM has no negative id).
func (Ops) BalanceOf1155(ctx context.Context, cc chain.Client, contract, owner common.Address, tokenID *big.Int) (*big.Int, error) {
	data := make([]byte, 0, 4+64)
	data = append(data, selector(sigBalanceOf1155)...)
	data = append(data, addrWord(owner)...)
	data = append(data, uintWord(tokenID)...)

	out, err := callRead(ctx, cc, contract, data)
	if err != nil {
		return nil, err
	}
	n, ok := decodeUint(out) // decodeUint is shared with metadata.go
	if !ok {
		return nil, ErrNotNFT
	}
	return n, nil
}

// decodeBool decodes a 32-byte ABI bool return: a nonzero first word is true. An
// empty / short return yields ok=false (the caller treats that as "false /
// unsupported"). It mirrors decodeUint's bounds discipline so a hostile/short
// return can never panic.
func decodeBool(out []byte) (bool, bool) {
	if len(out) < 32 {
		return false, false
	}
	return new(big.Int).SetBytes(out[:32]).Sign() != 0, true
}
