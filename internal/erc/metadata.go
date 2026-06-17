package erc

import (
	"bytes"
	"context"
	"math/big"

	"github.com/daxchain-io/daxie/internal/chain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// The metadata reads take a chain.Client PER CALL (§2.8): service resolves the
// request's client from its network/endpoint and passes it in, so one Ops value
// serves every network. Each read is a single eth_call (read-only; no signing, no
// nonce, no value) against the token contract, decoding the ABI return.
//
// A revert or an empty/short return is mapped to ErrNotERC20 (the address is not
// an ERC-20 / does not implement the read) so the caller can say "that's not a
// token" with exit 2 rather than a raw transport error. A genuine transport
// failure (the client returns a non-nil error) is propagated UNCHANGED so the
// §5.7 rpc.* taxonomy (exit 6, retryable) is preserved.

// Decimals reads ERC-20 decimals() (selector 0x313ce567) and decodes the uint8.
// An ERC-20 decimals is in [0,255]; a value above 255 (a malformed return) is
// ErrNotERC20. A revert / empty return is ErrNotERC20. The result is used for
// DISPLAY only — amounts cross the system as base-unit strings (no float).
func (Ops) Decimals(ctx context.Context, cc chain.Client, token common.Address) (uint8, error) {
	out, err := callRead(ctx, cc, token, selector(sigDecimals))
	if err != nil {
		return 0, err
	}
	n, ok := decodeUint(out)
	if !ok {
		return 0, ErrNotERC20
	}
	// decimals() returns uint8; anything that doesn't fit a uint8 is not a
	// conforming ERC-20 metadata value.
	if !n.IsUint64() || n.Uint64() > 255 {
		return 0, ErrNotERC20
	}
	return uint8(n.Uint64()), nil // #nosec G115 -- bounded to [0,255] by the guard just above
}

// Symbol reads ERC-20 symbol() (selector 0x95d89b41) and returns the DISPLAY
// symbol. It handles BOTH the canonical ABI `string` return AND the legacy
// `bytes32` return (e.g. early MKR/SAI-era tokens that returned a fixed 32-byte
// symbol): a return of exactly 32 bytes is treated as bytes32 (trailing NULs
// trimmed); otherwise it is decoded as an ABI dynamic string. A revert / empty
// return is ErrNotERC20.
//
// SECURITY (§7.8): this value is for DISPLAY ONLY. It MUST NEVER be used to
// resolve an alias — symbol spoofing is free, so alias resolution is
// registry-only. Callers show this to the user; they never look up a token by it.
func (Ops) Symbol(ctx context.Context, cc chain.Client, token common.Address) (string, error) {
	out, err := callRead(ctx, cc, token, selector(sigSymbol))
	if err != nil {
		return "", err
	}
	s, ok := decodeStringOrBytes32(out)
	if !ok {
		return "", ErrNotERC20
	}
	return s, nil
}

// Name reads name() (selector 0x06fdde03) and returns the DISPLAY name. Like
// Symbol it handles BOTH the canonical ABI `string` return AND the legacy
// `bytes32` return (early tokens that returned a fixed 32-byte name): a return of
// exactly 32 bytes is treated as bytes32 (trailing NULs trimmed); otherwise it is
// decoded as an ABI dynamic string. A revert / empty return is ErrNotERC20.
//
// SECURITY (§7.8): this value is for DISPLAY ONLY (and, for the NFT registry, the
// default-alias source — see service.NFTAdd). It MUST NEVER be used to RESOLVE an
// alias — name spoofing is free, so alias resolution is registry-only. The
// default-alias derivation at `nft add` is a one-time write the user fully
// overrides with --name; it is never the resolution path.
func (Ops) Name(ctx context.Context, cc chain.Client, token common.Address) (string, error) {
	out, err := callRead(ctx, cc, token, selector(sigName))
	if err != nil {
		return "", err
	}
	s, ok := decodeStringOrBytes32(out)
	if !ok {
		return "", ErrNotERC20
	}
	return s, nil
}

// BalanceOf reads ERC-20 balanceOf(address) (selector 0x70a08231) for owner and
// decodes the uint256 base-unit balance. A revert / empty return is ErrNotERC20.
func (Ops) BalanceOf(ctx context.Context, cc chain.Client, token, owner common.Address) (*big.Int, error) {
	data := append(selector(sigBalanceOf), addrWord(owner)...)
	out, err := callRead(ctx, cc, token, data)
	if err != nil {
		return nil, err
	}
	n, ok := decodeUint(out)
	if !ok {
		return nil, ErrNotERC20
	}
	return n, nil
}

// OwnerOf reads ERC-721 ownerOf(uint256) (selector 0x6352211e) and decodes the
// owning address. This is the M6 NFT read; defined now per §2.8 with the ERC-20
// path unaffected. A revert / empty return (e.g. a burned or nonexistent token,
// or a non-721 contract) is ErrNotERC20. tokenID nil is treated as zero.
func (Ops) OwnerOf(ctx context.Context, cc chain.Client, nft common.Address, tokenID *big.Int) (common.Address, error) {
	data := append(selector(sigOwnerOf), uintWord(tokenID)...)
	out, err := callRead(ctx, cc, nft, data)
	if err != nil {
		return common.Address{}, err
	}
	a, ok := decodeAddress(out)
	if !ok {
		return common.Address{}, ErrNotERC20
	}
	return a, nil
}

// ── eth_call helper + ABI-return decoders ──

// callRead performs a read-only eth_call against `to` with `data` at the latest
// block and returns the raw return bytes. A non-nil client error is propagated
// UNCHANGED (preserving the rpc.* taxonomy / retryable hint). A revert that the
// adapter surfaces as a typed error is propagated as-is; a revert surfaced as an
// empty return is detected by the per-method decoder (which maps it to
// ErrNotERC20). A nil/empty successful return is also left to the decoder.
func callRead(ctx context.Context, cc chain.Client, to common.Address, data []byte) ([]byte, error) {
	toAddr := to
	msg := ethereum.CallMsg{To: &toAddr, Data: data}
	out, err := cc.CallContract(ctx, msg, nil)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decodeUint decodes a 32-byte (or longer, taking the first word) ABI uint256
// return into a big.Int. An empty return (a contract that didn't implement the
// method and returned nothing) yields ok=false. A return shorter than 32 bytes is
// also rejected (a conforming uint return is always a full 32-byte word).
func decodeUint(out []byte) (*big.Int, bool) {
	if len(out) < 32 {
		return nil, false
	}
	return new(big.Int).SetBytes(out[:32]), true
}

// decodeAddress decodes a 32-byte ABI address return (the low 20 bytes of the
// first word). An empty/short return yields ok=false.
func decodeAddress(out []byte) (common.Address, bool) {
	if len(out) < 32 {
		return common.Address{}, false
	}
	return common.BytesToAddress(out[:32]), true
}

// decodeStringOrBytes32 decodes an ERC-20 symbol()/name() return, accepting both
// the canonical ABI `string` encoding and the legacy `bytes32` encoding:
//
//   - len == 32: legacy bytes32 — trim trailing NUL bytes and return the prefix.
//     (A non-empty, otherwise-valid 32-byte word is treated as a packed symbol.)
//   - len >= 96 and well-formed: ABI string — head word is the offset (0x20),
//     the next word is the length, then the UTF-8 bytes. Bounds-checked.
//
// An empty or otherwise undecodable return yields ok=false (→ ErrNotERC20).
func decodeStringOrBytes32(out []byte) (string, bool) {
	switch {
	case len(out) == 0:
		return "", false
	case len(out) == 32:
		// Legacy bytes32: trim trailing zero padding.
		s := string(bytes.TrimRight(out, "\x00"))
		if s == "" {
			return "", false
		}
		return s, true
	case len(out) >= 64:
		return decodeABIString(out)
	default:
		return "", false
	}
}

// decodeABIString decodes a canonical ABI dynamic-string return: a 32-byte offset
// word, a 32-byte length word at that offset, then `length` UTF-8 bytes. Every
// index is bounds-checked so a malformed/hostile return cannot panic; a failure
// yields ok=false.
func decodeABIString(out []byte) (string, bool) {
	// Head: the offset to the dynamic data (typically 0x20).
	off := new(big.Int).SetBytes(out[:32])
	if !off.IsUint64() {
		return "", false
	}
	o := off.Uint64()
	// Need the length word fully inside the buffer.
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
