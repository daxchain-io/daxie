// Package erc is the pure ERC-20/721/1155 calldata builder + the per-request
// metadata reader (design §2.8). It is a provider leaf: it imports chain (for the
// Client param on the metadata reads), domain (the error taxonomy), and
// go-ethereum value/behavioral packages (common, crypto, accounts/abi,
// core/types) — NEVER service, a frontend, policy, or registry.
//
// The split mandated by §2.8 / requirements §6 (every invocation may choose its
// network + endpoint):
//
//   - The calldata builders (TransferCalldata, ApproveCalldata,
//     SafeTransferFromCalldata) are PURE: no network, no chain.Client, no state.
//     They produce the exact `selector || abi(args)` byte string the EVM expects,
//     and the §2.9 golden test pins those bytes byte-for-byte against
//     cast/foundry output — this encoder is validated against foundry, not merely
//     round-tripped.
//   - The metadata reads (Decimals, Symbol, BalanceOf, OwnerOf) take a
//     chain.Client PER CALL (the per-request endpoint binding), so one Ops value
//     serves every network — the endpoint is a parameter, not constructor state.
//
// Ops is a stateless concrete struct (§2.8): the value receiver carries no state,
// so service can hold a bare erc.Ops and hand it the request's chain.Client.
//
// Anti-spoofing note (§7.8 / requirements §2): Symbol returns the on-chain
// DISPLAY symbol only. It MUST NEVER be used to resolve an alias — alias
// resolution is registry-only (a name not found is an error, never a symbol()
// lookup). This package neither performs nor enables alias resolution; it only
// reads the display symbol the caller shows the user.
package erc

import (
	"math/big"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Ops is the stateless ERC operations namespace (§2.8). Value receiver; no state,
// so a single zero value serves every network and every concurrent request.
type Ops struct{}

// Function selectors (the first 4 bytes of keccak256 of the canonical signature).
// They are pinned as literal constants AND independently re-derived in the test
// from the signature string, so a typo cannot pass silently. The golden-byte test
// then proves the full calldata (selector || args) matches cast/foundry.
const (
	// sigTransfer is ERC-20 transfer(address,uint256) → selector 0xa9059cbb.
	sigTransfer = "transfer(address,uint256)"
	// sigApprove is ERC-20 approve(address,uint256) → selector 0x095ea7b3.
	sigApprove = "approve(address,uint256)"
	// sigBalanceOf is ERC-20 balanceOf(address) → selector 0x70a08231.
	sigBalanceOf = "balanceOf(address)"
	// sigAllowance is ERC-20 allowance(address,address) → selector 0xdd62ed3e.
	// (Read-only; service uses it for `token allowance`. Exposed via the selector
	// so the builder lives in one place, but allowance has no calldata builder on
	// Ops — service hand-builds the two-arg call; kept here for the golden test.)
	sigAllowance = "allowance(address,address)"
	// sigDecimals is ERC-20 decimals() → selector 0x313ce567.
	sigDecimals = "decimals()"
	// sigSymbol is ERC-20 symbol() → selector 0x95d89b41.
	sigSymbol = "symbol()"
	// sigName is name() → selector 0x06fdde03. Backs Ops.Name (a DISPLAY read),
	// which the M6 NFT registry uses as the default-alias source at `nft add`
	// (overridable with --name; never the resolution path — §7.8 anti-spoofing).
	sigName = "name()"
	// sigOwnerOf is ERC-721 ownerOf(uint256) → selector 0x6352211e (M6 NFT read).
	sigOwnerOf = "ownerOf(uint256)"
	// sigSafeTransferFrom721 is ERC-721 safeTransferFrom(address,address,uint256)
	// → selector 0x42842e0e (M6 NFT transfer).
	sigSafeTransferFrom721 = "safeTransferFrom(address,address,uint256)"
	// sigSafeTransferFrom1155 is ERC-1155
	// safeTransferFrom(address,address,uint256,uint256,bytes) → selector
	// 0xf242432a (M6 NFT transfer).
	sigSafeTransferFrom1155 = "safeTransferFrom(address,address,uint256,uint256,bytes)"
	// sigSupportsInterface is ERC-165 supportsInterface(bytes4) → selector
	// 0x01ffc9a7 (M6 kind detection at `nft add`). The DetectKind/SupportsInterface
	// reads live in nft.go (same package, same Ops value receiver).
	sigSupportsInterface = "supportsInterface(bytes4)"
	// sigBalanceOf1155 is ERC-1155 balanceOf(address,uint256) → selector
	// 0x00fdd58e (M6 NFT read). DISTINCT from the ERC-20 balanceOf(address)
	// 0x70a08231 above (a second uint256 id arg and a different selector).
	sigBalanceOf1155 = "balanceOf(address,uint256)"
)

// ERC-165 interface IDs (EIP-165 §"How interfaces are identified": the bytewise
// XOR of an interface's function selectors). They are pinned as literal 4-byte
// values AND re-asserted in the test against the well-known canonical IDs, so a
// typo cannot pass silently. supportsInterface(id) reporting true selects the
// token standard at `nft add` (the result is STORED — resolution thereafter is
// registry-only, never a re-detection; the anti-spoofing wall).
var (
	// iface721 is the ERC-721 interface ID (EIP-721).
	iface721 = [4]byte{0x80, 0xac, 0x58, 0xcd}
	// iface1155 is the ERC-1155 interface ID (EIP-1155).
	iface1155 = [4]byte{0xd9, 0xb6, 0x7a, 0x26}
)

// MaxUint256 is the unlimited-approval sentinel (2^256 - 1). An approve(spender,
// MaxUint256) is the "infinite allowance" the policy unlimited ceremony matches on
// (§4.2: Unlimited if value == 2^256-1). Exported so service flags Check.Unlimited
// against the SAME value the calldata encodes — the golden test pins the encoded
// ff…ff word so the ceremony and the wire agree.
//
// It is returned as a fresh copy so a caller can never mutate the package value.
func MaxUint256() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
}

// MaxUint160 is the uint160 unlimited sentinel (2^160 - 1) — a Permit2-style
// "infinite" amount (§4.2). A bounded approve(spender, 2^160-1) is unbounded for
// every realistic balance; the §4.2 sentinel set treats it as unlimited.
// Returned as a fresh copy.
func MaxUint160() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
}

// MaxUint96 is the uint96 unlimited sentinel (2^96 - 1) — the §4.2 sentinel set's
// smallest member (some token/permit shapes pack the allowance into a uint96).
// Returned as a fresh copy.
func MaxUint96() *big.Int {
	return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 96), big.NewInt(1))
}

// IsUnlimitedAmount reports whether an approval amount is one of the §4.2 unlimited
// sentinels (2^256-1, uint160 max, or uint96 max). This is the SINGLE match set the
// approve calldata builder and the policy unlimited-ack ceremony must agree on: an
// approval whose amount equals any sentinel is unbounded and MUST take the
// `--unlimited --yes` ceremony regardless of HOW it was specified (the typed
// --unlimited flag OR a literal sentinel passed via --amount). design §4.2 lines
// 1633/1644: "Unlimited if amount ∈ the §4.2 unlimited sentinels (2²⁵⁶−1,
// uint96/uint160 max)" and the ceremony fires "exactly as on the typed path".
// A nil amount (the revoke/zero encoding) is never unlimited.
func IsUnlimitedAmount(amount *big.Int) bool {
	if amount == nil {
		return false
	}
	return amount.Cmp(MaxUint256()) == 0 ||
		amount.Cmp(MaxUint160()) == 0 ||
		amount.Cmp(MaxUint96()) == 0
}

// ErrNotERC20 is the typed "this address is not an ERC-20 token" error the
// metadata reads return when decimals()/symbol()/balanceOf() reverts or returns
// an empty/undecodable result (an EOA, a non-token contract, or a contract that
// does not implement the ERC-20 metadata surface). It maps to exit 2 (usage
// class) via the "usage" prefix rule in §5.7 — a caller-input error (the user
// pointed at the wrong address), not a daxie bug.
var ErrNotERC20 = domain.New("usage.not_erc20", "address is not an ERC-20 token (no decimals/symbol)")

// ErrNotNFT is the typed "this address is not an ERC-721 / ERC-1155" error
// DetectKind (nft.go) returns when ERC-165 supportsInterface reports neither the
// 721 nor the 1155 interface (an EOA, a plain ERC-20, or a non-165 contract that
// reverts/returns false). Like ErrNotERC20 it maps to exit 2 (usage class) via
// the "usage" prefix — a caller-input error (the user pointed `nft add` at the
// wrong address), not a daxie bug. A genuine transport error is NEVER relabeled
// to this (it propagates so the §5.7 rpc.* taxonomy / retryable hint survive).
var ErrNotNFT = domain.New("usage.not_nft", "address is not an ERC-721 or ERC-1155 contract (ERC-165 check failed)")

// ── PURE calldata builders (no network) — §2.8 verbatim ──

// TransferCalldata builds the ERC-20 transfer(address,uint256) calldata:
// selector 0xa9059cbb || abi(to, amount). amount is in BASE UNITS (the caller has
// already applied decimals via ethunit — this package never sees a decimal/float).
// Pure: no network, no state. A nil amount is treated as zero.
//
// The policy destination for the resulting transfer is `to` (the decoded
// recipient), NEVER the token contract — that decision lives in service; this
// builder only encodes the recipient the caller passes.
func (Ops) TransferCalldata(to common.Address, amount *big.Int) []byte {
	return pack(sigTransfer, addrWord(to), uintWord(amount))
}

// ApproveCalldata builds the ERC-20 approve(address,uint256) calldata:
// selector 0x095ea7b3 || abi(spender, amount). amount is in base units; pass
// MaxUint256() for an unlimited approval (the policy ceremony matches that
// sentinel) and big.NewInt(0) to REVOKE (approve(spender, 0)). Pure. A nil amount
// is treated as zero (the revoke encoding).
//
// The policy destination for the resulting approval is `spender` (the decoded
// spender), NEVER the token contract — that decision lives in service.
func (Ops) ApproveCalldata(spender common.Address, amount *big.Int) []byte {
	return pack(sigApprove, addrWord(spender), uintWord(amount))
}

// SafeTransferFromCalldata builds an NFT safeTransferFrom (M6 consumer; defined
// now per §2.8 so the Ops surface is complete). amount selects the standard:
//
//   - amount == nil → ERC-721 safeTransferFrom(address from,address to,uint256
//     tokenId), selector 0x42842e0e || abi(from, to, tokenID).
//   - amount != nil → ERC-1155 safeTransferFrom(address from,address to,uint256
//     id,uint256 amount,bytes data), selector 0xf242432a || abi(from, to,
//     tokenID, amount, data=empty). The bytes arg is encoded as an empty dynamic
//     byte string (offset word 0xa0 + length word 0x00).
//
// tokenID nil is treated as zero. Pure: no network, no state.
func (Ops) SafeTransferFromCalldata(from, to common.Address, tokenID, amount *big.Int) []byte {
	if amount == nil {
		// ERC-721: three static 32-byte words.
		return pack(sigSafeTransferFrom721, addrWord(from), addrWord(to), uintWord(tokenID))
	}
	// ERC-1155: four static words (from,to,id,amount) + a dynamic empty bytes.
	// The dynamic tail follows the ABI: the 5th head word is the offset to the
	// bytes (5 words * 32 = 0xa0 from the start of the arg block), then the tail
	// is a single length word = 0.
	const bytesOffset = 5 * 32 // 0xa0
	return pack(sigSafeTransferFrom1155,
		addrWord(from),
		addrWord(to),
		uintWord(tokenID),
		uintWord(amount),
		uintWord(big.NewInt(bytesOffset)), // offset to the dynamic bytes arg
		uintWord(big.NewInt(0)),           // bytes length = 0 (empty data)
	)
}

// ── internal ABI packers (hand-packed; the golden test validates byte-for-byte) ──

// keccak256Sig returns the full keccak256 of a canonical signature string. It is
// the single keccak path the package uses: selector() takes its first 4 bytes for
// a function selector, and transfers.go takes the full 32 bytes for the Transfer
// event topic[0]. This is exactly how solc/cast derive both, so the golden test's
// cast output matches.
func keccak256Sig(sig string) []byte {
	return crypto.Keccak256([]byte(sig))
}

// selector returns the 4-byte function selector for a canonical signature string
// (the first 4 bytes of its keccak256).
func selector(sig string) []byte {
	return keccak256Sig(sig)[:4]
}

// pack concatenates the selector for sig with each pre-encoded 32-byte word (and
// any dynamic tail words, already in order) into the final calldata. Each word
// must already be exactly 32 bytes (addrWord/uintWord guarantee this).
func pack(sig string, words ...[]byte) []byte {
	out := make([]byte, 0, 4+len(words)*32)
	out = append(out, selector(sig)...)
	for _, w := range words {
		out = append(out, w...)
	}
	return out
}

// addrWord left-pads a 20-byte address to a 32-byte ABI word (the high 12 bytes
// are zero), matching the ABI encoding of an `address` argument.
func addrWord(a common.Address) []byte {
	return common.LeftPadBytes(a.Bytes(), 32)
}

// uintWord left-pads an unsigned big integer to a 32-byte ABI word, matching the
// ABI encoding of a `uint256` argument. A nil or negative value is treated as
// zero (callers never pass a negative base-unit amount; this is defensive — the
// EVM has no negative uint256). The value is read-only (Bytes() does not mutate).
func uintWord(v *big.Int) []byte {
	if v == nil || v.Sign() < 0 {
		return make([]byte, 32)
	}
	return common.LeftPadBytes(v.Bytes(), 32)
}
