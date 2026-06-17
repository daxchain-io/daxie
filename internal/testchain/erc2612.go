//go:build integration

package testchain

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// erc2612.go deploys the minimal test EIP-2612 permit token (erc2612bytecode.go) to
// anvil and exposes the helpers the M9 sign/verify integration tests need: the
// EIP-712 Permit typed-data JSON builder (Permit712 — the exact apitypes.TypedData
// shape `daxie sign typed` consumes AND the policy recognizer accepts), the on-chain
// nonces/DOMAIN_SEPARATOR/allowance readers (raw eth_call, independent of Daxie's
// own packages — no self-confirmation), and SubmitPermit which calls permit() with a
// Daxie-produced signature and proves the allowance is set. Compiled only under
// `go test -tags integration`.
//
// The Solidity source (compiled offline into erc2612bytecode.go) is a standalone,
// no-import ERC-2612 token: PERMIT_TYPEHASH ==
// keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
// DOMAIN_SEPARATOR over EIP712Domain(name,version,chainId,verifyingContract) with
// name "Permit Test", version "1". The on-chain permit() does ecrecover(digest,v,r,s)
// and asserts recovered == owner, so a wrong/forged signature reverts — the roundtrip
// is a real authorization, not a no-op.

// itSelDomainSeparator / itSelNonces are the read selectors for the permit token,
// pinned literals so the harness reads independently of any Daxie package.
var (
	itSelDomainSeparator = []byte{0x36, 0x44, 0xe5, 0x15} // DOMAIN_SEPARATOR()
	itSelNonces          = []byte{0x7e, 0xce, 0xbe, 0x00} // nonces(address)
)

// DeployERC2612 deploys the test EIP-2612 token from anvil's unlocked dev account 0
// (the funded account the constructor mints the full supply to), waits for the
// receipt, and returns the deployed contract address. Mirrors DeployERC20.
func DeployERC2612(t *testing.T, a *Anvil) common.Address {
	t.Helper()
	params := []any{map[string]any{
		"from": fundedAddr0.Hex(),
		"data": erc2612BytecodeHex,
		"gas":  "0x" + big.NewInt(3_000_000).Text(16),
	}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("erc2612 deploy tx hash decode: %v", err)
	}
	rcpt := a.waitReceipt(t, hash)
	addrStr, _ := rcpt["contractAddress"].(string)
	if addrStr == "" || !common.IsHexAddress(addrStr) {
		t.Fatalf("erc2612 deploy receipt has no contractAddress: %+v", rcpt)
	}
	return common.HexToAddress(addrStr)
}

// PermitNonce reads nonces(owner) for the permit token via a raw eth_call.
func (a *Anvil) PermitNonce(t *testing.T, token, owner common.Address) *big.Int {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append(itSelNonces, common.LeftPadBytes(owner.Bytes(), 32)...))
	return a.ethCallUint(t, token, data)
}

// PermitDomainSeparator reads DOMAIN_SEPARATOR() for the permit token via a raw
// eth_call, returning the 32-byte separator. The harness does NOT need it to build
// the typed JSON (apitypes recomputes it from the domain fields), but the integration
// test asserts the Daxie-computed digest path lines up with the on-chain one by
// submitting the signature, so this reader is provided for diagnostics.
func (a *Anvil) PermitDomainSeparator(t *testing.T, token common.Address) common.Hash {
	t.Helper()
	v := a.ethCallUint(t, token, "0x"+common.Bytes2Hex(itSelDomainSeparator))
	return common.BytesToHash(common.LeftPadBytes(v.Bytes(), 32))
}

// ERC2612Allowance reads allowance(owner, spender) for the permit token via a raw
// eth_call (the same selector as ERC20Allowance — provided as a named alias so the
// M9 test reads naturally).
func (a *Anvil) ERC2612Allowance(t *testing.T, token, owner, spender common.Address) *big.Int {
	t.Helper()
	return a.ERC20Allowance(t, token, owner, spender)
}

// SubmitPermit calls permit(owner, spender, value, deadline, v, r, s) on the token
// from anvil's unlocked dev account 0 (any sender may relay a permit — that is the
// whole point of EIP-2612), waits for the receipt, and FAILS the test if the call
// reverted. A reverted permit means the signature did not recover to owner, so a
// green SubmitPermit + an allowance read == value is the executable proof that the
// Daxie-signed permit is a valid, fund-moving authorization.
func SubmitPermit(t *testing.T, a *Anvil, token, owner, spender common.Address, value, deadline *big.Int, v uint8, r, s [32]byte) {
	t.Helper()
	// permit(address,address,uint256,uint256,uint8,bytes32,bytes32) selector.
	sel := []byte{0xd5, 0x05, 0xac, 0xcf}
	var data []byte
	data = append(data, sel...)
	data = append(data, common.LeftPadBytes(owner.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(spender.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(value.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(deadline.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes([]byte{v}, 32)...)
	data = append(data, r[:]...)
	data = append(data, s[:]...)

	params := []any{map[string]any{
		"from": fundedAddr0.Hex(),
		"to":   token.Hex(),
		"data": "0x" + common.Bytes2Hex(data),
		"gas":  "0x" + big.NewInt(300_000).Text(16),
	}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("permit tx hash decode: %v", err)
	}
	rcpt := a.waitReceipt(t, hash)
	if status, _ := rcpt["status"].(string); status != "0x1" {
		t.Fatalf("permit() reverted (status %v) — the Daxie-signed permit did not recover to the owner: %+v", status, rcpt)
	}
}

// Permit712 builds the EIP-2612 Permit typed-data document as an apitypes.TypedData
// JSON byte slice — the EXACT shape `daxie sign typed --data` consumes and the
// policy recognizer matches (primaryType "Permit" + exactly {owner,spender,value,
// nonce,deadline} + domain.verifyingContract == token + domain.chainId). All
// uint256 values cross as DECIMAL STRINGS (the only precision-safe JSON form; the
// recognizer's messageBig parses them). The domain name/version are the token's
// ("Permit Test" / "1"); chainID is a parameter so the wrong-chainId-deny scenario
// can pass a mismatched id (1) while signing on anvil (31337).
func Permit712(chainID int64, token, owner, spender common.Address, value, nonce, deadline *big.Int) []byte {
	doc := map[string]any{
		"types": map[string]any{
			"EIP712Domain": []map[string]string{
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"},
			},
			"Permit": []map[string]string{
				{"name": "owner", "type": "address"},
				{"name": "spender", "type": "address"},
				{"name": "value", "type": "uint256"},
				{"name": "nonce", "type": "uint256"},
				{"name": "deadline", "type": "uint256"},
			},
		},
		"primaryType": "Permit",
		"domain": map[string]any{
			"name":              "Permit Test",
			"version":           "1",
			"chainId":           fmt.Sprintf("%d", chainID),
			"verifyingContract": token.Hex(),
		},
		"message": map[string]any{
			"owner":    owner.Hex(),
			"spender":  spender.Hex(),
			"value":    value.String(),
			"nonce":    nonce.String(),
			"deadline": deadline.String(),
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		// A static document; a marshal error is a programming bug, not a test condition.
		panic("Permit712 marshal: " + err.Error())
	}
	return b
}

// UnknownTyped712 builds a NON-recognizer EIP-712 document (a Seaport-ish
// OrderComponents primaryType) — used by the unknown-typed deny scenario. It is a
// well-formed typed-data doc the digest path can hash, but no recognizer matches it,
// so it hits the stage-5 deny-by-default gate (until `policy typed allow` opens it).
func UnknownTyped712(chainID int64, verifying, offerer common.Address) []byte {
	doc := map[string]any{
		"types": map[string]any{
			"EIP712Domain": []map[string]string{
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"},
			},
			"OrderComponents": []map[string]string{
				{"name": "offerer", "type": "address"},
				{"name": "startAmount", "type": "uint256"},
				{"name": "salt", "type": "uint256"},
			},
		},
		"primaryType": "OrderComponents",
		"domain": map[string]any{
			"name":              "Seaport",
			"version":           "1.5",
			"chainId":           fmt.Sprintf("%d", chainID),
			"verifyingContract": verifying.Hex(),
		},
		"message": map[string]any{
			"offerer":     offerer.Hex(),
			"startAmount": "1000000000000000000",
			"salt":        "42",
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic("UnknownTyped712 marshal: " + err.Error())
	}
	return b
}
