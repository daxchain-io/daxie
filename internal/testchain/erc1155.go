//go:build integration

package testchain

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// erc1155.go deploys the minimal test ERC-1155 (erc1155bytecode.go) to anvil and
// exposes a RAW-RPC balanceOf reader so the M6 integration tests assert on-chain
// state INDEPENDENTLY of Daxie's own erc package — no self-confirmation. Deploy +
// mint go straight to anvil via the test-only rpc helper. Compiled only under
// `go test -tags integration`.

// ERC-1155 selectors used by the harness (deploy/mint) + the raw-RPC reader.
var (
	itSelMint1155      = []byte{0x15, 0x6e, 0x29, 0xf6} // mint(address,uint256,uint256)
	itSelBalanceOf1155 = []byte{0x00, 0xfd, 0xd5, 0x8e} // balanceOf(address,uint256)
)

// DeployERC1155 deploys the test ERC-1155 from anvil's unlocked dev account 0,
// waits for the receipt, and returns the deployed contract address. Use MintNFT1155
// to mint a quantity of an id to an owner.
func DeployERC1155(t *testing.T, a *Anvil) common.Address {
	t.Helper()
	params := []any{map[string]any{
		"from": fundedAddr0.Hex(),
		"data": erc1155BytecodeHex,
		"gas":  "0x" + big.NewInt(3_000_000).Text(16),
	}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("deploy 1155 tx hash decode: %v", err)
	}
	rcpt := a.waitReceipt(t, hash)
	addrStr, _ := rcpt["contractAddress"].(string)
	if addrStr == "" || !common.IsHexAddress(addrStr) {
		t.Fatalf("deploy 1155 receipt has no contractAddress: %+v", rcpt)
	}
	return common.HexToAddress(addrStr)
}

// MintNFT1155 mints `amount` of token id `tokenID` to `to` via the test
// collection's mint(address,uint256,uint256), from the unlocked dev account 0, and
// waits for the receipt.
func MintNFT1155(t *testing.T, a *Anvil, token, to common.Address, tokenID, amount *big.Int) {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append(itSelMint1155,
		append(common.LeftPadBytes(to.Bytes(), 32),
			append(common.LeftPadBytes(tokenID.Bytes(), 32), common.LeftPadBytes(amount.Bytes(), 32)...)...)...))
	params := []any{map[string]any{"from": fundedAddr0.Hex(), "to": token.Hex(), "data": data}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("mint 1155 tx hash decode: %v", err)
	}
	a.waitReceipt(t, hash)
}

// ERC1155BalanceOf reads balanceOf(owner, id) for token via a raw eth_call
// (independent of Daxie's erc package). It returns the base-unit balance.
func (a *Anvil) ERC1155BalanceOf(t *testing.T, token, owner common.Address, tokenID *big.Int) *big.Int {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append(itSelBalanceOf1155,
		append(common.LeftPadBytes(owner.Bytes(), 32), common.LeftPadBytes(tokenID.Bytes(), 32)...)...))
	return a.ethCallUint(t, token, data)
}
