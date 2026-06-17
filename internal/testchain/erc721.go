//go:build integration

package testchain

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// erc721.go deploys the minimal test ERC-721 (erc721bytecode.go) to anvil and
// exposes RAW-RPC assertion readers (ownerOf / supportsInterface) so the M6
// integration tests assert on-chain state INDEPENDENTLY of Daxie's own erc package
// — no self-confirmation. Deploy + mint go straight to anvil via the test-only rpc
// helper (the production adapter does not expose eth_sendTransaction from an
// unlocked account). Compiled only under `go test -tags integration`.

// ERC-721 selectors used by the harness (deploy/mint) + the raw-RPC readers.
// Pinned literals so the harness asserts independently of the erc package under test.
var (
	itSelMint721       = []byte{0x40, 0xc1, 0x0f, 0x19} // mint(address,uint256)
	itSelOwnerOf       = []byte{0x63, 0x52, 0x21, 0x1e} // ownerOf(uint256)
	itSelSupportsIface = []byte{0x01, 0xff, 0xc9, 0xa7} // supportsInterface(bytes4)
)

// DeployERC721 deploys the test ERC-721 from anvil's unlocked dev account 0, waits
// for the receipt, and returns the deployed contract address. The collection mints
// nothing in its constructor; use MintNFT721 to mint a token id to an owner.
func DeployERC721(t *testing.T, a *Anvil) common.Address {
	t.Helper()
	params := []any{map[string]any{
		"from": fundedAddr0.Hex(),
		"data": erc721BytecodeHex,
		"gas":  "0x" + big.NewInt(3_000_000).Text(16),
	}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("deploy 721 tx hash decode: %v", err)
	}
	rcpt := a.waitReceipt(t, hash)
	addrStr, _ := rcpt["contractAddress"].(string)
	if addrStr == "" || !common.IsHexAddress(addrStr) {
		t.Fatalf("deploy 721 receipt has no contractAddress: %+v", rcpt)
	}
	return common.HexToAddress(addrStr)
}

// MintNFT721 mints token id `tokenID` to `to` via the test collection's
// mint(address,uint256), from the unlocked dev account 0, and waits for the
// receipt.
func MintNFT721(t *testing.T, a *Anvil, token, to common.Address, tokenID *big.Int) {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append(itSelMint721,
		append(common.LeftPadBytes(to.Bytes(), 32), common.LeftPadBytes(tokenID.Bytes(), 32)...)...))
	params := []any{map[string]any{"from": fundedAddr0.Hex(), "to": token.Hex(), "data": data}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("mint 721 tx hash decode: %v", err)
	}
	a.waitReceipt(t, hash)
}

// ERC721OwnerOf reads ownerOf(tokenID) for token via a raw eth_call (independent of
// Daxie's erc package). It returns the owning address.
func (a *Anvil) ERC721OwnerOf(t *testing.T, token common.Address, tokenID *big.Int) common.Address {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append(itSelOwnerOf, common.LeftPadBytes(tokenID.Bytes(), 32)...))
	out := a.ethCallRaw(t, token, data)
	if len(out) < 32 {
		t.Fatalf("ownerOf(%s) returned %d bytes, want 32", tokenID, len(out))
	}
	return common.BytesToAddress(out[:32])
}

// ERC721SupportsInterface reads supportsInterface(id4) for token via a raw eth_call.
func (a *Anvil) ERC721SupportsInterface(t *testing.T, token common.Address, id4 [4]byte) bool {
	t.Helper()
	var word [32]byte
	copy(word[:4], id4[:]) // bytes4 is LEFT-aligned
	data := "0x" + common.Bytes2Hex(append(itSelSupportsIface, word[:]...))
	out := a.ethCallRaw(t, token, data)
	return len(out) >= 32 && new(big.Int).SetBytes(out[:32]).Sign() != 0
}

// ethCallRaw performs eth_call(to, data) at latest and returns the raw return
// bytes (decoded from the 0x-hex result).
func (a *Anvil) ethCallRaw(t *testing.T, to common.Address, data string) []byte {
	t.Helper()
	params := []any{map[string]any{"to": to.Hex(), "data": data}, "latest"}
	raw := a.rpc(t, "eth_call", params)
	var hexStr string
	if err := json.Unmarshal(raw, &hexStr); err != nil {
		t.Fatalf("eth_call decode: %v", err)
	}
	return common.FromHex(strings.TrimSpace(hexStr))
}
