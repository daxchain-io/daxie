//go:build integration

package testchain

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// erc20.go deploys the minimal test ERC-20 (erc20bytecode.go) to anvil and exposes
// RAW-RPC assertion readers (balanceOf / allowance) so the M5 integration tests
// assert on-chain state INDEPENDENTLY of Daxie's own erc package — no
// self-confirmation. Deploy + the readers go straight to anvil via the test-only rpc
// helper (the production adapter does not expose eth_sendTransaction from an unlocked
// account). Compiled only under `go test -tags integration`.

// ERC-20 read selectors used by the raw-RPC readers (first 4 keccak bytes of the
// canonical signature). Pinned literals so the harness asserts independently of the
// erc package under test.
var (
	itSelBalanceOf = []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
	itSelAllowance = []byte{0xdd, 0x62, 0xed, 0x3e} // allowance(address,address)
)

// DeployERC20 deploys the test ERC-20 from anvil's unlocked dev account 0 (the
// funded account that the constructor mints the full supply to), waits for the
// receipt, and returns the deployed contract address. The deployer holds 1,000,000
// TST after deploy; use MintTo to move some to another account if needed.
func DeployERC20(t *testing.T, a *Anvil) common.Address {
	t.Helper()
	// eth_sendTransaction from the unlocked dev account 0 with data = creation
	// bytecode (no `to`).
	params := []any{map[string]any{
		"from": fundedAddr0.Hex(),
		"data": erc20BytecodeHex,
		"gas":  "0x" + big.NewInt(3_000_000).Text(16),
	}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("deploy tx hash decode: %v", err)
	}
	rcpt := a.waitReceipt(t, hash)
	addrStr, _ := rcpt["contractAddress"].(string)
	if addrStr == "" || !common.IsHexAddress(addrStr) {
		t.Fatalf("deploy receipt has no contractAddress: %+v", rcpt)
	}
	return common.HexToAddress(addrStr)
}

// MintTo moves `amount` TST from the deployer (dev account 0) to `to` via a real
// transfer (the test token has no mint function; the deployer holds the full
// supply). It uses eth_sendTransaction from the unlocked deployer and waits for the
// receipt.
func MintTo(t *testing.T, a *Anvil, token, to common.Address, amount *big.Int) {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append([]byte{0xa9, 0x05, 0x9c, 0xbb}, // transfer(address,uint256)
		append(common.LeftPadBytes(to.Bytes(), 32), common.LeftPadBytes(amount.Bytes(), 32)...)...))
	params := []any{map[string]any{"from": fundedAddr0.Hex(), "to": token.Hex(), "data": data}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("mint tx hash decode: %v", err)
	}
	a.waitReceipt(t, hash)
}

// ERC20BalanceOf reads balanceOf(owner) for token via a raw eth_call (independent of
// Daxie's erc package). It returns the base-unit balance.
func (a *Anvil) ERC20BalanceOf(t *testing.T, token, owner common.Address) *big.Int {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append(itSelBalanceOf, common.LeftPadBytes(owner.Bytes(), 32)...))
	return a.ethCallUint(t, token, data)
}

// ERC20Allowance reads allowance(owner, spender) for token via a raw eth_call.
func (a *Anvil) ERC20Allowance(t *testing.T, token, owner, spender common.Address) *big.Int {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append(itSelAllowance,
		append(common.LeftPadBytes(owner.Bytes(), 32), common.LeftPadBytes(spender.Bytes(), 32)...)...))
	return a.ethCallUint(t, token, data)
}

// ethCallUint performs eth_call(to, data) at latest and decodes the uint256 return.
func (a *Anvil) ethCallUint(t *testing.T, to common.Address, data string) *big.Int {
	t.Helper()
	params := []any{map[string]any{"to": to.Hex(), "data": data}, "latest"}
	raw := a.rpc(t, "eth_call", params)
	var hexStr string
	if err := json.Unmarshal(raw, &hexStr); err != nil {
		t.Fatalf("eth_call decode: %v", err)
	}
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if hexStr == "" {
		return big.NewInt(0)
	}
	v, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		t.Fatalf("eth_call return %q is not hex", hexStr)
	}
	return v
}

// waitReceipt polls eth_getTransactionReceipt until the tx is mined (or a deadline),
// returning the decoded receipt map. anvil auto-mines instantly, so this returns
// promptly under Spawn (and the caller controls mining under SpawnManualMining).
func (a *Anvil) waitReceipt(t *testing.T, hash string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		raw := a.rpc(t, "eth_getTransactionReceipt", []any{hash})
		if len(raw) > 0 && string(raw) != "null" {
			var rcpt map[string]any
			if err := json.Unmarshal(raw, &rcpt); err != nil {
				t.Fatalf("receipt decode: %v", err)
			}
			return rcpt
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tx %s did not mine within the deadline", hash)
	return nil
}
