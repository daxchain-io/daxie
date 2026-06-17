//go:build integration

package testchain

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// ens.go deploys the mock ENS contract (ensbytecode.go) to anvil and exposes the
// test-only writers (setAddr / setName / setResolver) + raw-RPC readers the M7
// integration tests use. Like erc20.go it goes straight to anvil via raw
// eth_sendTransaction from the unlocked dev account 0, and the readers go straight
// to eth_call — so the tests assert on-chain ENS state INDEPENDENTLY of daxie's own
// internal/ens package (no self-confirmation). Compiled only under
// `go test -tags integration`.
//
// The mock is a COMBINED registry + public resolver: registry.resolver(node)
// returns the contract itself unless an explicit per-node resolver was set, and the
// same contract answers addr(node)/name(node). That mirrors the real ENS call
// sequence internal/ens walks: registry.resolver(node) → resolver.addr(node).

// Mock ENS function selectors (first 4 keccak bytes of the canonical signature).
// Pinned literals so the harness writes/reads independently of the ens package.
var (
	itSelSetAddr     = []byte{0xd5, 0xfa, 0x2b, 0x00} // setAddr(bytes32,address)
	itSelSetName     = []byte{0x77, 0x37, 0x22, 0x13} // setName(bytes32,string)
	itSelSetResolver = []byte{0x18, 0x96, 0xf7, 0x0a} // setResolver(bytes32,address)
	itSelEnsResolver = []byte{0x01, 0x78, 0xb8, 0xbf} // resolver(bytes32)
	itSelEnsAddr     = []byte{0x3b, 0x3b, 0x57, 0xde} // addr(bytes32)
)

// DeployENS deploys the mock ENS (registry+resolver) from anvil's unlocked dev
// account 0, waits for the receipt, and returns the deployed address. The test then
// injects this address as the chain-31337 registry via ens.SetTestRegistry so
// internal/ens.RegistryFor(31337) resolves to it (the §2.8 integration-only hook).
func DeployENS(t *testing.T, a *Anvil) common.Address {
	t.Helper()
	params := []any{map[string]any{
		"from": fundedAddr0.Hex(),
		"data": ensBytecodeHex,
		"gas":  "0x" + big.NewInt(3_000_000).Text(16),
	}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("ens deploy tx hash decode: %v", err)
	}
	rcpt := a.waitReceipt(t, hash)
	addrStr, _ := rcpt["contractAddress"].(string)
	if addrStr == "" || !common.IsHexAddress(addrStr) {
		t.Fatalf("ens deploy receipt has no contractAddress: %+v", rcpt)
	}
	return common.HexToAddress(addrStr)
}

// ENSSetAddr registers a forward record: addr(node) = a. node is the EIP-137
// namehash of the name (compute via ens.Namehash in the test). Re-pointing the same
// node to a different address is how the pin-drift scenario is staged.
func (a *Anvil) ENSSetAddr(t *testing.T, registry common.Address, node [32]byte, addr common.Address) {
	t.Helper()
	data := append(append([]byte{}, itSelSetAddr...), node[:]...)
	data = append(data, common.LeftPadBytes(addr.Bytes(), 32)...)
	a.ensWrite(t, registry, data)
}

// ENSSetResolver sets a per-node resolver (registry.resolver(node) = r). The mock
// returns the contract itself when unset, so tests use this only to point a node at
// a DIFFERENT resolver address (a no-resolver / zero-resolver case is staged by
// pointing at address(0) via a node that was never set on the combined contract).
func (a *Anvil) ENSSetResolver(t *testing.T, registry common.Address, node [32]byte, r common.Address) {
	t.Helper()
	data := append(append([]byte{}, itSelSetResolver...), node[:]...)
	data = append(data, common.LeftPadBytes(r.Bytes(), 32)...)
	a.ensWrite(t, registry, data)
}

// ENSSetName sets the reverse record name(node) = n (node is the namehash of
// "<lowerhex(addr)>.addr.reverse"). The mock ABI-encodes the dynamic string return;
// the test stages a forward record too so internal/ens.Reverse's forward-verify
// passes (and breaks the forward record to assert the unverified→"" path).
func (a *Anvil) ENSSetName(t *testing.T, registry common.Address, node [32]byte, n string) {
	t.Helper()
	// abi-encode setName(bytes32 node, string n): head = [node][offset=0x40],
	// tail = [len][padded bytes].
	nameBytes := []byte(n)
	data := append(append([]byte{}, itSelSetName...), node[:]...)
	data = append(data, common.LeftPadBytes(big.NewInt(0x40).Bytes(), 32)...) // offset to string
	data = append(data, common.LeftPadBytes(big.NewInt(int64(len(nameBytes))).Bytes(), 32)...)
	// right-pad the string bytes to a 32-byte boundary
	padded := make([]byte, ((len(nameBytes)+31)/32)*32)
	copy(padded, nameBytes)
	data = append(data, padded...)
	a.ensWrite(t, registry, data)
}

// ENSResolverOf reads registry.resolver(node) via a raw eth_call (independent of the
// ens package). Returns the resolver address.
func (a *Anvil) ENSResolverOf(t *testing.T, registry common.Address, node [32]byte) common.Address {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append(append([]byte{}, itSelEnsResolver...), node[:]...))
	return a.ensCallAddr(t, registry, data)
}

// ENSAddrOf reads resolver.addr(node) via a raw eth_call (independent of the ens
// package). Returns the resolved address (zero if unset).
func (a *Anvil) ENSAddrOf(t *testing.T, resolver common.Address, node [32]byte) common.Address {
	t.Helper()
	data := "0x" + common.Bytes2Hex(append(append([]byte{}, itSelEnsAddr...), node[:]...))
	return a.ensCallAddr(t, resolver, data)
}

// ensWrite sends a raw eth_sendTransaction to the mock ENS from dev account 0 and
// waits for the receipt.
func (a *Anvil) ensWrite(t *testing.T, to common.Address, data []byte) {
	t.Helper()
	params := []any{map[string]any{
		"from": fundedAddr0.Hex(),
		"to":   to.Hex(),
		"data": "0x" + common.Bytes2Hex(data),
		"gas":  "0x" + big.NewInt(300_000).Text(16),
	}}
	hashRaw := a.rpc(t, "eth_sendTransaction", params)
	var hash string
	if err := json.Unmarshal(hashRaw, &hash); err != nil {
		t.Fatalf("ens write tx hash decode: %v", err)
	}
	a.waitReceipt(t, hash)
}

// ensCallAddr performs eth_call(to, data) at latest and decodes the address return
// (the low 20 bytes of the 32-byte word).
func (a *Anvil) ensCallAddr(t *testing.T, to common.Address, data string) common.Address {
	t.Helper()
	params := []any{map[string]any{"to": to.Hex(), "data": data}, "latest"}
	raw := a.rpc(t, "eth_call", params)
	var hexStr string
	if err := json.Unmarshal(raw, &hexStr); err != nil {
		t.Fatalf("ens eth_call decode: %v", err)
	}
	b := common.FromHex(hexStr)
	if len(b) < 32 {
		return common.Address{}
	}
	return common.BytesToAddress(b[len(b)-20:])
}
