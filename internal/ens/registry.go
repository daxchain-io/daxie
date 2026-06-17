package ens

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// RegistryAddr is the canonical ENS registry (ENSRegistryWithFallback) address.
// It is the SAME 20-byte address on Ethereum mainnet and on every official
// testnet that has ENS deployed (Sepolia, Holesky, …) — ENS chose a deterministic
// deployment so the registry entry point is network-independent. The per-network
// difference is the *records inside* the registry, not its address.
const RegistryAddr = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"

// Canonical chain ids for the networks that carry the ENS registry at RegistryAddr.
var (
	chainMainnet = big.NewInt(1)        // Ethereum mainnet
	chainSepolia = big.NewInt(11155111) // Sepolia testnet
)

// registryAddr is RegistryAddr parsed once.
var registryAddr = common.HexToAddress(RegistryAddr)

// testRegistries is a test-only override table keyed by chain id (decimal string).
// Production never writes it; an //go:build integration helper sets it via
// SetTestRegistry so the anvil mock registry (deployed at a non-canonical address
// on chain id 31337) can be reached without faking the chain.Client. It is read
// FIRST by RegistryFor so a test override always wins. Keyed by string to avoid
// holding *big.Int map keys (pointer identity).
var testRegistries = map[string]common.Address{}

// RegistryFor returns the ENS registry contract address for a chain id. Mainnet
// (1) and Sepolia (11155111) share the canonical RegistryAddr. Any other chain id
// is ErrNoRegistry UNLESS a test override was installed for it (SetTestRegistry,
// integration builds only) — which is how the anvil mock registry is injected
// without an ens.Resolver interface (§2.8: the only ENS test seam is the
// chain.Client fake one layer down; the integration path injects the real mock's
// address here instead). A nil chain id is ErrNoRegistry.
//
// The resolver reads the chain id from the per-call chain.Client (cc.ChainID), so
// one Resolver value serves every network and the registry is chosen per request,
// never held as constructor state.
func RegistryFor(chainID *big.Int) (common.Address, error) {
	if chainID == nil {
		return common.Address{}, ErrNoRegistry
	}
	if a, ok := testRegistries[chainID.String()]; ok {
		return a, nil
	}
	switch {
	case chainID.Cmp(chainMainnet) == 0, chainID.Cmp(chainSepolia) == 0:
		return registryAddr, nil
	default:
		return common.Address{}, ErrNoRegistry
	}
}
