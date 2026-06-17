//go:build integration

package ens

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// SetTestRegistry installs (or, with the zero address, removes) a per-chain-id ENS
// registry override for integration tests. It exists ONLY under the `integration`
// build tag (plan §1 option (b)): the anvil mock ENS registry is deployed at a
// non-canonical address on chain id 31337, and RegistryFor would otherwise return
// ErrNoRegistry for that chain id. By injecting the deployed mock's address here,
// the integration suite drives the REAL Resolve/Reverse/ResolvePinned code path
// against a real (mock) on-chain registry — no ens.Resolver interface and no
// chain.Client trickery (§2.8: the only ENS test seam is the chain.Client fake;
// the integration path injects the real address instead of faking the reads).
//
// Calling SetTestRegistry(id, common.Address{}) clears the override for id so a
// test can restore the canonical lookup. NOT safe for concurrent use with
// resolution on the same chain id; integration tests set it once during setup.
func SetTestRegistry(chainID *big.Int, addr common.Address) {
	if chainID == nil {
		return
	}
	if (addr == common.Address{}) {
		delete(testRegistries, chainID.String())
		return
	}
	testRegistries[chainID.String()] = addr
}
