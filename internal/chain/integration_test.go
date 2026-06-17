//go:build integration

// integration_test.go runs the SHARED chain.Client contract suite against the
// REAL JSON-RPC adapter dialed at a local anvil, plus the two chain-id guard
// cases the fake cannot prove: a matching chain-id dials successfully, and a
// DELIBERATE mismatch is refused fail-closed (rpc.chain_id_mismatch, exit 12) —
// the malicious/misconfigured-endpoint guard (§2.9, §7.5).
//
// It is an EXTERNAL test package (chain_test) so it does not collide with the
// package-internal files in this directory, and it is gated by //go:build
// integration so it compiles only under `go test -tags integration`.
package chain_test

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/chaintest"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/testchain"
)

// TestContractSuite_RealAdapter runs the full chaintest.Run contract against the
// real adapter dialed at anvil — the SAME assertions the fake satisfies in
// contract_fake_test.go, so the two cannot drift.
func TestContractSuite_RealAdapter(t *testing.T) {
	anvil := testchain.Spawn(t)
	chaintest.Run(t, func(t *testing.T) (chain.Client, chaintest.Harness) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cc, err := chain.Dial(ctx, chain.Options{
			URL:           anvil.URL(),
			Network:       "localanvil",
			ExpectChainID: anvil.ExpectChainID(),
		})
		if err != nil {
			t.Fatalf("Dial(anvil): %v", err)
		}
		return cc, anvil
	})
}

// TestDial_ChainIDMatch confirms a dial declaring anvil's real chain-id succeeds.
func TestDial_ChainIDMatch(t *testing.T) {
	anvil := testchain.Spawn(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cc, err := chain.Dial(ctx, chain.Options{
		URL:           anvil.URL(),
		Network:       "localanvil",
		ExpectChainID: big.NewInt(testchain.AnvilChainID),
	})
	if err != nil {
		t.Fatalf("Dial with matching chain-id: unexpected error: %v", err)
	}
	defer cc.Close()

	id, err := cc.ChainID(ctx)
	if err != nil {
		t.Fatalf("ChainID: %v", err)
	}
	if id.Uint64() != testchain.AnvilChainID {
		t.Fatalf("ChainID = %d, want %d", id.Uint64(), testchain.AnvilChainID)
	}
}

// TestDial_ChainIDMismatch_Refuses is the load-bearing guard: dialing anvil while
// DECLARING the wrong chain-id (mainnet's 1) MUST fail closed with
// rpc.chain_id_mismatch (exit 12) and return no usable client. A wrong/malicious
// endpoint must never silently be used for the wrong chain.
func TestDial_ChainIDMismatch_Refuses(t *testing.T) {
	anvil := testchain.Spawn(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cc, err := chain.Dial(ctx, chain.Options{
		URL:           anvil.URL(),
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1), // WRONG: anvil reports 31337
	})
	if err == nil {
		if cc != nil {
			cc.Close()
		}
		t.Fatal("Dial with mismatched chain-id: expected refusal, got a usable client")
	}
	de := domain.AsError(err)
	if de.Code != domain.CodeRPCChainIDMismatch {
		t.Fatalf("error code = %q, want %q", de.Code, domain.CodeRPCChainIDMismatch)
	}
	if de.Exit != domain.ExitIntegrity {
		t.Fatalf("exit = %d, want %d (INTEGRITY)", de.Exit, domain.ExitIntegrity)
	}
}
