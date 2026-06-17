// Package chaintest is the SHARED chain.Client contract-test suite (design
// §2.9). The SAME assertions run against BOTH the real JSON-RPC adapter (behind
// //go:build integration, dialed at anvil) and the hand-written fake, so the two
// cannot drift: any behaviour the real client has that the fake lacks (or vice
// versa) turns the suite red on one side.
//
// chaintest is a sub-package of the chain provider (import path under
// internal/chain/), so it classifies as the "chain" provider in the arch matrix;
// its only daxie import is internal/chain itself (the intra-provider edge), plus
// internal/domain — it does NOT import internal/chain/fake (the caller supplies
// the client), keeping the matrix clean and the suite agnostic about which
// implementation it drives.
package chaintest

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/chain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Harness lets the suite assert against the backing chain (anvil) or the fake's
// programmed state without knowing which it drives. The real harness reports
// anvil's chain-id + a funded dev account; the fake harness reports the values
// the fake was programmed with.
type Harness interface {
	// ExpectChainID is the chain-id the client under test must report.
	ExpectChainID() *big.Int
	// FundedAddress is an address with a known NONZERO balance.
	FundedAddress() common.Address
	// ExpectFundedWei is the EXACT wei balance FundedAddress must report (anvil's
	// deterministic 10000 ETH on the real side; the programmed amount on the fake).
	// Asserting the exact value — not merely >0 — catches a wrong-but-positive read
	// or a wei/eth mis-scaling in the read path.
	ExpectFundedWei() *big.Int
	// EmptyAddress is an address with a ZERO balance.
	EmptyAddress() common.Address
	// SupportsSubscribe reports whether the transport supports Subscribe* (true
	// for a websocket; false for HTTP/the default fake → Subscribe* must return
	// chain.ErrNotSupported).
	SupportsSubscribe() bool
}

// suiteTimeout bounds each contract call so a hung endpoint fails the test fast
// rather than blocking CI.
const suiteTimeout = 20 * time.Second

// Run executes the full chain.Client contract against the client newClient
// returns, using the paired Harness to know what to expect. It is called by:
//
//   - internal/chain/contract_fake_test.go  (the fake)             [unit]
//   - internal/chain/integration_test.go    (real adapter @ anvil) [integration]
//
// so the fake can never silently drift from real behaviour (§2.9). newClient is
// a factory (one fresh client + harness per subtest) so subtests do not share a
// connection.
func Run(t *testing.T, newClient func(t *testing.T) (chain.Client, Harness)) {
	t.Helper()

	t.Run("ChainID", func(t *testing.T) {
		cc, h := newClient(t)
		defer cc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
		defer cancel()

		got, err := cc.ChainID(ctx)
		if err != nil {
			t.Fatalf("ChainID: unexpected error: %v", err)
		}
		if got == nil || got.Cmp(h.ExpectChainID()) != 0 {
			t.Fatalf("ChainID = %v, want %v", got, h.ExpectChainID())
		}
	})

	t.Run("Balance_funded_exact", func(t *testing.T) {
		cc, h := newClient(t)
		defer cc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
		defer cancel()

		bal, err := cc.Balance(ctx, h.FundedAddress(), nil)
		if err != nil {
			t.Fatalf("Balance(funded): unexpected error: %v", err)
		}
		// Assert the EXACT known amount, not merely >0: a wrong-but-positive read or
		// a wei/eth mis-scaling in the read path must turn this red.
		if bal == nil || bal.Cmp(h.ExpectFundedWei()) != 0 {
			t.Fatalf("Balance(funded) = %v, want exactly %v", bal, h.ExpectFundedWei())
		}
	})

	t.Run("Balance_empty_zero", func(t *testing.T) {
		cc, h := newClient(t)
		defer cc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
		defer cancel()

		bal, err := cc.Balance(ctx, h.EmptyAddress(), nil)
		if err != nil {
			t.Fatalf("Balance(empty): unexpected error: %v", err)
		}
		if bal == nil || bal.Sign() != 0 {
			t.Fatalf("Balance(empty) = %v, want 0", bal)
		}
	})

	t.Run("Nonce_latest", func(t *testing.T) {
		cc, h := newClient(t)
		defer cc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
		defer cancel()

		// A fresh funded account has a defined (>=0) nonce; the call must succeed.
		if _, err := cc.Nonce(ctx, h.FundedAddress(), false); err != nil {
			t.Fatalf("Nonce(latest): unexpected error: %v", err)
		}
		if _, err := cc.Nonce(ctx, h.FundedAddress(), true); err != nil {
			t.Fatalf("Nonce(pending): unexpected error: %v", err)
		}
	})

	t.Run("BlockNumber", func(t *testing.T) {
		cc, _ := newClient(t)
		defer cc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
		defer cancel()

		if _, err := cc.BlockNumber(ctx); err != nil {
			t.Fatalf("BlockNumber: unexpected error: %v", err)
		}
	})

	t.Run("Subscribe_transport_contract", func(t *testing.T) {
		cc, h := newClient(t)
		defer cc.Close()
		ctx, cancel := context.WithTimeout(context.Background(), suiteTimeout)
		defer cancel()

		logCh := make(chan types.Log, 1)
		headCh := make(chan uint64, 1)

		subLogs, errLogs := cc.SubscribeLogs(ctx, ethereum.FilterQuery{}, logCh)
		subHead, errHead := cc.SubscribeNewHead(ctx, headCh)

		if h.SupportsSubscribe() {
			if errLogs != nil {
				t.Fatalf("SubscribeLogs on a subscribe-capable transport: unexpected error: %v", errLogs)
			}
			if errHead != nil {
				t.Fatalf("SubscribeNewHead on a subscribe-capable transport: unexpected error: %v", errHead)
			}
			if subLogs != nil {
				subLogs.Unsubscribe()
			}
			if subHead != nil {
				subHead.Unsubscribe()
			}
			return
		}

		// HTTP / default fake: Subscribe* MUST return chain.ErrNotSupported (no
		// second interface) and a nil subscription.
		if !errors.Is(errLogs, chain.ErrNotSupported) {
			t.Fatalf("SubscribeLogs on HTTP: err = %v, want chain.ErrNotSupported", errLogs)
		}
		if subLogs != nil {
			t.Fatalf("SubscribeLogs on HTTP: subscription = %v, want nil", subLogs)
		}
		if !errors.Is(errHead, chain.ErrNotSupported) {
			t.Fatalf("SubscribeNewHead on HTTP: err = %v, want chain.ErrNotSupported", errHead)
		}
		if subHead != nil {
			t.Fatalf("SubscribeNewHead on HTTP: subscription = %v, want nil", subHead)
		}
	})
}
