package service

import (
	"context"
	"math/big"
	"sync"
	"testing"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
)

// flakyFilterClient fails FilterLogs for the first failN calls, then delegates.
// FilterLogs is only ever called inside the receive loop (the token scan), so this
// drives the loop's transient-error path without touching the pre-loop setup.
type flakyFilterClient struct {
	chain.Client
	mu      sync.Mutex
	calls   int
	failN   int
	failErr error
}

func (f *flakyFilterClient) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	f.mu.Lock()
	f.calls++
	c := f.calls
	f.mu.Unlock()
	if c <= f.failN {
		return nil, f.failErr
	}
	return f.Client.FilterLogs(ctx, q)
}

// erc20FlakyFixture builds an ERC-20 receive that completes in one successful scan,
// wrapped so FilterLogs fails failErr for the first failN in-loop calls.
func erc20FlakyFixture(t *testing.T, failN int, failErr error) (*Service, *flakyFilterClient, common.Address) {
	t.Helper()
	listen := someAddr(1)
	token := someAddr(2)
	payer := someAddr(3)
	bh := common.HexToHash("0x77aa")
	base := fake.New()
	base.BlockNum = 10 // head ≥ detection block (8) + confirmations (mainnet 2)
	log := erc20TransferLog(token, payer, listen, big.NewInt(100_000_000), 8, bh, 7)
	base.FilterLogsFn = func(_ context.Context, _ ethereum.FilterQuery) ([]types.Log, error) {
		return []types.Log{log}, nil
	}
	base.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: types.ReceiptStatusSuccessful, BlockHash: bh, GasUsed: 50000, EffectiveGasPrice: gwei(20)}, nil
	}
	flaky := &flakyFilterClient{Client: base, failN: failN, failErr: failErr}
	svc := receiveService(t, flaky, time.Second)
	addTestToken(t, svc, "testtok", token, 6)
	return svc, flaky, token
}

// TestReceive_TransientRPCError_KeepsListening proves a flaky endpoint does NOT
// abort a listen: a few transport failures on the in-loop log scan are retried
// (mapRPCErr types a plain error as rpc.unreachable), then detection completes.
func TestReceive_TransientRPCError_KeepsListening(t *testing.T) {
	listen := someAddr(1)
	svc, flaky, token := erc20FlakyFixture(t, 3, errString("dial tcp: connection refused"))
	cs := &collectSink{}
	res, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Token: token.Hex(), Amount: "100"}, cs.sink())
	if err != nil {
		t.Fatalf("Receive should survive transient RPC errors, got: %v", err)
	}
	if res.Status != "complete" {
		t.Fatalf("status = %q, want complete (listen survived the transport outage)", res.Status)
	}
	if flaky.calls <= flaky.failN {
		t.Errorf("expected FilterLogs to be retried past the %d injected failures, got %d calls",
			flaky.failN, flaky.calls)
	}
}

// TestReceive_FatalRPCError_Terminates proves a non-transport error in the loop
// (here a chain-id mismatch, never retryable) ends the listen immediately rather
// than spinning forever.
func TestReceive_FatalRPCError_Terminates(t *testing.T) {
	listen := someAddr(1)
	svc, _, token := erc20FlakyFixture(t, 1_000_000, // always fail
		domain.New(domain.CodeRPCChainIDMismatch, "endpoint is on the wrong chain"))
	cs := &collectSink{}
	_, err := svc.Receive(context.Background(), domain.LocalCLI(),
		domain.ReceiveRequest{Account: listen.Hex(), Token: token.Hex(), Amount: "100"}, cs.sink())
	if err == nil {
		t.Fatal("a chain-id mismatch should terminate the listen, not be retried forever")
	}
	if got := domain.AsError(err).Code; got != domain.CodeRPCChainIDMismatch {
		t.Errorf("error code = %q, want %q", got, domain.CodeRPCChainIDMismatch)
	}
}
