package fake

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestFake_Defaults(t *testing.T) {
	c := New()
	ctx := context.Background()

	id, err := c.ChainID(ctx)
	if err != nil {
		t.Fatalf("ChainID: %v", err)
	}
	if id.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("default ChainID = %v, want 1", id)
	}

	addr := common.HexToAddress("0xabc")
	bal, err := c.Balance(ctx, addr, nil)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if bal.Sign() != 0 {
		t.Errorf("unprogrammed Balance = %v, want 0", bal)
	}
}

func TestFake_ProgrammedBalanceAndNonce(t *testing.T) {
	c := New()
	ctx := context.Background()
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	c.Balances[addr] = big.NewInt(42)
	c.Nonces[addr] = 7

	bal, _ := c.Balance(ctx, addr, nil)
	if bal.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("Balance = %v, want 42", bal)
	}
	n, _ := c.Nonce(ctx, addr, false)
	if n != 7 {
		t.Errorf("Nonce = %d, want 7", n)
	}

	// Balance returns a COPY: mutating the result must not corrupt the fake state.
	bal.SetInt64(0)
	again, _ := c.Balance(ctx, addr, nil)
	if again.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("fake state mutated through returned balance; got %v", again)
	}
}

func TestFake_ErrShortCircuitsEveryMethod(t *testing.T) {
	c := New()
	c.Err = errors.New("network down")
	ctx := context.Background()

	if _, err := c.ChainID(ctx); err == nil {
		t.Error("ChainID: want error when Err set")
	}
	if _, err := c.Balance(ctx, common.Address{}, nil); err == nil {
		t.Error("Balance: want error when Err set")
	}
	if _, err := c.BlockNumber(ctx); err == nil {
		t.Error("BlockNumber: want error when Err set")
	}
}

func TestFake_SubscribeHTTPSemantics(t *testing.T) {
	c := New() // SupportsSubscribe defaults false (HTTP)
	ctx := context.Background()

	if _, err := c.SubscribeNewHead(ctx, make(chan uint64, 1)); !errors.Is(err, chain.ErrNotSupported) {
		t.Errorf("SubscribeNewHead: err = %v, want chain.ErrNotSupported", err)
	}
	if _, err := c.SubscribeLogs(ctx, ethereum.FilterQuery{}, make(chan types.Log, 1)); !errors.Is(err, chain.ErrNotSupported) {
		t.Errorf("SubscribeLogs: err = %v, want chain.ErrNotSupported", err)
	}
}

func TestFake_SubscribeWebsocketSemantics(t *testing.T) {
	c := New()
	c.SupportsSubscribe = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub, err := c.SubscribeNewHead(ctx, make(chan uint64, 1))
	if err != nil {
		t.Fatalf("SubscribeNewHead (ws): %v", err)
	}
	if sub == nil {
		t.Fatal("SubscribeNewHead (ws): nil subscription, want live")
	}
	sub.Unsubscribe()
}

func TestFake_RecordsCalls(t *testing.T) {
	c := New()
	ctx := context.Background()
	addr := common.HexToAddress("0x9")

	_, _ = c.ChainID(ctx)
	_, _ = c.Balance(ctx, addr, nil)
	_, _ = c.Balance(ctx, addr, big.NewInt(5))

	if got := len(c.CallsFor("Balance")); got != 2 {
		t.Errorf("recorded Balance calls = %d, want 2", got)
	}
	if got := len(c.CallsFor("ChainID")); got != 1 {
		t.Errorf("recorded ChainID calls = %d, want 1", got)
	}
}

func TestFake_FunctionHooks(t *testing.T) {
	c := New()
	ctx := context.Background()

	c.SuggestFeesFn = func(ctx context.Context, speed domain.Speed) (*big.Int, *big.Int, *big.Int, error) {
		return big.NewInt(100), big.NewInt(2), big.NewInt(49), nil
	}
	maxFee, prio, base, err := c.SuggestFees(ctx, domain.SpeedFast)
	if err != nil {
		t.Fatalf("SuggestFees: %v", err)
	}
	if maxFee.Int64() != 100 || prio.Int64() != 2 || base.Int64() != 49 {
		t.Errorf("SuggestFees = (%v,%v,%v), want (100,2,49)", maxFee, prio, base)
	}

	c.ReceiptFn = func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		return &types.Receipt{Status: 1}, nil
	}
	r, err := c.Receipt(ctx, common.Hash{})
	if err != nil {
		t.Fatalf("Receipt: %v", err)
	}
	if r.Status != 1 {
		t.Errorf("Receipt status = %d, want 1", r.Status)
	}
}

func TestFake_ReceiptDefaultNotFound(t *testing.T) {
	c := New()
	if _, err := c.Receipt(context.Background(), common.Hash{}); !errors.Is(err, chain.ErrTxNotFound) {
		t.Errorf("default Receipt err = %v, want chain.ErrTxNotFound", err)
	}
}

// interface satisfaction (belt-and-suspenders; the package var already asserts it).
var _ chain.Client = New()
