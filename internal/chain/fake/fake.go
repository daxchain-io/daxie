// Package fake is the one hand-written chain.Client fake — the single
// load-bearing test seam of the codebase (design §2.9). Service-pipeline unit
// tests inject it instead of touching the network; it programs per-method
// results (or function hooks) and records every call for assertions. No mock
// framework.
//
// Its behaviour is kept honest against the real adapter by the shared
// chaintest.Run suite (§2.9): the same contract assertions run against both a
// fake and a real anvil-backed client, so the fake cannot drift from real
// semantics. In particular, Subscribe* default to chain.ErrNotSupported,
// mirroring an HTTP endpoint; set SupportsSubscribe=true to simulate a websocket.
package fake

import (
	"context"
	"math/big"
	"sync"

	"github.com/daxchain-io/daxie/internal/chain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Call is one recorded method invocation. Method is the Client method name;
// Args holds the salient arguments for assertions (addresses, hashes, flags).
type Call struct {
	Method string
	Args   []any
}

// Client is a programmable chain.Client fake. Zero values are sensible; prefer
// New() for chain-id 1 and initialized maps. All fields are read under a mutex
// so the fake is safe to drive from concurrent goroutines (the receive engine
// tests do).
type Client struct {
	mu sync.Mutex

	// Programmable state for the wired M2 paths.
	ChainIDVal *big.Int
	Balances   map[common.Address]*big.Int // missing key => zero balance
	Nonces     map[common.Address]uint64
	BlockNum   uint64

	// SupportsSubscribe flips Subscribe* from chain.ErrNotSupported (HTTP
	// semantics, the default) to a live event subscription (websocket semantics).
	SupportsSubscribe bool

	// Function hooks for the methods later milestones drive. When nil, the method
	// returns a sensible zero/typed-default.
	SuggestFeesFn     func(ctx context.Context, blocks int) (chain.Fees, error)
	SuggestGasPriceFn func(ctx context.Context) (*big.Int, error)
	EstimateGasFn     func(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	CallContractFn    func(ctx context.Context, msg ethereum.CallMsg, block *big.Int) ([]byte, error)
	FilterLogsFn      func(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
	SendRawFn         func(ctx context.Context, raw []byte) (common.Hash, error)
	ReceiptFn         func(ctx context.Context, h common.Hash) (*types.Receipt, error)
	BlockByNumberFn   func(ctx context.Context, n *big.Int, fullTx bool) (*types.Block, error)

	// Calls records every invocation in order.
	Calls []Call

	// Err, when non-nil, is returned by EVERY method (a network-down / endpoint-
	// unreachable simulation). It takes precedence over programmed results and
	// hooks. ChainID returns it too. Closed/Subscribe* still honor it.
	Err error
}

// compile-time guarantee the fake satisfies the real interface.
var _ chain.Client = (*Client)(nil)

// New returns a fake on chain-id 1 with initialized maps and no programmed
// results.
func New() *Client {
	return &Client{
		ChainIDVal: big.NewInt(1),
		Balances:   map[common.Address]*big.Int{},
		Nonces:     map[common.Address]uint64{},
	}
}

// record appends a call; the caller holds c.mu.
func (c *Client) record(method string, args ...any) {
	c.Calls = append(c.Calls, Call{Method: method, Args: args})
}

// CallsFor returns the recorded calls to a given method, in order. Safe for
// concurrent use.
func (c *Client) CallsFor(method string) []Call {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Call
	for _, call := range c.Calls {
		if call.Method == method {
			out = append(out, call)
		}
	}
	return out
}

func (c *Client) ChainID(ctx context.Context) (*big.Int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record("ChainID")
	if c.Err != nil {
		return nil, c.Err
	}
	if c.ChainIDVal == nil {
		return big.NewInt(1), nil
	}
	return new(big.Int).Set(c.ChainIDVal), nil
}

func (c *Client) Nonce(ctx context.Context, a common.Address, pending bool) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record("Nonce", a, pending)
	if c.Err != nil {
		return 0, c.Err
	}
	return c.Nonces[a], nil
}

func (c *Client) Balance(ctx context.Context, a common.Address, block *big.Int) (*big.Int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record("Balance", a, block)
	if c.Err != nil {
		return nil, c.Err
	}
	if b, ok := c.Balances[a]; ok && b != nil {
		return new(big.Int).Set(b), nil
	}
	return big.NewInt(0), nil
}

func (c *Client) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	c.mu.Lock()
	fn := c.EstimateGasFn
	err := c.Err
	c.record("EstimateGas", msg)
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if fn != nil {
		return fn(ctx, msg)
	}
	return 21000, nil
}

func (c *Client) SuggestFees(ctx context.Context, blocks int) (chain.Fees, error) {
	c.mu.Lock()
	fn := c.SuggestFeesFn
	e := c.Err
	c.record("SuggestFees", blocks)
	c.mu.Unlock()
	if e != nil {
		return chain.Fees{}, e
	}
	if fn != nil {
		return fn(ctx, blocks)
	}
	return chain.Fees{
		BaseFee:        big.NewInt(0),
		PrioritySlow:   big.NewInt(0),
		PriorityNormal: big.NewInt(0),
		PriorityFast:   big.NewInt(0),
		Source:         "fee-history",
	}, nil
}

func (c *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	c.mu.Lock()
	fn := c.SuggestGasPriceFn
	e := c.Err
	c.record("SuggestGasPrice")
	c.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if fn != nil {
		return fn(ctx)
	}
	return big.NewInt(0), nil
}

func (c *Client) CallContract(ctx context.Context, msg ethereum.CallMsg, block *big.Int) ([]byte, error) {
	c.mu.Lock()
	fn := c.CallContractFn
	e := c.Err
	c.record("CallContract", msg, block)
	c.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if fn != nil {
		return fn(ctx, msg, block)
	}
	return nil, nil
}

func (c *Client) SendRawTransaction(ctx context.Context, raw []byte) (common.Hash, error) {
	c.mu.Lock()
	fn := c.SendRawFn
	e := c.Err
	c.record("SendRawTransaction", raw)
	c.mu.Unlock()
	if e != nil {
		return common.Hash{}, e
	}
	if fn != nil {
		return fn(ctx, raw)
	}
	return common.Hash{}, nil
}

func (c *Client) Receipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	c.mu.Lock()
	fn := c.ReceiptFn
	e := c.Err
	c.record("Receipt", h)
	c.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if fn != nil {
		return fn(ctx, h)
	}
	return nil, chain.ErrTxNotFound
}

func (c *Client) BlockNumber(ctx context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record("BlockNumber")
	if c.Err != nil {
		return 0, c.Err
	}
	return c.BlockNum, nil
}

func (c *Client) BlockByNumber(ctx context.Context, n *big.Int, fullTx bool) (*types.Block, error) {
	c.mu.Lock()
	fn := c.BlockByNumberFn
	e := c.Err
	c.record("BlockByNumber", n, fullTx)
	c.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if fn != nil {
		return fn(ctx, n, fullTx)
	}
	return nil, chain.ErrTxNotFound
}

func (c *Client) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	c.mu.Lock()
	fn := c.FilterLogsFn
	e := c.Err
	c.record("FilterLogs", q)
	c.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if fn != nil {
		return fn(ctx, q)
	}
	return nil, nil
}

// SubscribeLogs returns chain.ErrNotSupported unless SupportsSubscribe is set,
// matching the HTTP-vs-websocket semantics the real adapter enforces. When
// supported, it returns a live (but empty) subscription the test controls via
// the channel; the producer simply waits for unsubscribe.
func (c *Client) SubscribeLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	c.mu.Lock()
	supported := c.SupportsSubscribe
	e := c.Err
	c.record("SubscribeLogs", q)
	c.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if !supported {
		return nil, chain.ErrNotSupported
	}
	return idleSubscription(ctx), nil
}

// SubscribeNewHead mirrors SubscribeLogs: ErrNotSupported on the default (HTTP)
// fake, a live idle subscription when SupportsSubscribe is set.
func (c *Client) SubscribeNewHead(ctx context.Context, ch chan<- uint64) (ethereum.Subscription, error) {
	c.mu.Lock()
	supported := c.SupportsSubscribe
	e := c.Err
	c.record("SubscribeNewHead")
	c.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if !supported {
		return nil, chain.ErrNotSupported
	}
	return idleSubscription(ctx), nil
}

func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.record("Close")
}

// idleSubscription is a live subscription that delivers nothing and ends on
// Unsubscribe or ctx cancellation — enough for tests that only assert a websocket
// fake returns a non-nil subscription rather than ErrNotSupported.
func idleSubscription(ctx context.Context) ethereum.Subscription {
	return event.NewSubscription(func(quit <-chan struct{}) error {
		select {
		case <-quit:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}
