package chain

import (
	"context"
	"math/big"
	"sort"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// client is the real JSON-RPC/HTTP(S)/ws adapter — a thin set of go-ethereum
// ethclient/rpc wrappers (real impls, not stubs that lie). Every Client method
// is implemented; M2 wires only ChainID/Balance/Nonce/BlockNumber through
// commands, the rest are covered by the shared chaintest suite and driven by
// later milestones. ws reflects whether the transport supports subscriptions.
type client struct {
	rc   *rpc.Client
	ec   *ethclient.Client
	opts Options
	ws   bool
}

// compile-time guarantee the real adapter satisfies the interface.
var _ Client = (*client)(nil)

func (c *client) ChainID(ctx context.Context) (*big.Int, error) {
	id, err := c.ec.ChainID(ctx)
	return id, unreachableErr(c.opts, "chainid", err)
}

func (c *client) Nonce(ctx context.Context, a common.Address, pending bool) (uint64, error) {
	if pending {
		n, err := c.ec.PendingNonceAt(ctx, a)
		return n, unreachableErr(c.opts, "nonce", err)
	}
	n, err := c.ec.NonceAt(ctx, a, nil)
	return n, unreachableErr(c.opts, "nonce", err)
}

func (c *client) Balance(ctx context.Context, a common.Address, block *big.Int) (*big.Int, error) {
	bal, err := c.ec.BalanceAt(ctx, a, block)
	return bal, unreachableErr(c.opts, "balance", err)
}

func (c *client) EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	g, err := c.ec.EstimateGas(ctx, msg)
	return g, unreachableErr(c.opts, "estimategas", err)
}

func (c *client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	p, err := c.ec.SuggestGasPrice(ctx)
	return p, unreachableErr(c.opts, "gasprice", err)
}

func (c *client) CallContract(ctx context.Context, msg ethereum.CallMsg, block *big.Int) ([]byte, error) {
	out, err := c.ec.CallContract(ctx, msg, block)
	return out, unreachableErr(c.opts, "call", err)
}

// SendRawTransaction broadcasts pre-signed RLP bytes via eth_sendRawTransaction.
// ethclient.SendTransaction takes a *types.Transaction; here the bytes are
// already the canonical signed encoding, so the raw RPC is the faithful path
// (no re-encode, no re-derivation). The returned hash is what the node echoes.
func (c *client) SendRawTransaction(ctx context.Context, raw []byte) (common.Hash, error) {
	var h common.Hash
	err := c.rc.CallContext(ctx, &h, "eth_sendRawTransaction", hexutil.Encode(raw))
	if err != nil {
		return common.Hash{}, unreachableErr(c.opts, "sendraw", err)
	}
	return h, nil
}

func (c *client) Receipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	r, err := c.ec.TransactionReceipt(ctx, h)
	if err != nil {
		return nil, c.notFoundErr("receipt", err)
	}
	return r, nil
}

func (c *client) BlockNumber(ctx context.Context) (uint64, error) {
	n, err := c.ec.BlockNumber(ctx)
	return n, unreachableErr(c.opts, "blocknumber", err)
}

// BlockByNumber returns a full block. ethclient.BlockByNumber always fetches
// full transaction bodies; fullTx is honored as a hint but the geth client has
// no header-only block fetch, so we always return the full block (callers that
// pass fullTx=false simply ignore the bodies).
func (c *client) BlockByNumber(ctx context.Context, n *big.Int, fullTx bool) (*types.Block, error) {
	_ = fullTx
	b, err := c.ec.BlockByNumber(ctx, n)
	if err != nil {
		return nil, c.notFoundErr("block", err)
	}
	return b, nil
}

func (c *client) FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	logs, err := c.ec.FilterLogs(ctx, q)
	return logs, unreachableErr(c.opts, "filterlogs", err)
}

// SubscribeLogs streams logs over a websocket. On an HTTP(S) transport it
// returns ErrNotSupported — there is no second interface; the caller polls
// FilterLogs instead.
func (c *client) SubscribeLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	if !c.ws {
		return nil, ErrNotSupported
	}
	sub, err := c.ec.SubscribeFilterLogs(ctx, q, ch)
	return sub, unreachableErr(c.opts, "subscribelogs", err)
}

// SubscribeNewHead streams new block heights over a websocket. The geth client
// streams *types.Header; this adapter forwards the header NUMBER onto ch and
// translates the subscription so the interface stays head-height oriented (the
// receive engine only needs heights). On HTTP(S) it returns ErrNotSupported.
func (c *client) SubscribeNewHead(ctx context.Context, ch chan<- uint64) (ethereum.Subscription, error) {
	if !c.ws {
		return nil, ErrNotSupported
	}
	headers := make(chan *types.Header, 16)
	sub, err := c.ec.SubscribeNewHead(ctx, headers)
	if err != nil {
		return nil, unreachableErr(c.opts, "subscribehead", err)
	}
	return newHeadHeightSub(ctx, sub, headers, ch), nil
}

func (c *client) Close() {
	if c.rc != nil {
		c.rc.Close()
	}
}

// ── SuggestFees: the SINGLE eth_feeHistory(blocks,[25,50,90]) call + the
//    percentile/median math (the one place the gas/speed policy lives, §5.4) ────

// feePercentiles is the binding §5.4 percentile triple sampled in ONE
// eth_feeHistory call: slow→25th, normal→50th, fast→90th. It is the shared
// contract with config (slow|normal|fast → p25/p50/p90) and the test fixture.
var feePercentiles = []float64{25, 50, 90}

// defaultFeeHistoryBlocks is the fallback lookback window when the caller passes a
// non-positive block count (it mirrors the gas.fee-history-blocks config default,
// §5.4 — the real call site plumbs the configured value).
const defaultFeeHistoryBlocks = 20

// SuggestFees folds the SINGLE eth_feeHistory(blocks,"latest",[25,50,90]) call +
// the percentile/median math into one method (§5.4/§2.6). It samples `blocks`
// recent blocks, requests the binding 25/50/90 percentile triple in one
// round-trip, and returns the next-block base fee plus the three per-speed
// priority-fee tiers. Each tier is the MEDIAN of its percentile column across the
// sampled blocks — NOT the mean and NOT the latest block, because a single
// MEV-bribe block would otherwise poison `fast` (§5.4). Pure value math on
// *big.Int — no float drift in the returned fees (the percentile is only an array
// index into the node's own reward arrays). The caller selects the tier by
// --speed and layers the configured multipliers/floors/caps + the max-fee formula
// on top. One RPC serves all three speeds, so `daxie gas` issues exactly one
// feeHistory call.
func (c *client) SuggestFees(ctx context.Context, blocks int) (Fees, error) {
	if blocks <= 0 {
		blocks = defaultFeeHistoryBlocks
	}
	hist, err := c.ec.FeeHistory(ctx, uint64(blocks), nil, feePercentiles)
	if err != nil {
		return Fees{}, unreachableErr(c.opts, "feehistory", err)
	}

	out := Fees{Source: "fee-history"}

	// baseFee: prefer the projected next-block base fee (FeeHistory.BaseFee has
	// blockCount+1 entries, the last being the next block's base fee) and fall
	// back to SuggestGasPrice if the node returned none (non-1559 chain).
	out.BaseFee = nextBaseFee(hist)
	if out.BaseFee == nil {
		gp, gerr := c.ec.SuggestGasPrice(ctx)
		if gerr != nil {
			return Fees{}, unreachableErr(c.opts, "gasprice", gerr)
		}
		out.BaseFee = gp
		out.Source = "fallback"
	}

	// priority tiers: the MEDIAN of each percentile column across the sampled
	// blocks. When feeHistory carried no reward data at all, fall back to
	// eth_maxPriorityFeePerGas for every tier (the §5.4 fallback ladder rung).
	out.PrioritySlow = medianColumn(hist, 0)
	out.PriorityNormal = medianColumn(hist, 1)
	out.PriorityFast = medianColumn(hist, 2)
	if out.PrioritySlow == nil || out.PriorityNormal == nil || out.PriorityFast == nil {
		tip, terr := c.ec.SuggestGasTipCap(ctx)
		if terr != nil {
			return Fees{}, unreachableErr(c.opts, "gastip", terr)
		}
		if out.PrioritySlow == nil {
			out.PrioritySlow = new(big.Int).Set(tip)
		}
		if out.PriorityNormal == nil {
			out.PriorityNormal = new(big.Int).Set(tip)
		}
		if out.PriorityFast == nil {
			out.PriorityFast = new(big.Int).Set(tip)
		}
		out.Source = "fallback"
	}

	return out, nil
}

// nextBaseFee returns the projected next-block base fee from a FeeHistory (the
// last BaseFee entry, which is blockCount+1 long), or nil when the node returned
// no base-fee data (legacy chain).
func nextBaseFee(h *ethereum.FeeHistory) *big.Int {
	if h == nil || len(h.BaseFee) == 0 {
		return nil
	}
	last := h.BaseFee[len(h.BaseFee)-1]
	if last == nil {
		return nil
	}
	return new(big.Int).Set(last)
}

// medianColumn returns the MEDIAN of column `col` (one of the three requested
// percentiles) across every sampled block's reward row, or nil when no block
// carried a value for that column. The median (not the mean) is the §5.4 defense
// against a single MEV-bribe block poisoning the estimate. For an even count it
// takes the lower of the two middle values (a conservative, deterministic choice —
// no averaging, no float).
func medianColumn(h *ethereum.FeeHistory, col int) *big.Int {
	if h == nil {
		return nil
	}
	vals := make([]*big.Int, 0, len(h.Reward))
	for _, row := range h.Reward {
		if col < len(row) && row[col] != nil {
			vals = append(vals, new(big.Int).Set(row[col]))
		}
	}
	if len(vals) == 0 {
		return nil
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i].Cmp(vals[j]) < 0 })
	// Lower-middle for even counts: index (n-1)/2 — deterministic, no averaging.
	return vals[(len(vals)-1)/2]
}
