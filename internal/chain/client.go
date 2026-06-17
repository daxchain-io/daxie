package chain

import (
	"context"
	"math/big"

	"github.com/daxchain-io/daxie/internal/domain"
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

// ── SuggestFees: eth_feeHistory + the --speed percentile math (one place) ─────

// speedPercentile maps a --speed preset to the priority-fee percentile sampled
// from eth_feeHistory. Slower → lower percentile (cheaper, more patient); faster
// → higher percentile (pays to jump the queue). M3 owns the full gas policy;
// this is the single source of the percentile choice the design folds into
// SuggestFees (§2.6).
func speedPercentile(s domain.Speed) float64 {
	switch s {
	case domain.SpeedSlow:
		return 10
	case domain.SpeedFast:
		return 90
	default: // SpeedNormal and any unset value
		return 50
	}
}

// feeHistoryBlocks is the lookback window for the priority-fee percentile sample.
const feeHistoryBlocks = 5

// SuggestFees folds eth_feeHistory + the --speed percentile math into one
// method. It returns EIP-1559 fees: priorityFee is the chosen percentile of
// recent tips; baseFee is the latest block base fee; maxFee = 2*baseFee +
// priorityFee (one base-fee doubling of headroom, the conventional safe ceiling
// for the next ~6 blocks). Pure value math on *big.Int — no float drift in the
// returned fees (the percentile is only an array index). M3 layers the
// configured multipliers/floors/caps on top of this primitive.
func (c *client) SuggestFees(ctx context.Context, speed domain.Speed) (maxFee, priorityFee, baseFee *big.Int, err error) {
	pct := speedPercentile(speed)
	hist, err := c.ec.FeeHistory(ctx, feeHistoryBlocks, nil, []float64{pct})
	if err != nil {
		return nil, nil, nil, unreachableErr(c.opts, "feehistory", err)
	}

	// baseFee: prefer the projected next-block base fee (FeeHistory.BaseFee has
	// blockCount+1 entries, the last being the next block's base fee) and fall
	// back to SuggestGasPrice if the node returned none (non-1559 chain).
	baseFee = latestBaseFee(hist)
	if baseFee == nil {
		gp, gerr := c.ec.SuggestGasPrice(ctx)
		if gerr != nil {
			return nil, nil, nil, unreachableErr(c.opts, "gasprice", gerr)
		}
		baseFee = gp
	}

	// priorityFee: the chosen percentile from the most recent block with reward
	// data; fall back to SuggestGasTipCap when feeHistory carried no rewards.
	priorityFee = latestReward(hist)
	if priorityFee == nil {
		tip, terr := c.ec.SuggestGasTipCap(ctx)
		if terr != nil {
			return nil, nil, nil, unreachableErr(c.opts, "gastip", terr)
		}
		priorityFee = tip
	}

	// maxFee = 2*baseFee + priorityFee (one base-fee-doubling of headroom).
	maxFee = new(big.Int).Mul(baseFee, big.NewInt(2))
	maxFee.Add(maxFee, priorityFee)
	return maxFee, priorityFee, baseFee, nil
}

// latestBaseFee returns the projected next-block base fee from a FeeHistory, or
// nil when the node returned no base-fee data (legacy chain).
func latestBaseFee(h *ethereum.FeeHistory) *big.Int {
	if h == nil || len(h.BaseFee) == 0 {
		return nil
	}
	last := h.BaseFee[len(h.BaseFee)-1]
	if last == nil {
		return nil
	}
	return new(big.Int).Set(last)
}

// latestReward returns the most recent non-nil priority-fee sample (the single
// requested percentile) from a FeeHistory, or nil when no rewards were returned.
func latestReward(h *ethereum.FeeHistory) *big.Int {
	if h == nil {
		return nil
	}
	for i := len(h.Reward) - 1; i >= 0; i-- {
		row := h.Reward[i]
		if len(row) > 0 && row[0] != nil {
			return new(big.Int).Set(row[0])
		}
	}
	return nil
}
