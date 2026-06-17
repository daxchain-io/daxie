// Package chain is the RPC/chain-ops boundary (design §2.6, requirements §6):
// the single load-bearing test seam (§2.9). It defines the chain.Client
// interface, the fully-resolved chain.Options that Dial consumes, and a real
// JSON-RPC/HTTP(S) (and ws://) implementation backed by go-ethereum's
// ethclient/rpc.
//
// chain is a provider leaf. It imports domain (the error taxonomy + Speed), fsx
// (the §7.9 perms check on a TLS key file), and go-ethereum value+behavioral
// packages — but NEVER service, a frontend, or config (§2.2/§7.5). config does
// not import chain either: the Endpoint→Options assembly (secret-reference
// resolution, TLS-path loading) lives in service, the composition root that
// legally imports both. Resolved secrets exist only transiently inside an
// Options value at dial time; they are never persisted (§7.5).
//
// The interface is implemented in FULL by the JSON-RPC adapter (real geth
// wrappers, not stubs that lie). M2 only WIRES ChainID/Balance/Nonce/
// BlockNumber through commands; the remaining methods are exercised by the
// shared contract-test suite (chaintest) + the fake (chain/fake) and driven by
// later milestones (gas, send, receive, contract). Subscribe* return
// ErrNotSupported on an HTTP(S) transport — the receive loop (M8) falls back
// from that to polling, so there is no second interface.
package chain

import (
	"context"
	"math/big"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Client is the RPC/chain-ops boundary (design §2.6) — THE universal test seam.
// Every method is a thin, real go-ethereum ethclient/rpc wrapper in the
// JSON-RPC adapter; the same contract is satisfied by chain/fake. The pair is
// kept honest by the shared chaintest suite (§2.9), which runs the identical
// assertions against both so they cannot drift.
type Client interface {
	// ChainID returns eth_chainId. It also backs the rpc-add/test guard and is
	// run inside Dial to refuse a mismatched endpoint.
	ChainID(ctx context.Context) (*big.Int, error)

	// Nonce returns the account transaction count. pending selects the pending
	// block (eth_getTransactionCount "pending") vs the latest block.
	Nonce(ctx context.Context, a common.Address, pending bool) (uint64, error)

	// Balance returns the native-token balance at block (nil = latest).
	Balance(ctx context.Context, a common.Address, block *big.Int) (*big.Int, error)

	// EstimateGas returns eth_estimateGas for msg.
	EstimateGas(ctx context.Context, msg ethereum.CallMsg) (uint64, error)

	// SuggestFees folds eth_feeHistory + the --speed percentile math into ONE
	// method, so the gas/speed policy lives in exactly one place. It returns
	// EIP-1559 fees (maxFeePerGas, maxPriorityFeePerGas, and the latest baseFee).
	SuggestFees(ctx context.Context, speed domain.Speed) (maxFee, priorityFee, baseFee *big.Int, err error)

	// SuggestGasPrice returns a legacy (pre-1559) gas price for legacy chains.
	SuggestGasPrice(ctx context.Context) (*big.Int, error)

	// CallContract performs eth_call. block nil = latest. Backs `contract call`
	// (--from→msg.From via Signer.Address, no unlock; --block→block).
	CallContract(ctx context.Context, msg ethereum.CallMsg, block *big.Int) ([]byte, error)

	// SendRawTransaction broadcasts an already-signed, RLP-encoded transaction
	// (eth_sendRawTransaction) and returns its hash.
	SendRawTransaction(ctx context.Context, raw []byte) (common.Hash, error)

	// Receipt returns the transaction receipt for h. A not-yet-mined / unknown
	// hash returns ErrTxNotFound (wraps ethereum.NotFound).
	Receipt(ctx context.Context, h common.Hash) (*types.Receipt, error)

	// BlockNumber returns the latest block height.
	BlockNumber(ctx context.Context) (uint64, error)

	// BlockByNumber returns a full block (n nil = latest). fullTx selects whether
	// transaction bodies are included (the receive ETH scan needs them).
	BlockByNumber(ctx context.Context, n *big.Int, fullTx bool) (*types.Block, error)

	// FilterLogs returns logs matching q (eth_getLogs). Backs `contract logs`
	// and the §5.8 receive engine.
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)

	// SubscribeLogs streams logs over a websocket. On an HTTP(S) transport it
	// returns ErrNotSupported (no second interface; the caller polls instead).
	SubscribeLogs(ctx context.Context, q ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error)

	// SubscribeNewHead streams new block heights over a websocket. On an HTTP(S)
	// transport it returns ErrNotSupported.
	SubscribeNewHead(ctx context.Context, ch chan<- uint64) (ethereum.Subscription, error)

	// Close releases the underlying connection. Safe to call more than once.
	Close()
}

// DefaultTimeout is the per-dial / per-request timeout applied when
// Options.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// Options is the FULLY RESOLVED endpoint that Dial consumes. service assembles
// it from a config.Endpoint at dial time:
//
//   - URL has its ${env:}/${file:} references ALREADY resolved (the resolved
//     secret lives only for the lifetime of this struct and is never persisted,
//     §7.5);
//   - Headers carry ref-resolved values and are attached to EVERY RPC request;
//   - TLS{Cert,Key,CA} are file PATHS (mTLS), not secret references; the key
//     file is perms-checked like a passphrase file before it is loaded.
//
// config NEVER builds this value (config→chain is not a sanctioned edge, §7.5).
type Options struct {
	// URL is the resolved endpoint URL (no ${…} references remain). http(s)://
	// dials an HTTP transport; ws(s):// a websocket transport (Subscribe*
	// supported only on the latter). The resolved URL may carry a secret (an API
	// key embedded in the path/query) and is therefore NEVER put into a
	// user/log-facing string — error messages and data envelopes use DisplayURL.
	URL string

	// DisplayURL is the MASKED form of the endpoint URL, safe to log and to embed
	// in error messages/data envelopes (e.g. a resolved API-key segment is reduced
	// to "***", a ${env:…}/${file:…} reference is shown verbatim). service fills it
	// from config.MaskSecretRefs(ep.URLRef) at dial time (§7.5). When empty (a
	// caller that did not supply one), Dial derives a masked form from URL so a
	// resolved secret is never leaked even on that path.
	DisplayURL string

	// Network is the declared network name, carried only for error messages and
	// data envelopes (it never affects dialing).
	Network string

	// ExpectChainID is the network's declared chain-id. Dial verifies that
	// eth_chainId equals this and refuses on mismatch with
	// domain.CodeRPCChainIDMismatch (exit 12). A nil ExpectChainID skips the
	// guard (used only by callers that have no declared network, e.g. an
	// exploratory probe — not the command path).
	ExpectChainID *big.Int

	// Headers are resolved custom headers attached to every RPC request (e.g. an
	// Authorization bearer token). Values may contain anything; they are never
	// logged.
	Headers map[string]string

	// TLSCert / TLSKey are the mTLS client certificate + private-key PATHS
	// (optional; both must be set together to enable client auth). TLSKey is
	// perms-checked with fsx.CheckPerms before loading.
	TLSCert string
	TLSKey  string

	// TLSCA is an optional CA-bundle PATH used to verify the server certificate.
	// Empty means the system root pool is used.
	TLSCA string

	// Timeout bounds the dial and each request. Zero = DefaultTimeout.
	Timeout time.Duration
}

// timeout returns the effective per-dial/request timeout.
func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

// displayURL returns the masked, log-safe endpoint URL for error messages and
// data envelopes. It prefers the service-supplied DisplayURL (config.MaskSecretRefs
// of the RAW ref, so a ${env:…} reference is shown verbatim); when that is empty it
// derives a masked form from the RESOLVED URL so a leaked API key is still never
// surfaced (the §7.5 contract: resolved secrets are never logged).
func (o Options) displayURL() string {
	if o.DisplayURL != "" {
		return o.DisplayURL
	}
	return maskResolvedURL(o.URL)
}
