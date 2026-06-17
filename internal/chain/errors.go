package chain

import (
	"context"
	"errors"
	"math/big"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	ethereum "github.com/ethereum/go-ethereum"
)

// ErrNotSupported is the typed "unsupported on this transport" error that
// Subscribe* return on an HTTP(S) endpoint. The receive loop (M8) tests
// errors.Is(err, ErrNotSupported) and falls back to polling — there is no second
// interface (design §2.6). It carries domain.Code "rpc.unsupported" so that, if
// it ever surfaces to a command, it funnels honestly through §5.7 (exit 2,
// usage class) rather than masquerading as an internal error.
var ErrNotSupported = domain.New(
	domain.CodeRPCUnsupported,
	"subscriptions require a websocket (ws:// or wss://) endpoint",
)

// ErrTxNotFound wraps ethereum.NotFound for the receipt/lookup path so callers
// can distinguish "not mined yet / unknown hash" from a transport failure with
// errors.Is(err, ErrTxNotFound) or errors.Is(err, ethereum.NotFound).
var ErrTxNotFound = errors.New("transaction not found")

// chainIDMismatchErr is the fail-CLOSED error Dial returns when the endpoint's
// reported eth_chainId does not equal the network's declared chain-id. This is
// the malicious/misconfigured-endpoint guard (a wrong endpoint must never
// silently read or sign for the wrong chain). It maps to exit 12 (integrity).
func chainIDMismatchErr(o Options, got *big.Int) error {
	// Use the MASKED display URL — the resolved URL may carry an embedded API key,
	// and this message + data map are printed to the terminal/logs (§7.5: resolved
	// secrets are never logged).
	disp := o.displayURL()
	return domain.WithData(
		domain.Newf(
			domain.CodeRPCChainIDMismatch,
			"endpoint %s reports chain-id %s but network %q declares chain-id %s; refusing to use a mismatched endpoint",
			disp, bigString(got), o.Network, bigString(o.ExpectChainID),
		),
		map[string]any{
			"endpoint": disp,
			"network":  o.Network,
			"expected": bigString(o.ExpectChainID),
			"got":      bigString(got),
		},
	)
}

// unreachableErr maps a dial/transport/RPC failure to domain.CodeRPCUnreachable
// (exit 6, retryable). A context cancellation/deadline is preserved as-is so the
// caller's own timeout funnels correctly. Already-typed domain errors (e.g. the
// chain-id mismatch, or a perms tripwire from TLS loading) pass through
// unchanged.
func unreachableErr(o Options, op string, cause error) error {
	if cause == nil {
		return nil
	}
	// A context error is the caller's deadline/cancellation: surface it verbatim
	// rather than relabeling it as an unreachable endpoint.
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	// Already a daxie error (chain-id mismatch, perms tripwire, unsupported): do
	// not re-wrap — preserve its code/exit/data.
	var de *domain.Error
	if errors.As(cause, &de) {
		return cause
	}
	// Use the MASKED display URL: the resolved URL may carry an embedded API key,
	// and an unreachable error (a typo/down node) is printed to the terminal/logs
	// (§7.5: resolved secrets are never logged). go-ethereum's HTTP transport string
	// embeds the FULL request URL (e.g. `Post "https://…/v2/<KEY>": dial tcp …`), so
	// the cause itself must be scrubbed: any occurrence of the resolved URL is
	// rewritten to the masked form before it enters the user-facing message.
	disp := o.displayURL()
	return domain.WithData(
		domain.Wrap(
			domain.CodeRPCUnreachable,
			"rpc endpoint "+disp+" unreachable during "+op+": "+scrubURL(o, cause.Error()),
			cause,
		),
		map[string]any{"endpoint": disp, "op": op},
	)
}

// scrubURL removes any occurrence of the RESOLVED endpoint URL from a transport
// error string, replacing it with the masked display form, so a go-ethereum error
// that echoes the full request URL (with an embedded API key) never reaches a
// user/log-facing message (§7.5). go-ethereum echoes the URL verbatim as it was
// passed to Dial, so an exact substring replacement is precise and cannot mangle
// the surrounding transport text.
func scrubURL(o Options, msg string) string {
	if o.URL == "" {
		return msg
	}
	return strings.ReplaceAll(msg, o.URL, o.displayURL())
}

// notFoundErr maps ethereum.NotFound to ErrTxNotFound (so errors.Is sees both),
// and any other error through unreachableErr.
func (c *client) notFoundErr(op string, cause error) error {
	if cause == nil {
		return nil
	}
	if errors.Is(cause, ethereum.NotFound) {
		return errors.Join(ErrTxNotFound, cause)
	}
	return unreachableErr(c.opts, op, cause)
}

// bigString renders a *big.Int for messages/data, tolerating nil.
func bigString(b *big.Int) string {
	if b == nil {
		return "<nil>"
	}
	return b.String()
}
