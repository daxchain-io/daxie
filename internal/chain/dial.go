package chain

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gorilla/websocket"
)

// Dial connects to the resolved endpoint and returns a ready Client. It is the
// security boundary for endpoint binding (design §2.6, requirements §6):
//
//  1. builds an *http.Client whose transport injects mTLS (a tls.Config from the
//     cert/key/CA paths, key perms-checked) and the custom headers on EVERY
//     request;
//  2. dials the go-ethereum rpc.Client with those options (rpc.WithHTTPClient +
//     rpc.WithHeaders) and wraps it in an ethclient;
//  3. VERIFIES eth_chainId == Options.ExpectChainID and refuses on mismatch —
//     fail CLOSED with domain.CodeRPCChainIDMismatch (exit 12), closing the
//     connection. A wrong/malicious endpoint must never silently read or sign
//     for the wrong chain.
//
// A transport/dial failure maps to domain.CodeRPCUnreachable (exit 6). The dial
// and the chain-id probe are bounded by ctx and by Options.Timeout (default
// 30s).
//
// ws://wss:// URLs yield a websocket-backed client whose Subscribe* work; an
// http(s):// URL yields an HTTP client whose Subscribe* return ErrNotSupported.
func Dial(ctx context.Context, o Options) (Client, error) {
	to := o.timeout()

	dialCtx, cancel := context.WithTimeout(ctx, to)
	defer cancel()

	ws := isWebsocket(o.URL)

	opts, err := dialOptions(o, ws)
	if err != nil {
		return nil, err // typed perms/config error from TLS assembly
	}

	rc, err := rpc.DialOptions(dialCtx, o.URL, opts...)
	if err != nil {
		return nil, unreachableErr(o, "dial", err)
	}

	c := &client{
		rc:   rc,
		ec:   ethclient.NewClient(rc),
		opts: o,
		ws:   ws,
	}

	// Chain-ID verification guard. ExpectChainID nil skips it (non-command probe
	// paths only); the command path always sets it.
	if o.ExpectChainID != nil {
		idCtx, idCancel := context.WithTimeout(ctx, to)
		defer idCancel()
		got, err := c.ec.ChainID(idCtx)
		if err != nil {
			c.Close()
			return nil, unreachableErr(o, "chainid", err)
		}
		if got == nil || got.Cmp(o.ExpectChainID) != 0 {
			c.Close()
			return nil, chainIDMismatchErr(o, got)
		}
	}

	return c, nil
}

// dialOptions builds the rpc.ClientOption slice carrying the endpoint's mTLS
// material + custom headers. The mTLS *tls.Config (client cert + custom CA pool,
// key perms-checked) MUST reach whichever transport is in use:
//
//   - HTTP(S): an *http.Client whose transport sets TLSClientConfig (and, as
//     belt-and-suspenders, re-applies headers on every request incl. reconnects);
//   - WS(S): a websocket.Dialer whose TLSClientConfig carries the SAME material —
//     go-ethereum's WithHTTPClient does NOT reach the websocket transport, so a
//     dialer must be supplied explicitly or the client cert + custom CA are
//     silently dropped (mTLS fails / a private CA is bypassed).
//
// rpc.WithHeaders attaches headers to BOTH handshakes, so it is added regardless.
func dialOptions(o Options, ws bool) ([]rpc.ClientOption, error) {
	tlsCfg, err := buildTLSConfig(o)
	if err != nil {
		return nil, err
	}

	var opts []rpc.ClientOption

	// Headers via the rpc client option attach to BOTH http and websocket
	// handshakes (go-ethereum applies rpc.WithHeaders to each).
	if len(o.Headers) > 0 {
		h := make(http.Header, len(o.Headers))
		for k, v := range o.Headers {
			h.Set(k, v)
		}
		opts = append(opts, rpc.WithHeaders(h))
	}

	if ws {
		// For WS(S), the mTLS config rides a websocket.Dialer; without it the client
		// cert + custom CA pool would never reach the handshake (WithHTTPClient is
		// not consulted by the websocket transport). Carry the same buffer/proxy
		// defaults go-ethereum uses for its built-in dialer so behaviour matches
		// the no-TLS path.
		if tlsCfg != nil {
			opts = append(opts, rpc.WithWebsocketDialer(websocket.Dialer{
				Proxy:            http.ProxyFromEnvironment,
				HandshakeTimeout: o.timeout(),
				ReadBufferSize:   wsBufferSize,
				WriteBufferSize:  wsBufferSize,
				WriteBufferPool:  wsBufferPool,
				TLSClientConfig:  tlsCfg,
			}))
		}
		return opts, nil
	}

	// For HTTP(S), supply an *http.Client whose transport carries mTLS and (as
	// belt-and-suspenders) the same headers on every request including reconnects.
	base := http.DefaultTransport.(*http.Transport).Clone()
	if tlsCfg != nil {
		base.TLSClientConfig = tlsCfg
	}
	hc := &http.Client{
		Timeout:   o.timeout(),
		Transport: newHeaderRoundTripper(base, o.Headers),
	}
	opts = append(opts, rpc.WithHTTPClient(hc))

	return opts, nil
}

// wsBufferSize and wsBufferPool mirror go-ethereum's built-in websocket dialer
// defaults (rpc/websocket.go: 1024-byte read/write buffers sharing one pool) so a
// TLS-carrying dialer behaves identically to the default one in every respect but
// the TLS config.
const wsBufferSize = 1024

var wsBufferPool = new(sync.Pool)

// isWebsocket reports whether url uses a websocket scheme (ws:// or wss://).
// Scheme detection is case-insensitive and ignores surrounding whitespace.
func isWebsocket(url string) bool {
	u := strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(u, "ws://") || strings.HasPrefix(u, "wss://")
}
