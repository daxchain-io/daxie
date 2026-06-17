package service

import (
	"context"
	"math/big"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
)

// chainprovider.go is the §2.8 per-request endpoint binding: it resolves a
// request's (network, endpoint) selection into a dialed chain.Client. It lives in
// service — the composition root that legally imports BOTH config and chain —
// because the Endpoint→chain.Options assembly (secret-reference resolution,
// TLS-path loading) must not live in config (config→chain is not a sanctioned
// edge, §7.5) and must not live in chain (chain→config likewise). Resolved
// secrets exist only transiently inside the chain.Options value built here; they
// are NEVER written back to config and NEVER logged (§7.5).
//
// ChainProvider is NOT one of the two exported provider interfaces (J24: only
// domain.Signer + chain.Client). The dialing provider is concrete service
// plumbing; the interface exists only so use-case tests can inject a
// fake-returning provider in place of a real dial.

// ChainProvider resolves a per-invocation network + endpoint override into a
// dialed chain.Client (§2.8). The CLI/MCP/HTTP frontends all choose network+rpc
// per call; service threads them here. v1 dials per call (no failover, no pool);
// §2.10's ordered-endpoint evolution plugs in behind this same seam with no
// caller change.
type ChainProvider interface {
	// ClientFor resolves the request's network (req.Network, else the configured
	// defaults.network) and endpoint (req.RPC, else that network's default-rpc),
	// assembles chain.Options (secret refs resolved in-memory, TLS paths attached),
	// and dials — running the chain-ID guard. The CALLER Close()s the returned
	// client.
	ClientFor(ctx context.Context, req ChainRequest) (chain.Client, error)

	// VerifyEndpoint dials an explicit endpoint config bound to netName and runs
	// the chain-ID guard, WITHOUT requiring the endpoint to be present in the
	// merged config snapshot. It backs add-time verification (`rpc add`), where the
	// endpoint has just been written to disk but is not yet in the in-memory
	// config. netName must name a known network (its declared chain-id is the
	// ExpectChainID). The caller does NOT receive a client — VerifyEndpoint dials,
	// checks, and closes. A chain-ID mismatch returns rpc.chain_id_mismatch (exit
	// 12); a transport/secret-resolution failure is returned for the caller to
	// downgrade to a warning (so a genuinely-offline add still works).
	VerifyEndpoint(ctx context.Context, netName string, ep config.Endpoint) error
}

// ChainRequest is the per-invocation network/endpoint selection. Both empty means
// "use the config defaults" (defaults.network, then that network's default-rpc).
type ChainRequest struct {
	Network string // the network (chain); "" = config defaults.network
	RPC     string // the endpoint override; "" = the network's default-rpc
}

// dialFunc is the dial seam chain.Dial satisfies; tests swap it for one returning
// a chain/fake so a use case can be exercised without a network.
type dialFunc func(ctx context.Context, opts chain.Options) (chain.Client, error)

// dialingProvider is the v1 concrete ChainProvider: stateless, dials per call.
type dialingProvider struct {
	cfg            *config.Config
	defaultNetwork string   // the process default (Options.Network / defaults.network)
	defaultRPC     string   // the process default endpoint override (Options.RPC)
	dial           dialFunc // = chain.Dial; swappable in tests
}

// newDialingProvider builds the v1 provider over the merged config. defNet/defRPC
// are the per-process defaults the cli frontend resolved (Options.Network /
// Options.RPC); an empty defNet falls through to cfg.Defaults.Network.
func newDialingProvider(cfg *config.Config, defNet, defRPC string) *dialingProvider {
	return &dialingProvider{
		cfg:            cfg,
		defaultNetwork: defNet,
		defaultRPC:     defRPC,
		dial:           chain.Dial,
	}
}

// ClientFor performs the §2.8 resolution + the §7.5 fail-closed error mapping:
//
//   - network = req.Network → d.defaultNetwork → cfg.Defaults.Network; unknown →
//     ref.not_found.
//   - endpoint = req.RPC → d.defaultRPC → the network's default-rpc; unknown →
//     ref.not_found; an endpoint bound to a different network → usage.rpc_network_mismatch.
//   - a --rpc that names a NETWORK (not an endpoint) → ref.not_found (strict
//     separation, §7.5).
//   - no resolvable default endpoint for the network → ref.not_found with a hint.
//   - secret ref unresolved → secret.unresolved (from config.ResolveSecretRefs).
//   - chain-id mismatch / transport failure are raised by chain.Dial
//     (rpc.chain_id_mismatch exit 12 / rpc.unreachable exit 6).
func (d *dialingProvider) ClientFor(ctx context.Context, req ChainRequest) (chain.Client, error) {
	opts, err := d.optionsFor(req)
	if err != nil {
		return nil, err
	}
	return d.dial(ctx, opts)
}

// optionsFor is the pure resolution+assembly half of ClientFor, split out so it is
// unit-testable without dialing (it performs the §7.5 secret resolution into a
// transient chain.Options).
func (d *dialingProvider) optionsFor(req ChainRequest) (chain.Options, error) {
	// ── 1. resolve the network ──
	netName := firstNonEmpty(req.Network, d.defaultNetwork, d.cfg.Defaults.Network)
	if netName == "" {
		return chain.Options{}, domain.New(domain.CodeRefNotFound,
			"no network selected and no default network configured (set one with `daxie network use`)")
	}
	net, ok := d.cfg.Networks[netName]
	if !ok {
		return chain.Options{}, domain.Newf(domain.CodeRefNotFound,
			"unknown network %q", netName)
	}

	// ── 2. resolve the endpoint (strict separation: --rpc selects an ENDPOINT) ──
	epName := firstNonEmpty(req.RPC, d.defaultRPC, net.DefaultRPC)
	if epName == "" {
		return chain.Options{}, domain.Newf(domain.CodeRefNotFound,
			"no default endpoint for network %q; add one with `daxie rpc add` or pass --rpc", netName)
	}
	ep, ok := d.cfg.RPC[epName]
	if !ok {
		// A common mistake is passing a network name to --rpc. Name the strict
		// separation in the message but keep the code ref.not_found (§7.5).
		if _, isNet := d.cfg.Networks[epName]; isNet {
			return chain.Options{}, domain.Newf(domain.CodeRefNotFound,
				"%q is a network, not an endpoint; --rpc selects an endpoint (see `daxie rpc list`)", epName)
		}
		return chain.Options{}, domain.Newf(domain.CodeRefNotFound,
			"unknown endpoint %q", epName)
	}
	// An endpoint is bound to exactly one network; using it on another is a
	// configuration mismatch (a misrouted request must never read the wrong chain).
	if ep.Network != "" && ep.Network != netName {
		return chain.Options{}, domain.Newf(domain.CodeUsageRPCNetworkMismatch,
			"endpoint %q is bound to network %q, not %q", epName, ep.Network, netName)
	}

	// ── 3. resolve secret refs IN-MEMORY (never persisted) and assemble Options ──
	return assembleOptions(netName, net, ep)
}

// assembleOptions resolves an endpoint's ${env:}/${file:} refs IN-MEMORY (never
// persisted, §7.5) and builds the transient chain.Options for a dial: the resolved
// URL, the MASKED DisplayURL (so the resolved secret is never logged), the
// network's declared chain-id as ExpectChainID (so Dial runs the guard), resolved
// headers, and the mTLS file paths. It is shared by the config-lookup path
// (optionsFor) and the add-time verification path (VerifyEndpoint) so the two
// assemble identically.
func assembleOptions(netName string, net config.Network, ep config.Endpoint) (chain.Options, error) {
	url, err := config.ResolveSecretRefs(ep.URLRef)
	if err != nil {
		return chain.Options{}, err
	}
	var headers map[string]string
	if len(ep.Headers) > 0 {
		headers = make(map[string]string, len(ep.Headers))
		for k, v := range ep.Headers {
			rv, herr := config.ResolveSecretRefs(v)
			if herr != nil {
				return chain.Options{}, herr
			}
			headers[k] = rv
		}
	}

	opts := chain.Options{
		URL: url,
		// DisplayURL is the MASKED form of the RAW ref (a ${env:…}/${file:…}
		// reference shown verbatim; a literal/resolved key segment reduced to
		// "***"). chain uses it in error messages/data envelopes so the resolved
		// secret in URL is never logged (§7.5).
		DisplayURL:    config.MaskSecretRefs(ep.URLRef),
		Network:       netName,
		ExpectChainID: new(big.Int).SetUint64(net.ChainID),
		Headers:       headers,
		Timeout:       ep.Timeout,
	}
	if ep.TLS != nil {
		opts.TLSCert = ep.TLS.Cert
		opts.TLSKey = ep.TLS.Key
		opts.TLSCA = ep.TLS.CA
	}
	return opts, nil
}

// VerifyEndpoint dials an explicit endpoint bound to netName and runs the chain-ID
// guard, used by `rpc add` to catch a reachable wrong-chain endpoint at
// registration (the in-memory config snapshot does not yet contain the
// just-written endpoint, so this assembles transient Options directly rather than
// looking the endpoint up). An unknown network is ref.not_found; a chain-ID
// mismatch surfaces from chain.Dial as rpc.chain_id_mismatch (exit 12); a
// transport/secret failure is returned for the caller to downgrade to a warning.
func (d *dialingProvider) VerifyEndpoint(ctx context.Context, netName string, ep config.Endpoint) error {
	net, ok := d.cfg.Networks[netName]
	if !ok {
		return domain.Newf(domain.CodeRefNotFound, "unknown network %q", netName)
	}
	opts, err := assembleOptions(netName, net, ep)
	if err != nil {
		return err
	}
	cc, err := d.dial(ctx, opts)
	if err != nil {
		return err
	}
	cc.Close()
	return nil
}

// firstNonEmpty returns the first non-empty argument, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
