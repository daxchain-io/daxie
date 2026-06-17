package service

import (
	"context"
	"time"

	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
)

// addVerifyTimeout bounds the add-time chain-ID probe. `rpc add` verification is a
// quick connectivity check, not a long operation: an unreachable host must fail
// FAST and downgrade to a warning (so an offline `rpc add` is not penalised by the
// 30s default dial timeout), while a reachable wrong-chain endpoint is still caught
// well within this window.
const addVerifyTimeout = 5 * time.Second

// rpc.go is the M2 `daxie rpc` use-case surface (cli-spec §rpc):
// add/list/show/use/test/rename/remove. An ENDPOINT is a named connection bound to
// ONE network; many endpoints per network; one default per network; any command
// overrides per invocation with --rpc (§7.5). config owns the masking,
// literal-secret heuristic, and the raw-rewrite mutators; service maps the
// config-owned EndpointView into a domain.RPCRow (URL already masked) and runs the
// chain-ID guard for `rpc test` via the §2.8 ChainProvider. The cli never imports
// config (the arch matrix).

// RPCList returns every endpoint (optionally filtered to one network), sorted by
// name, with masked URLs + default/public-default markers. Read-only.
func (s *Service) RPCList(ctx context.Context, p domain.Principal, req domain.RPCListRequest) (domain.RPCListResult, error) {
	views := s.cfg.ListEndpoints(req.Network)
	out := domain.RPCListResult{RPCs: make([]domain.RPCRow, 0, len(views))}
	for _, v := range views {
		out.RPCs = append(out.RPCs, rpcRow(v))
	}
	return out, nil
}

// RPCShow returns one endpoint by name (masked URL), or ref.not_found.
func (s *Service) RPCShow(ctx context.Context, p domain.Principal, req domain.RPCShowRequest) (domain.RPCResult, error) {
	v, err := s.cfg.ShowEndpoint(req.Name)
	if err != nil {
		return domain.RPCResult{}, err
	}
	return domain.RPCResult{RPC: rpcRow(v)}, nil
}

// RPCAdd adds a named endpoint bound to a network (cli-spec §rpc add). config
// rejects a duplicate (usage.rpc_exists), an unknown network (ref.not_found), an
// empty url/network, and — under StrictSecrets — a detected literal secret
// (usage.literal_secret); otherwise a literal secret returns warnings. The URL +
// header values are stored RAW (refs preserved). A config write → config.read_only
// on a read-only mount.
func (s *Service) RPCAdd(ctx context.Context, p domain.Principal, req domain.RPCAddRequest) (domain.RPCResult, error) {
	e := config.Endpoint{
		Network: req.Network,
		URLRef:  req.URL, // RAW — ${env:}/${file:} refs preserved
		Headers: req.Headers,
		Timeout: req.Timeout.D,
	}
	if req.TLSCert != "" || req.TLSKey != "" || req.TLSCA != "" {
		e.TLS = &config.TLSFiles{Cert: req.TLSCert, Key: req.TLSKey, CA: req.TLSCA}
	}
	warnings, err := config.AddEndpoint(s.paths, req.Name, e, s.knownNetworks(), req.StrictSecrets)
	if err != nil {
		return domain.RPCResult{}, err
	}

	// Add-time chain-ID verification (cli-spec §rpc, requirements §6, design §7.5):
	// dial the just-written endpoint and verify eth_chainId == the network's
	// declared chain-id, to catch a misconfigured/malicious wrong-chain endpoint at
	// registration rather than only at first use. Per the design's "refuse/warn"
	// wording this is fail-CLOSED on a real chain-ID mismatch (rpc.chain_id_mismatch,
	// exit 12 — the security guard) but DOWNGRADES a transport/secret-resolution
	// failure (an unset ${env:} ref, an offline node) to a warning so a genuinely
	// offline `rpc add` still succeeds. The endpoint is not yet in the in-memory
	// config snapshot, so we verify the explicit Endpoint via VerifyEndpoint.
	vctx, cancel := context.WithTimeout(ctx, addVerifyTimeout)
	defer cancel()
	if verr := s.chains.VerifyEndpoint(vctx, req.Network, e); verr != nil {
		if domain.AsError(verr).Code == domain.CodeRPCChainIDMismatch {
			return domain.RPCResult{}, verr // fail closed: a wrong-chain endpoint
		}
		warnings = append(warnings,
			"could not verify endpoint "+req.Name+" at add time ("+verr.Error()+
				"); run `daxie rpc test "+req.Name+"` once it is reachable")
	}

	// Build the result row from the request (URL masked) — the write succeeded.
	row := domain.RPCRow{
		Name:       req.Name,
		Network:    req.Network,
		URL:        config.MaskSecretRefs(req.URL),
		HasHeaders: len(req.Headers) > 0,
		HasTLS:     e.TLS != nil,
	}
	return domain.RPCResult{RPC: row, Warnings: warnings}, nil
}

// RPCUse makes an endpoint the default for ITS network (cli-spec §rpc use): it
// rewrites networks.<endpoint.network>.default-rpc. An unknown endpoint is
// ref.not_found; a config write → config.read_only on a read-only mount.
func (s *Service) RPCUse(ctx context.Context, p domain.Principal, req domain.RPCUseRequest) (domain.RPCResult, error) {
	ep, ok := s.cfg.RPC[req.Name]
	if !ok {
		return domain.RPCResult{}, domain.Newf(domain.CodeRefNotFound, "no endpoint named %q", req.Name)
	}
	if err := config.UseEndpoint(s.paths, req.Name, ep.Network); err != nil {
		return domain.RPCResult{}, err
	}
	v, err := s.cfg.ShowEndpoint(req.Name)
	if err != nil {
		return domain.RPCResult{}, err
	}
	row := rpcRow(v)
	row.Default = true // it is now its network's default
	return domain.RPCResult{RPC: row}, nil
}

// RPCRename renames a user endpoint (cli-spec §rpc rename). config refuses
// renaming a built-in (usage.builtin_immutable), an unknown source (ref.not_found),
// or a target collision (usage.rpc_exists); it re-points any network default-rpc
// that named the old endpoint. A config write → config.read_only on a read-only
// mount.
func (s *Service) RPCRename(ctx context.Context, p domain.Principal, req domain.RPCRenameRequest) (domain.RPCResult, error) {
	if err := config.RenameEndpoint(s.paths, req.Old, req.New); err != nil {
		return domain.RPCResult{}, err
	}
	// Build a row from the pre-rename endpoint (the table moved verbatim).
	ep := s.cfg.RPC[req.Old]
	row := domain.RPCRow{
		Name:       req.New,
		Network:    ep.Network,
		URL:        config.MaskSecretRefs(ep.URLRef),
		HasHeaders: len(ep.Headers) > 0,
		HasTLS:     ep.TLS != nil && (ep.TLS.Cert != "" || ep.TLS.Key != "" || ep.TLS.CA != ""),
	}
	return domain.RPCResult{RPC: row}, nil
}

// RPCRemove removes a user endpoint (cli-spec §rpc remove) and clears any network
// default-rpc that pointed at it. config refuses a built-in
// (usage.builtin_immutable) and an unknown endpoint (ref.not_found). A config write
// → config.read_only on a read-only mount.
func (s *Service) RPCRemove(ctx context.Context, p domain.Principal, req domain.RPCRemoveRequest) (domain.RPCRemoveResult, error) {
	clearedFor, err := config.RemoveEndpoint(s.paths, req.Name)
	if err != nil {
		return domain.RPCRemoveResult{}, err
	}
	return domain.RPCRemoveResult{Name: req.Name, Removed: true, ClearedAsDefaultFor: clearedFor}, nil
}

// RPCTest connects to an endpoint, verifies eth_chainId matches the endpoint's
// network, and reports the round-trip latency (cli-spec §rpc test). The chain-ID
// guard runs INSIDE chain.Dial (via the ChainProvider): a mismatch fails closed
// with rpc.chain_id_mismatch (exit 12); an unreachable endpoint is rpc.unreachable
// (exit 6). Secrets resolve in-memory at dial and are masked in any echoed row.
func (s *Service) RPCTest(ctx context.Context, p domain.Principal, req domain.RPCTestRequest) (domain.RPCTestResult, error) {
	// Resolve the endpoint selection: a named endpoint binds its own network; an
	// ad-hoc Network/RPC selection is used as-is (so `rpc test --network X --rpc Y`
	// works too).
	creq := ChainRequest{Network: req.Network, RPC: req.RPC}
	network := req.Network
	if req.Name != "" {
		ep, ok := s.cfg.RPC[req.Name]
		if !ok {
			return domain.RPCTestResult{}, domain.Newf(domain.CodeRefNotFound, "no endpoint named %q", req.Name)
		}
		creq = ChainRequest{Network: ep.Network, RPC: req.Name}
		network = ep.Network
	}

	start := s.clock()
	cc, err := s.chains.ClientFor(ctx, creq) // dials + verifies eth_chainId == declared
	if err != nil {
		return domain.RPCTestResult{}, err
	}
	defer cc.Close()

	// The guard already passed inside Dial; read the verified chain-id for the
	// result and measure the round trip with the injected clock (deterministic seam).
	id, err := cc.ChainID(ctx)
	if err != nil {
		return domain.RPCTestResult{}, err
	}
	latency := s.clock().Sub(start)

	return domain.RPCTestResult{
		Name:      req.Name,
		Network:   network,
		ChainID:   id.Uint64(),
		LatencyMS: latency.Milliseconds(),
		OK:        true,
	}, nil
}

// rpcRow maps a config.EndpointView (URL already masked) into the domain wire row.
func rpcRow(v config.EndpointView) domain.RPCRow {
	return domain.RPCRow{
		Name:          v.Name,
		Network:       v.Network,
		URL:           v.URL,
		HasHeaders:    v.HasHeaders,
		HasTLS:        v.HasTLS,
		Default:       v.Default,
		PublicDefault: v.PublicDefault,
	}
}
