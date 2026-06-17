package service

import (
	"context"
	"errors"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ens"
	"github.com/ethereum/go-ethereum/common"
)

// ens.go is the M7 ENS resolution surface (design §2.8/§4.8): the `daxie ens
// resolve|reverse` use cases plus the private destination/pin resolution helpers the
// tx/balance/policy paths call. Resolution is PER-INVOCATION against the connected
// network's ENS registry (§2.8: ens.Resolver takes the request's chain.Client per
// call, no constructor state). The resolved address is ALWAYS echoed before signing
// — the EvResolved emit in resolveIntent/balance does that; this file supplies the
// real address those echoes carry.
//
// Pin safety (the non-negotiable, §4.8): ENS is accepted only in destination/
// read-only positions, never as a signing-from identity (the keystore's AddressOf/
// LookupSigning already reject RefENS in a signing position). A reverse name is only
// trusted when it forward-resolves back to the address (ens.Reverse forward-verifies
// inside the package). The allow-time pin (policy allow / contacts add) snapshots the
// resolved 0x; a later send re-resolves and the §4.3 stage-4 gate refuses on drift.

// EnsResolve is `daxie ens resolve <name>`: forward-resolve a name to its address on
// the request's network. It dials the per-request endpoint (§2.8) and calls
// s.ens.Resolve with that client. An unresolved name / no-registry network / a
// transport failure map to clean ens.* domain codes (never an all-zero address
// echoed as success).
func (s *Service) EnsResolve(ctx context.Context, _ domain.Principal, req domain.EnsResolveRequest, emit domain.EventSink) (domain.EnsResolveResult, error) {
	name := req.Name
	if name == "" {
		return domain.EnsResolveResult{}, domain.New(domain.CodeUsage+".bad_ens", "an ENS name is required (e.g. vitalik.eth)")
	}
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.EnsResolveResult{}, err
	}
	defer cc.Close()

	addr, err := s.ens.Resolve(ctx, cc, name)
	if err != nil {
		return domain.EnsResolveResult{}, mapENSErr(err, name)
	}
	emitResolved(emit, addr.Hex(), "ens "+name)
	return domain.EnsResolveResult{
		Name:    name,
		Address: addr.Hex(),
		Network: s.networkName(req.Network),
	}, nil
}

// EnsReverse is `daxie ens reverse <addr>`: reverse-resolve an address to its primary
// ENS name on the request's network. The result is FORWARD-VERIFIED inside
// ens.Reverse (a reverse name is only trusted when it forward-resolves back to the
// address, §4.8); an unverified record returns Name=="" Verified=false rather than a
// name that does not round-trip. A bad address is usage.*; a transport failure maps
// to rpc.*.
func (s *Service) EnsReverse(ctx context.Context, _ domain.Principal, req domain.EnsReverseRequest, emit domain.EventSink) (domain.EnsReverseResult, error) {
	if !common.IsHexAddress(req.Address) {
		return domain.EnsReverseResult{}, domain.Newf(domain.CodeUsage+".bad_address",
			"reverse lookup needs a 0x address, got %q", req.Address)
	}
	a := common.HexToAddress(req.Address)
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.EnsReverseResult{}, err
	}
	defer cc.Close()

	name, err := s.ens.Reverse(ctx, cc, a)
	if err != nil {
		// A no-registry network is a clean unsupported; any other reverse failure is
		// transport. An address with no (verified) primary name is NOT an error — it
		// returns name=="" below, so the caller renders "(no primary name)".
		return domain.EnsReverseResult{}, mapENSErr(err, req.Address)
	}
	res := domain.EnsReverseResult{
		Address:  a.Hex(),
		Name:     name,
		Verified: name != "", // ens.Reverse returns "" for an unverified record
		Network:  s.networkName(req.Network),
	}
	if name != "" {
		emitResolved(emit, a.Hex(), "ens reverse "+name)
	}
	return res, nil
}

// resolveENS is the DESTINATION-context ENS resolver shared by resolveDest (tx/nft/
// token/approve --to/--spender). It dials the request's endpoint and forward-resolves
// the name to an address, returning a Dest tagged Via="ens"/ENSName=name so the
// stage-4 pin-drift producer can tell ENS from contact from literal. It is the
// fresh, per-invocation resolution that runs in the prefetch stage BEFORE the
// spend-state lock (§2.7/§4.3 invariant — the engine does no network I/O in the
// lock). cc is owned/closed here (resolveDest never holds a client across the dial).
func (s *Service) resolveENS(ctx context.Context, cr ChainRequest, name string) (domain.Dest, error) {
	cc, err := s.chains.ClientFor(ctx, cr)
	if err != nil {
		return domain.Dest{}, err
	}
	defer cc.Close()
	addr, err := s.ens.Resolve(ctx, cc, name)
	if err != nil {
		return domain.Dest{}, mapENSErr(err, name)
	}
	return domain.Dest{Address: addr, Name: name, Via: "ens", ENSName: name}, nil
}

// resolveENSForPin is the ALLOW-TIME pin resolver (`policy allow <name.eth>` /
// `contacts add <name> <name.eth>`): it resolves the name NOW so the policy/contact
// entry pins the resolved 0x address + the name (§4.8 — store the resolved address,
// never a bare name). A later send re-resolves and the §4.3 stage-4 gate refuses if
// the resolution drifted. It dials the default network's endpoint (an allow-time pin
// is per-network: the same name on Sepolia vs mainnet is a different pin).
func (s *Service) resolveENSForPin(ctx context.Context, name string) (common.Address, error) {
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: s.defaultNetwork, RPC: s.defaultRPC})
	if err != nil {
		return common.Address{}, err
	}
	defer cc.Close()
	addr, err := s.ens.Resolve(ctx, cc, name)
	if err != nil {
		return common.Address{}, mapENSErr(err, name)
	}
	return addr, nil
}

// mapENSErr maps an ens package error to a clean §5.7 domain code so a frontend
// never surfaces a bare "ens: ..." string with the wrong exit code:
//   - ErrUnresolved   → ref.not_found (exit 10): the name does not resolve, and a
//     destination/read REQUIRED one. (A reverse of an address with no name is NOT
//     this — ens.Reverse returns "" there, not an error.)
//   - ErrNoRegistry   → usage.unsupported (exit 2): the connected network has no ENS.
//   - ErrPinChanged   → policy.denied.pin_drift (exit 3): a pinned name re-pointed.
//     (This is reached only if a caller surfaces ResolvePinned directly; the normal
//     send path routes drift through the policy engine's stage-4 gate.)
//   - anything else   → rpc.unreachable (exit 6) via mapRPCErr (transport failure).
//
// An already-typed domain error (e.g. a dial error from ClientFor that bubbled here)
// passes through unchanged.
func mapENSErr(err error, subject string) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ens.ErrUnresolved):
		return domain.Newf(domain.CodeRefNotFound,
			"ENS name %q does not resolve on this network", subject)
	case errors.Is(err, ens.ErrNoRegistry):
		return domain.Newf(domain.CodeUsageUnsupported,
			"this network has no ENS registry; %q cannot be resolved here", subject)
	case errors.Is(err, ens.ErrPinChanged):
		return domain.Newf(domain.CodePolicyDenied+".pin_drift",
			"ENS name %q resolves to a different address than the allow-time pin", subject)
	default:
		return mapRPCErr(err)
	}
}
