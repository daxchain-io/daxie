package service

import (
	"context"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ethunit"
)

// balance.go is the M2 read-only ETH balance use case (cli-spec §balance). It is
// the first command that touches the chain: it resolves the active account ref to
// an address (no unlock — a balance is a read-only/destination op, §3.2), dials
// the request's endpoint through the §2.8 ChainProvider, reads eth_getBalance at
// the latest block, and returns the value as a wei decimal string + a formatted
// ETH string (no float, §2.5).
//
// In-scope for M2: ETH, a raw 0x address, and the default account. OUT of scope
// (flag-plumbed but failing clean, NEVER faked): --token/--all (ERC-20 + the local
// registry, M5) and an ENS account ref (M7). Those return usage.unsupported so an
// agent gets an honest, branchable error rather than a fabricated zero.

// Balance returns the native (ETH) balance of the request's account on the
// selected network. The account ref resolves flag>env>meta.json (§7.7) when empty.
func (s *Service) Balance(ctx context.Context, p domain.Principal, req domain.BalanceRequest, emit domain.EventSink) (domain.BalanceResult, error) {
	// M5 paths: --token / --all. Plumbed but not active in M2 — fail clean.
	if req.Token != "" {
		return domain.BalanceResult{}, domain.New(domain.CodeUsageUnsupported,
			"token balances (--token) land in M5; M2 reads native ETH only")
	}
	if req.All {
		return domain.BalanceResult{}, domain.New(domain.CodeUsageUnsupported,
			"all-asset balances (--all) land in M5; M2 reads native ETH only")
	}

	// Resolve the account reference: an explicit ref, else the §7.7 default. An
	// empty default (no flag/env/meta.json) is a usage error — there is nothing to
	// read.
	refStr := req.Account
	if refStr == "" {
		refStr = s.activeDefault(ctx)
	}
	if refStr == "" {
		return domain.BalanceResult{}, domain.New(domain.CodeUsage+".no_account",
			"no account given and no default account set (pass an address/ref or run `daxie account use`)")
	}

	ref, err := domain.ParseAccountRef(refStr)
	if err != nil {
		return domain.BalanceResult{}, err
	}
	// M7 path: ENS account ref. Plumbed but not active in M2 — fail clean.
	if ref.Kind == domain.RefENS {
		return domain.BalanceResult{}, domain.Newf(domain.CodeUsageUnsupported,
			"ENS resolution (%s) lands in M7; pass a raw 0x address or a keystore account", ref.Raw)
	}

	// AddressOf is the §3.2 read-only resolver: a raw 0x returns its literal; an
	// HD/standalone ref returns the cached plaintext address WITHOUT unlocking. A
	// bare wallet name / unknown ref maps to ref.not_found here.
	addr, err := s.keys.AddressOf(ref)
	if err != nil {
		return domain.BalanceResult{}, err
	}

	// Dial the request's endpoint (§2.8). The provider runs the chain-ID guard and
	// maps a transport failure to rpc.unreachable (exit 6). The caller Close()s it.
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.BalanceResult{}, err
	}
	defer cc.Close()

	wei, err := cc.Balance(ctx, addr, nil) // nil = latest block
	if err != nil {
		return domain.BalanceResult{}, err
	}

	out := domain.BalanceResult{
		Address: addr.Hex(),
		Network: s.networkName(req.Network),
		Wei:     wei.String(),
		Eth:     ethunit.FormatAmount(wei, ethunit.Eth),
		Symbol:  s.nativeSymbol(req.Network),
	}
	// Echo the keystore ref back only when the request actually named a keystore
	// account (not a raw 0x literal) — useful context for a human, omitted in JSON
	// when empty.
	if ref.Kind != domain.RefAddress {
		out.Account = ref.Raw
	}
	emitResolved(emit, addr.Hex(), "balance of "+addr.Hex())
	return out, nil
}

// networkName reports the effective network name for the request (the override,
// else the process/config default), for the result envelope.
func (s *Service) networkName(reqNetwork string) string {
	name := firstNonEmpty(reqNetwork, s.defaultNetwork, s.cfg.Defaults.Network)
	return name
}

// nativeSymbol reports the selected network's native currency symbol (defaults to
// "ETH" when the network is unknown or leaves it unset).
func (s *Service) nativeSymbol(reqNetwork string) string {
	name := s.networkName(reqNetwork)
	if n, ok := s.cfg.Networks[name]; ok && n.NativeSymbol != "" {
		return n.NativeSymbol
	}
	return "ETH"
}
