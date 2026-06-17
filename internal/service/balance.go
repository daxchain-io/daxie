package service

import (
	"context"
	"math/big"
	"sort"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ethunit"
	"github.com/ethereum/go-ethereum/common"
)

// balance.go is the M2 read-only ETH balance use case (cli-spec §balance). It is
// the first command that touches the chain: it resolves the active account ref to
// an address (no unlock — a balance is a read-only/destination op, §3.2), dials
// the request's endpoint through the §2.8 ChainProvider, reads eth_getBalance at
// the latest block, and returns the value as a wei decimal string + a formatted
// ETH string (no float, §2.5).
//
// In-scope for M2: ETH, a raw 0x address, and the default account. M5 adds
// --token (a single ERC-20 balance, registry-only alias resolution or a raw 0x) and
// --all (ETH + every registry token the account holds a nonzero balance of). OUT of
// scope: an ENS account ref (M7) — it fails clean (usage.unsupported), never faked.

// Balance returns the balance of the request's account on the selected network: the
// native ETH balance (default), a single ERC-20 balance (--token), or ETH + every
// nonzero registry token (--all). The account ref resolves flag>env>meta.json (§7.7)
// when empty.
func (s *Service) Balance(ctx context.Context, p domain.Principal, req domain.BalanceRequest, emit domain.EventSink) (domain.BalanceResult, error) {
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
	// M7 path: ENS account ref. Plumbed but not active — fail clean.
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

	network := s.networkName(req.Network)
	account := ""
	if ref.Kind != domain.RefAddress {
		account = ref.Raw
	}

	switch {
	case req.Token != "":
		return s.balanceToken(ctx, cc, network, addr, account, req.Token, emit)
	case req.All:
		return s.balanceAll(ctx, cc, network, addr, account, emit)
	default:
		return s.balanceETH(ctx, cc, network, addr, account, req.Network, emit)
	}
}

// balanceETH reads the native ETH balance (the M2 path, unchanged behavior).
func (s *Service) balanceETH(ctx context.Context, cc chain.Client, network string, addr common.Address, account, reqNetwork string, emit domain.EventSink) (domain.BalanceResult, error) {
	wei, err := cc.Balance(ctx, addr, nil) // nil = latest block
	if err != nil {
		return domain.BalanceResult{}, err
	}
	emitResolved(emit, addr.Hex(), "balance of "+addr.Hex())
	return domain.BalanceResult{
		Address: addr.Hex(),
		Network: network,
		Wei:     wei.String(),
		Eth:     ethunit.FormatAmount(wei, ethunit.Eth),
		Symbol:  s.nativeSymbol(reqNetwork),
		Account: account,
	}, nil
}

// balanceToken reads a single ERC-20 balance (`balance --token <alias|0x>`). The
// token is resolved registry-only for an alias (a miss is ref.not_found) or as a raw
// 0x contract; the balance crosses as an exact base-unit string + a decimals-aware
// human form (no float). Wei/Eth stay empty — this is a token-only read.
func (s *Service) balanceToken(ctx context.Context, cc chain.Client, network string, addr common.Address, account, tokenRef string, emit domain.EventSink) (domain.BalanceResult, error) {
	ra, err := s.resolveAsset(ctx, cc, network, tokenRef)
	if err != nil {
		return domain.BalanceResult{}, err
	}
	bal, err := s.erc.BalanceOf(ctx, cc, ra.contract, addr)
	if err != nil {
		return domain.BalanceResult{}, mapRPCErr(err)
	}
	tb := tokenBalance(ra, bal)
	emitResolved(emit, addr.Hex(), "token balance of "+addr.Hex())
	return domain.BalanceResult{
		Address: addr.Hex(),
		Network: network,
		Account: account,
		Token:   &tb,
	}, nil
}

// balanceAll reads ETH + every registry token (bundled majors ∪ file entries) the
// account holds a NONZERO balance of (`balance --all`). It iterates the Discovery
// known-assets set (the §10.3 seam: a future indexer enumerates holdings instead),
// reading each balanceOf; tokens with a zero balance are omitted. The ETH value
// rides in Wei/Eth alongside.
func (s *Service) balanceAll(ctx context.Context, cc chain.Client, network string, addr common.Address, account string, emit domain.EventSink) (domain.BalanceResult, error) {
	wei, err := cc.Balance(ctx, addr, nil)
	if err != nil {
		return domain.BalanceResult{}, err
	}
	known, err := s.discovery.KnownAssets(ctx, network, addr)
	if err != nil {
		return domain.BalanceResult{}, err
	}
	var tokens []domain.TokenBalance
	for _, k := range known {
		bal, berr := s.erc.BalanceOf(ctx, cc, k.Address, addr)
		if berr != nil {
			// A single token's read failure (a self-destructed contract, a non-ERC-20
			// the user mis-registered) must not sink the whole --all view; skip it.
			continue
		}
		if bal.Sign() == 0 {
			continue // omit zero balances (the --all view shows what is held)
		}
		ra := resolvedAsset{
			contract: k.Address,
			decimals: k.Decimals,
			kind:     orERC20(k.Kind),
			alias:    k.Alias,
			symbol:   k.Symbol,
			bundled:  k.Bundled,
		}
		tokens = append(tokens, tokenBalance(ra, bal))
	}
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].Alias < tokens[j].Alias })
	emitResolved(emit, addr.Hex(), "all balances of "+addr.Hex())
	return domain.BalanceResult{
		Address: addr.Hex(),
		Network: network,
		Wei:     wei.String(),
		Eth:     ethunit.FormatAmount(wei, ethunit.Eth),
		Symbol:  s.nativeSymbol(network),
		Account: account,
		Tokens:  tokens,
	}, nil
}

// tokenBalance projects a resolved asset + a raw base-unit balance into the wire
// TokenBalance (exact base string + decimals-aware human form; no float).
func tokenBalance(ra resolvedAsset, bal *big.Int) domain.TokenBalance {
	return domain.TokenBalance{
		Alias:     ra.alias,
		Contract:  ra.contract.Hex(),
		Symbol:    ra.symbol,
		Decimals:  int(ra.decimals),
		Kind:      ra.kind,
		Base:      bal.String(),
		Formatted: ethunit.FormatTokenAmount(bal, ra.decimals),
		Bundled:   ra.bundled,
	}
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
