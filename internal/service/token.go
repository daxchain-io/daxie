package service

import (
	"context"
	"math/big"
	"strings"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/erc"
	"github.com/daxchain-io/daxie/internal/ethunit"
	"github.com/daxchain-io/daxie/internal/registry"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// token.go is the M5 token-registry use-case layer + the asset-resolution
// chokepoint (design §2.8, §5.1, §7.8, cli-spec §`daxie token`). It holds:
//
//   - the registry CRUD use cases (TokenInfo/Add/Rename/List/Remove) over the
//     §7.8 per-network token store + the bundled majors;
//   - resolveAsset — the ONE place a --token (alias | 0x) is turned into a
//     concrete {contract, decimals, kind}: an alias resolves REGISTRY-ONLY (file
//     ∪ bundled — never an on-chain symbol() lookup, the anti-spoofing wall); a
//     raw 0x contract is always allowed (decimals read on-chain for DISPLAY only);
//   - TokenAllowance — the read-only allowance(owner,spender) eth_call.
//
// The transfer path (tx send --token) lives in tx.go and the approve/revoke path
// in approve.go; both call resolveAsset here so the alias-resolution security
// property is enforced in exactly one place.

// allowanceSelector is the ERC-20 allowance(address,address) function selector
// (the first 4 bytes of keccak256("allowance(address,address)") = 0xdd62ed3e).
// Hardcoded so service stays free of the keccak/crypto import (erc owns calldata
// building, but allowance has no builder on Ops — it is a two-arg read service
// hand-builds; the value is pinned by erc's golden selector test).
var allowanceSelector = []byte{0xdd, 0x62, 0xed, 0x3e}

// resolvedAsset is the network-confirmed token a send/approve/allowance uses. It
// is the output of resolveAsset and the single shape the token paths consume.
type resolvedAsset struct {
	contract common.Address // the token contract (the tx `To`; NEVER the policy dest)
	decimals uint8          // display precision (read once; amounts cross as base units)
	kind     string         // "erc20"
	alias    string         // the registry alias when it came from one ("" for a raw 0x)
	symbol   string         // display only
	bundled  bool           // provenance: a compiled-in major
}

// resolveAsset turns a --token reference (alias | 0x contract) into a resolved
// {contract, decimals, kind} on the request's network. It is the ONE asset
// chokepoint (§5.1) both the transfer and approve paths funnel through.
//
//  1. A raw 0x address is ALWAYS allowed (the spec: "--token accepts a raw
//     contract address"): the contract is the literal; decimals are read on-chain
//     via erc.Decimals (DISPLAY only); kind defaults erc20 (M6 detects 721/1155).
//     If the literal IS a registered alias's address, its alias/symbol/decimals
//     are surfaced (the registered entry is authoritative for display).
//  2. Otherwise it is an ALIAS: discovery.ResolveAsset (registry-only: file ∪
//     bundled). FOUND ⇒ use the registered {address,decimals,kind}. NOT FOUND ⇒
//     ref.not_found — the anti-spoofing wall: NO erc.Symbol fallback, EVER.
//
// A nil chain.Client is allowed only for the registry-alias path (no chain read
// needed); the raw-0x path requires a live client to read decimals.
func (s *Service) resolveAsset(ctx context.Context, cc chain.Client, network, tokenRef string) (resolvedAsset, error) {
	tokenRef = strings.TrimSpace(tokenRef)
	if tokenRef == "" {
		return resolvedAsset{}, domain.New(domain.CodeUsage+".no_token",
			"--token is required (a registry alias or a 0x contract address)")
	}

	// ── 1. raw 0x contract literal ──
	if common.IsHexAddress(tokenRef) {
		contract := common.HexToAddress(tokenRef)
		// If the literal address is a registered/bundled token, prefer its registry
		// metadata (alias + stored decimals/symbol) — no chain read needed, and the
		// alias echo helps the human confirm "this is the token I registered".
		if reg, ok := s.lookupByAddress(ctx, network, contract); ok {
			return resolvedAsset{
				contract: contract,
				decimals: reg.Decimals,
				kind:     orERC20(reg.Kind),
				alias:    reg.Alias,
				symbol:   reg.Symbol,
				bundled:  reg.Bundled,
			}, nil
		}
		// Unregistered literal: read decimals on-chain for DISPLAY only (amounts still
		// cross as base-unit strings). A non-ERC-20 address surfaces ErrNotERC20 (exit 2).
		if cc == nil {
			return resolvedAsset{}, domain.New(domain.CodeRPCUnreachable,
				"a chain endpoint is required to read the decimals of an unregistered token contract")
		}
		dec, err := s.erc.Decimals(ctx, cc, contract)
		if err != nil {
			return resolvedAsset{}, mapRPCErr(err)
		}
		sym, _ := s.erc.Symbol(ctx, cc, contract) // display only; a failure leaves it empty
		return resolvedAsset{contract: contract, decimals: dec, kind: registry.KindERC20, symbol: sym}, nil
	}

	// ── 2. registry alias (registry-only; NEVER an on-chain symbol() lookup) ──
	rt, found, err := s.discovery.ResolveAsset(ctx, network, tokenRef)
	if err != nil {
		return resolvedAsset{}, err
	}
	if !found {
		// The anti-spoofing wall: a name not in the registry (or bundled set) is an
		// ERROR — symbol spoofing is free, so daxie never resolves a name by symbol().
		return resolvedAsset{}, domain.Newf(domain.CodeRefNotFound,
			"no token aliased %q on %s; register it with `daxie token add <0x> --name %s` or pass a 0x contract address",
			tokenRef, network, tokenRef)
	}
	return resolvedAsset{
		contract: rt.Address,
		decimals: rt.Decimals,
		kind:     orERC20(rt.Kind),
		alias:    rt.Alias,
		symbol:   rt.Symbol,
		bundled:  rt.Bundled,
	}, nil
}

// lookupByAddress finds a registered/bundled token whose address matches addr on a
// network (case-insensitive), so a raw-0x --token that names a registered token
// surfaces its alias/decimals/symbol. It scans the merged known set (file ∪
// bundled). found=false on a miss (an unregistered literal).
func (s *Service) lookupByAddress(ctx context.Context, network string, addr common.Address) (registry.ResolvedToken, bool) {
	known, err := s.discovery.KnownAssets(ctx, network, common.Address{})
	if err != nil {
		return registry.ResolvedToken{}, false
	}
	for _, k := range known {
		if k.Address == addr {
			return k, true
		}
	}
	return registry.ResolvedToken{}, false
}

// ── token info/add/rename/list/remove use cases ──────────────────────────────

// TokenInfo reads on-chain metadata (symbol/decimals + kind) for a token WITHOUT
// registering it (`daxie token info`). An alias resolves registry-only (a miss is
// ref.not_found); a raw 0x reads on-chain. It reports whether the address is in the
// local registry so the cli can suggest `token add`.
func (s *Service) TokenInfo(ctx context.Context, _ domain.Principal, req domain.TokenInfoRequest, emit domain.EventSink) (domain.TokenInfoResult, error) {
	network := s.networkName(req.Network)
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.TokenInfoResult{}, err
	}
	defer cc.Close()

	ra, err := s.resolveAsset(ctx, cc, network, req.Token)
	if err != nil {
		return domain.TokenInfoResult{}, err
	}

	// For a registered alias resolveAsset returns the stored decimals/symbol (no
	// chain read); always read the LIVE on-chain symbol/decimals for the info view so
	// `token info` reports what the contract actually says (a registry/chain mismatch
	// is itself worth seeing). Display only — never used to resolve.
	if dec, derr := s.erc.Decimals(ctx, cc, ra.contract); derr == nil {
		ra.decimals = dec
	}
	if sym, serr := s.erc.Symbol(ctx, cc, ra.contract); serr == nil && sym != "" {
		ra.symbol = sym
	}

	emitResolved(emit, ra.contract.Hex(), "token "+ra.contract.Hex())
	return domain.TokenInfoResult{
		Network:    network,
		Contract:   ra.contract.Hex(),
		Kind:       ra.kind,
		Symbol:     ra.symbol,
		Decimals:   int(ra.decimals),
		Registered: ra.alias != "",
		Alias:      ra.alias,
		Bundled:    ra.bundled,
	}, nil
}

// TokenAdd registers a token alias→contract (`daxie token add <0x> [--name]`). The
// contract MUST be a raw 0x address; the alias defaults to the case-folded on-chain
// symbol when --name is empty (read via erc.Symbol — the registry never touches the
// chain). A collision with a file entry OR a bundled major is usage.duplicate
// (instructing --name). decimals/kind are detected on-chain at add and stored.
func (s *Service) TokenAdd(ctx context.Context, _ domain.Principal, req domain.TokenAddRequest) (domain.TokenResult, error) {
	network := s.networkName(req.Network)
	if !common.IsHexAddress(strings.TrimSpace(req.Contract)) {
		return domain.TokenResult{}, domain.Newf(domain.CodeUsage+".bad_address",
			"token contract %q is not a 0x address", req.Contract)
	}
	contract := common.HexToAddress(strings.TrimSpace(req.Contract))

	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.TokenResult{}, err
	}
	defer cc.Close()

	// Detect kind + read decimals/symbol on-chain (the registry stores them; resolution
	// never uses symbol). A non-ERC-20 address fails here (ErrNotERC20, exit 2) — daxie
	// refuses to register a non-token.
	dec, err := s.erc.Decimals(ctx, cc, contract)
	if err != nil {
		return domain.TokenResult{}, mapRPCErr(err)
	}
	sym, _ := s.erc.Symbol(ctx, cc, contract) // display only; a failure leaves it empty

	alias := strings.TrimSpace(req.Name)
	if alias == "" {
		// Default the alias to the case-folded on-chain symbol. If the symbol cannot
		// fold to a valid §3.1 alias, require an explicit --name (the registry Add
		// will reject a bad grammar; surface a clear message here).
		alias = strings.ToLower(sym)
		if alias == "" {
			return domain.TokenResult{}, domain.New(domain.CodeUsage+".no_name",
				"the token has no readable symbol; give it an alias with --name")
		}
	}

	tok := registry.Token{
		Alias:    alias,
		Address:  contract,
		Kind:     registry.KindERC20,
		Decimals: dec,
		Symbol:   sym,
	}
	if err := s.tokens.Add(ctx, network, tok); err != nil {
		return domain.TokenResult{}, err
	}
	return domain.TokenResult{Token: domain.TokenRow{
		Alias:    tok.Alias,
		Contract: contract.Hex(),
		Kind:     registry.KindERC20,
		Symbol:   sym,
		Decimals: int(dec),
		Network:  network,
	}}, nil
}

// TokenRename renames a FILE alias (`daxie token rename <old> <new>`). A bundled
// major cannot be renamed in place (usage.bundled_immutable); an absent old alias
// is ref.not_found.
func (s *Service) TokenRename(ctx context.Context, _ domain.Principal, req domain.TokenRenameRequest) (domain.TokenResult, error) {
	network := s.networkName(req.Network)
	if err := s.tokens.Rename(ctx, network, req.Old, req.New); err != nil {
		return domain.TokenResult{}, err
	}
	// Echo the renamed row (resolve it to surface the address/decimals/symbol).
	rt, found, err := s.discovery.ResolveAsset(ctx, network, req.New)
	if err != nil || !found {
		// The rename succeeded; an echo-resolution failure is non-fatal — return the
		// names we know.
		return domain.TokenResult{Token: domain.TokenRow{
			Alias: strings.ToLower(strings.TrimSpace(req.New)), Network: network, Kind: registry.KindERC20,
		}}, nil
	}
	return domain.TokenResult{Token: tokenRow(rt, network)}, nil
}

// TokenList returns the merged known set (bundled majors ∪ file entries),
// alias-sorted, each row marked Bundled for provenance (`daxie token list`).
func (s *Service) TokenList(ctx context.Context, _ domain.Principal, req domain.TokenListRequest) (domain.TokenListResult, error) {
	network := s.networkName(req.Network)
	rows, err := s.tokens.List(ctx, network)
	if err != nil {
		return domain.TokenListResult{}, err
	}
	out := make([]domain.TokenRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, tokenRow(r, network))
	}
	return domain.TokenListResult{Network: network, Tokens: out}, nil
}

// TokenRemove deletes a FILE alias (`daxie token remove <alias>`). A bundled major
// cannot be removed (usage.bundled_immutable); an absent alias is ref.not_found.
func (s *Service) TokenRemove(ctx context.Context, _ domain.Principal, req domain.TokenRemoveRequest) (domain.TokenRemoveResult, error) {
	network := s.networkName(req.Network)
	if err := s.tokens.Remove(ctx, network, req.Alias); err != nil {
		return domain.TokenRemoveResult{}, err
	}
	return domain.TokenRemoveResult{Alias: strings.ToLower(strings.TrimSpace(req.Alias)), Network: network, Removed: true}, nil
}

// ── allowance read (read-only eth_call; no signing, no policy) ────────────────

// TokenAllowance reads allowance(owner, spender) for a token (`daxie token
// allowance`). Owner defaults to the active account; spender is a 0x address or a
// contact name. No signing, no policy — a pure read. Decimals come from
// resolveAsset (display); the allowance crosses as a base-unit string + a
// decimals-aware human form (no float).
func (s *Service) TokenAllowance(ctx context.Context, _ domain.Principal, req domain.AllowanceRequest, emit domain.EventSink) (domain.AllowanceResult, error) {
	network := s.networkName(req.Network)

	// Owner: the request ref or the §7.7 default account. AddressOf is the read-only
	// resolver (no unlock — allowance is a read).
	ownerStr := strings.TrimSpace(req.Owner)
	if ownerStr == "" {
		ownerStr = s.activeDefault(ctx)
	}
	if ownerStr == "" {
		return domain.AllowanceResult{}, domain.New(domain.CodeUsage+".no_account",
			"no --owner given and no default account set (run `daxie account use`)")
	}
	ownerRef, err := domain.ParseAccountRef(ownerStr)
	if err != nil {
		return domain.AllowanceResult{}, err
	}
	owner, err := s.keys.AddressOf(ownerRef)
	if err != nil {
		return domain.AllowanceResult{}, err
	}

	// Spender: a 0x literal or a contact name (the same resolver tx/approve use).
	spenderDest, err := s.resolveDest(ctx, req.Spender)
	if err != nil {
		return domain.AllowanceResult{}, err
	}
	spender := spenderDest.Address

	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.AllowanceResult{}, err
	}
	defer cc.Close()

	ra, err := s.resolveAsset(ctx, cc, network, req.Token)
	if err != nil {
		return domain.AllowanceResult{}, err
	}

	amt, err := s.readAllowance(ctx, cc, ra.contract, owner, spender)
	if err != nil {
		return domain.AllowanceResult{}, err
	}

	emitResolved(emit, ra.contract.Hex(), "allowance of "+spender.Hex())
	return domain.AllowanceResult{
		Network:            network,
		Contract:           ra.contract.Hex(),
		Symbol:             ra.symbol,
		Decimals:           int(ra.decimals),
		Owner:              owner.Hex(),
		Spender:            spender.Hex(),
		Allowance:          amt.String(),
		AllowanceFormatted: ethunit.FormatTokenAmount(amt, ra.decimals),
		Unlimited:          amt.Cmp(erc.MaxUint256()) == 0,
	}, nil
}

// readAllowance performs the allowance(owner,spender) eth_call and decodes the
// uint256 return. It hand-builds the two-arg call (allowance has no calldata
// builder on erc.Ops) using the pinned selector + ABI address words.
func (s *Service) readAllowance(ctx context.Context, cc chain.Client, token, owner, spender common.Address) (*big.Int, error) {
	data := make([]byte, 0, 4+64)
	data = append(data, allowanceSelector...)
	data = append(data, common.LeftPadBytes(owner.Bytes(), 32)...)
	data = append(data, common.LeftPadBytes(spender.Bytes(), 32)...)
	to := token
	out, err := cc.CallContract(ctx, ethereum.CallMsg{To: &to, Data: data}, nil)
	if err != nil {
		return nil, mapRPCErr(err)
	}
	if len(out) < 32 {
		return nil, domain.New("usage.not_erc20", "allowance() returned no value (not an ERC-20 token?)")
	}
	return new(big.Int).SetBytes(out[:32]), nil
}

// ── projections ──────────────────────────────────────────────────────────────

// tokenRow maps a registry ResolvedToken into the wire TokenRow.
func tokenRow(r registry.ResolvedToken, network string) domain.TokenRow {
	return domain.TokenRow{
		Alias:    r.Alias,
		Contract: r.Address.Hex(),
		Kind:     orERC20(r.Kind),
		Symbol:   r.Symbol,
		Decimals: int(r.Decimals),
		Network:  network,
		Bundled:  r.Bundled,
	}
}

// orERC20 defaults an empty kind to "erc20" (every M5 token is fungible).
func orERC20(kind string) string {
	if kind == "" {
		return registry.KindERC20
	}
	return kind
}
