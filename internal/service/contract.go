package service

import (
	"context"
	"encoding/json"
	"math/big"
	"sort"
	"strings"

	dabi "github.com/daxchain-io/daxie/internal/abi"
	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/registry"
	ethereum "github.com/ethereum/go-ethereum"
	gethabi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// contract.go is the M10 `daxie contract` use-case layer (design §2.5, §5.1, §5.11,
// §7.8). It holds:
//
//   - the contract registry CRUD (ContractAdd/List/Show/Remove) over the §7.8 per-
//     network contracts[] store — alias+address+inline-ABI, validated at add, REGISTRY-
//     ONLY resolution (the anti-spoofing wall, same as tokens);
//   - the §5.11 PURE read/build paths: ContractCall (eth_call), ContractLogs
//     (eth_getLogs), EncodeCalldata + DecodeCalldata (no chain at all). They NEVER sign
//     and NEVER touch policy — no exit 3 is reachable from a read path;
//   - ContractSend — the BROADEST-REACH signing path. It resolves the ABI (registry
//     alias > --abi > --sig), coerces args, abi.PackCall → the tx data, Contract → the
//     tx To (the policy destination, resolved+echoed), --value → native value, and
//     hands an Intent to the EXISTING §5.1 authorize→broadcast→settle kernel (runSend).
//     The §4.2 ClassifyCalldata runs INSIDE authorize at stage 2 (tx.go) — a recognized
//     ERC-20/721/1155/Permit selector becomes the SAME KindApprove/KindTransfer Check
//     the typed path emits (so the spender allowlist + --unlimited --yes ceremony +
//     fail-closed gates fire identically); an unrecognized selector hits the deny-by-
//     default stage-5b gate. The 21000-EOA gas exception does NOT apply.
//
// THE SECURITY NON-NEGOTIABLE (the review hunts this): alias resolution is REGISTRY-
// ONLY. The stored ABI is a DISPLAY/ENCODE convenience; it can never change the tx
// destination (resolveContractDest reads the alias's address, not the ABI) or the
// classified spender (ClassifyCalldata reads the calldata BYTES, not the ABI claims).

// ── ABI source resolution (§2.5 precedence, enforced in core) ─────────────────

// abiSource is the resolved ABI + the destination + the resolved method/event name.
// The codec is the stateless abi provider (a single zero value serves every request).
type abiSource struct {
	abi  *gethabi.ABI
	name string // the method/event name --sig carried ("" when the caller named it)
}

// resolveABISource enforces the §2.5 precedence and returns the parsed ABI + the name
// the ABI carries (when --sig supplied one). EXACTLY ONE source must resolve; a
// disagreement (a registered alias AND an explicit --abi/--sig) is usage.* (exit 2).
//
//  1. contractRef is a registered alias → use the STORED ABI (the alias's address is
//     the destination; the stored ABI cannot change the address — registry-only).
//  2. else src.ABIJSON (--abi/--abi-stdin) → abi.ParseJSON.
//  3. else src.Sig (--sig) → abi.ParseSig (also yields the method/event name).
//
// The contract ADDRESS is resolved separately by resolveContractDest (the SAME
// resolveDest as any --to), so a stored-ABI lie can never move the destination.
func (s *Service) resolveABISource(ctx context.Context, network, contractRef string, src domain.ABISource) (abiSource, error) {
	explicit := strings.TrimSpace(src.ABIJSON) != "" || strings.TrimSpace(src.Sig) != ""

	// 1. A registered alias's stored ABI wins. (A raw 0x / ENS contractRef is never a
	//    registry alias — Resolve returns found=false on a non-grammar name.)
	if reg, found, err := s.contracts.Resolve(ctx, network, contractRef); err != nil {
		return abiSource{}, err
	} else if found {
		if explicit {
			return abiSource{}, domain.Newf(domain.CodeUsage+".ambiguous_abi",
				"%q is a registered contract alias; do not also pass --abi/--sig (the stored ABI is authoritative)", contractRef)
		}
		parsed, perr := dabi.Codec{}.ParseJSON(reg.ABI)
		if perr != nil {
			return abiSource{}, perr
		}
		return abiSource{abi: parsed}, nil
	}

	// 2. --abi / --abi-stdin JSON.
	if strings.TrimSpace(src.ABIJSON) != "" {
		if strings.TrimSpace(src.Sig) != "" {
			return abiSource{}, domain.New(domain.CodeUsage+".ambiguous_abi",
				"pass exactly one of --abi/--abi-stdin or --sig, not both")
		}
		parsed, perr := dabi.Codec{}.ParseJSON([]byte(src.ABIJSON))
		if perr != nil {
			return abiSource{}, perr
		}
		return abiSource{abi: parsed}, nil
	}

	// 3. inline --sig (carries the method/event name).
	if strings.TrimSpace(src.Sig) != "" {
		parsed, name, _, perr := dabi.Codec{}.ParseSig(src.Sig)
		if perr != nil {
			return abiSource{}, perr
		}
		return abiSource{abi: parsed, name: name}, nil
	}

	return abiSource{}, domain.New(domain.CodeUsage+".no_abi",
		"no ABI source: register the contract (`daxie contract add`), or pass --abi/--abi-stdin or --sig")
}

// methodName picks the function/event name: the explicit one the caller passed, else
// the name --sig carried. An empty result with a multi-method ABI is a usage error.
func methodName(explicit string, src abiSource) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit), nil
	}
	if src.name != "" {
		return src.name, nil
	}
	return "", domain.New(domain.CodeUsage+".no_method",
		"no method/event name: pass it positionally or via --sig \"name(types)\"")
}

// resolveContractDest resolves the contract reference to its destination address. An
// alias resolves REGISTRY-ONLY to its STORED address (the anti-spoofing wall — the
// stored ABI never changes the address); a raw 0x / ENS resolves via the SAME
// resolveDest any --to uses. This is the policy destination + the eth_call/getLogs
// target + the unknown-calldata allowlist subject.
func (s *Service) resolveContractDest(ctx context.Context, cr ChainRequest, network, contractRef string) (domain.Dest, error) {
	contractRef = strings.TrimSpace(contractRef)
	if contractRef == "" {
		return domain.Dest{}, domain.New(domain.CodeUsage+".no_contract",
			"a contract is required (a registered alias, a 0x address, or an ENS name)")
	}
	// A registered alias resolves to its STORED address (registry-only).
	if reg, found, err := s.contracts.Resolve(ctx, network, contractRef); err != nil {
		return domain.Dest{}, err
	} else if found {
		return domain.Dest{Address: reg.Address, Name: reg.Alias, Via: "contract"}, nil
	}
	// Else a raw 0x / ENS / contact (the same resolver as --to). resolveDest's
	// contact fallthrough is harmless here (a contact-named contract is legal).
	return s.resolveDest(ctx, cr, contractRef)
}

// addrResolverFor builds the address-typed-arg resolver abi.CoerceArgs calls: an
// address arg may be a raw 0x / ENS / contact / account ref, resolved through the SAME
// resolveDest + AddressOf the rest of daxie uses, and echoed before signing (§4 always-
// echo). It returns the abi-layer AddrProvenance so the codec can carry the provenance
// back for the caller to echo.
func (s *Service) addrResolverFor(ctx context.Context, cr ChainRequest) func(string) (common.Address, dabi.AddrProvenance, error) {
	return func(arg string) (common.Address, dabi.AddrProvenance, error) {
		arg = strings.TrimSpace(arg)
		// A keystore/standalone account ref or a raw 0x resolves through AddressOf.
		if ref, err := domain.ParseAccountRef(arg); err == nil && ref.Kind == domain.RefAddress {
			return ref.Addr, dabi.AddrProvenance{Input: arg, Addr: ref.Addr, Via: "literal"}, nil
		}
		dest, err := s.resolveDest(ctx, cr, arg)
		if err != nil {
			return common.Address{}, dabi.AddrProvenance{}, err
		}
		return dest.Address, dabi.AddrProvenance{Input: arg, Addr: dest.Address, Via: dest.Via, ENSName: dest.ENSName}, nil
	}
}

// ── contract registry CRUD (state class; §7.8) ────────────────────────────────

// ContractAdd registers an alias→{address, inline-ABI} on a network (`daxie contract
// add <alias> <0x> --abi`). The ABI is validated by abi.ParseJSON BEFORE store (invalid
// ⇒ usage.bad_abi, never stored). The address must be a raw 0x (the alias binds a
// concrete address — not an ENS that could re-point). A collision needs --name.
func (s *Service) ContractAdd(ctx context.Context, _ domain.Principal, req domain.ContractAddRequest) (domain.ContractRow, error) {
	network := s.networkName(req.Network)
	addr := strings.TrimSpace(req.Address)
	if !common.IsHexAddress(addr) {
		return domain.ContractRow{}, domain.Newf(domain.CodeUsage+".bad_address",
			"contract address %q is not a 0x address", req.Address)
	}
	abiJSON := []byte(req.ABIJSON)
	parsed, perr := dabi.Codec{}.ParseJSON(abiJSON)
	if perr != nil {
		return domain.ContractRow{}, perr // usage.bad_abi (exit 2) — never stored
	}
	// Store the ABI normalized (re-marshal the parsed form is lossy for non-standard
	// fields, so store the raw bytes verbatim — they round-trip through ParseJSON).
	ct := registry.Contract{
		Alias:   strings.TrimSpace(req.Alias),
		Address: common.HexToAddress(addr),
		ABI:     json.RawMessage(abiJSON),
	}
	if err := s.contracts.Add(ctx, network, ct); err != nil {
		return domain.ContractRow{}, err
	}
	row := contractRow(ct, network, parsed)
	return row, nil
}

// ContractList lists the registered contracts for a network, alias-sorted.
func (s *Service) ContractList(ctx context.Context, _ domain.Principal, req domain.ContractListRequest) (domain.ContractListResult, error) {
	network := s.networkName(req.Network)
	cts, err := s.contracts.List(ctx, network)
	if err != nil {
		return domain.ContractListResult{}, err
	}
	out := make([]domain.ContractRow, 0, len(cts))
	for _, ct := range cts {
		// A stored ABI is re-parsed defensively for the function/event counts; a parse
		// failure (shouldn't happen — validated at add) yields zero counts, never an error.
		parsed, _ := dabi.Codec{}.ParseJSON(ct.ABI)
		out = append(out, contractRow(ct, network, parsed))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return domain.ContractListResult{Network: network, Contracts: out}, nil
}

// ContractShow prints one contract's address + ABI summary (function/event signatures).
func (s *Service) ContractShow(ctx context.Context, _ domain.Principal, req domain.ContractShowRequest) (domain.ContractRow, error) {
	network := s.networkName(req.Network)
	reg, found, err := s.contracts.Resolve(ctx, network, req.Alias)
	if err != nil {
		return domain.ContractRow{}, err
	}
	if !found {
		return domain.ContractRow{}, domain.Newf(domain.CodeRefNotFound,
			"no contract aliased %q on %s (register it with `daxie contract add`)", req.Alias, network)
	}
	parsed, perr := dabi.Codec{}.ParseJSON(reg.ABI)
	if perr != nil {
		return domain.ContractRow{}, perr
	}
	row := contractRow(reg, network, parsed)
	row.Functions, row.Events = abiSignatures(parsed)
	return row, nil
}

// ContractRemove drops a registered contract alias (`daxie contract remove <alias>`).
func (s *Service) ContractRemove(ctx context.Context, _ domain.Principal, req domain.ContractRemoveRequest) (domain.ContractRemoveResult, error) {
	network := s.networkName(req.Network)
	if err := s.contracts.Remove(ctx, network, req.Alias); err != nil {
		return domain.ContractRemoveResult{}, err
	}
	return domain.ContractRemoveResult{Alias: strings.ToLower(strings.TrimSpace(req.Alias)), Network: network, Removed: true}, nil
}

// ── §5.11 PURE read/build paths (NEVER sign, NEVER policy) ────────────────────

// ContractCall is `daxie contract call`: a read-only eth_call (§5.11). resolve ABI →
// coerce args → chain.CallContract(msg{To, From, Data}, block) → abi.UnpackReturns →
// labeled DecodedValue[]. --from is an OPTIONAL msg.sender via Signer.Address (no
// unlock); --block nil=latest. `call` requires the method to declare outputs. NO policy,
// NO signing — no exit 3 is reachable.
func (s *Service) ContractCall(ctx context.Context, _ domain.Principal, req domain.ContractCallRequest) (domain.ContractCallResult, error) {
	network := s.networkName(req.Network)
	cr := ChainRequest{Network: req.Network, RPC: req.RPC}

	src, err := s.resolveABISource(ctx, network, req.Contract, req.ABI)
	if err != nil {
		return domain.ContractCallResult{}, err
	}
	method, err := methodName(req.Method, src)
	if err != nil {
		return domain.ContractCallResult{}, err
	}

	dest, err := s.resolveContractDest(ctx, cr, network, req.Contract)
	if err != nil {
		return domain.ContractCallResult{}, err
	}

	cc, err := s.chains.ClientFor(ctx, cr)
	if err != nil {
		return domain.ContractCallResult{}, err
	}
	defer cc.Close()

	args, _, err := dabi.Codec{}.CoerceArgs(src.abi, method, req.Args, s.addrResolverFor(ctx, cr))
	if err != nil {
		return domain.ContractCallResult{}, err
	}
	data, err := dabi.Codec{}.PackCall(src.abi, method, args)
	if err != nil {
		return domain.ContractCallResult{}, err
	}

	// --from is an OPTIONAL msg.sender — resolved read-only (no unlock). A 0x/ENS/ref
	// all resolve through the SAME path; ENS via resolveDest, a ref via AddressOf.
	var from common.Address
	if strings.TrimSpace(req.From) != "" {
		fa, ferr := s.resolveMsgSender(ctx, cr, req.From)
		if ferr != nil {
			return domain.ContractCallResult{}, ferr
		}
		from = fa
	}

	block, err := parseBlock(req.Block)
	if err != nil {
		return domain.ContractCallResult{}, err
	}

	to := dest.Address
	msg := ethereum.CallMsg{To: &to, Data: data}
	if from != (common.Address{}) {
		msg.From = from
	}
	out, err := cc.CallContract(ctx, msg, block)
	if err != nil {
		return domain.ContractCallResult{}, mapCallErr(err)
	}
	returns, err := dabi.Codec{}.UnpackReturns(src.abi, method, out)
	if err != nil {
		return domain.ContractCallResult{}, err
	}

	var blkOut *uint64
	if block != nil {
		b := block.Uint64()
		blkOut = &b
	}
	return domain.ContractCallResult{
		Contract: dest,
		Method:   method,
		Returns:  toDomainDecoded(returns),
		Block:    blkOut,
		Network:  network,
	}, nil
}

// ContractLogs is `daxie contract logs`: a read-only eth_getLogs (§5.11). resolve ABI →
// abi.PackEvent (Topics[0]=keccak(sig), indexed filters → Topics[i]; a non-indexed
// filter ⇒ usage.*) → chunk the range by the §5.8 1000-block splitter → chain.FilterLogs
// per chunk → abi.UnpackLog per log → DecodedLog[]. NO signing, NO policy.
func (s *Service) ContractLogs(ctx context.Context, _ domain.Principal, req domain.ContractLogsRequest) (domain.ContractLogsResult, error) {
	network := s.networkName(req.Network)
	cr := ChainRequest{Network: req.Network, RPC: req.RPC}

	src, err := s.resolveABISource(ctx, network, req.Contract, req.ABI)
	if err != nil {
		return domain.ContractLogsResult{}, err
	}
	event, err := methodName(req.Event, src)
	if err != nil {
		return domain.ContractLogsResult{}, err
	}

	dest, err := s.resolveContractDest(ctx, cr, network, req.Contract)
	if err != nil {
		return domain.ContractLogsResult{}, err
	}

	cc, err := s.chains.ClientFor(ctx, cr)
	if err != nil {
		return domain.ContractLogsResult{}, err
	}
	defer cc.Close()

	// Build the indexed-arg filter map: an address-typed filter value is ref/ENS-
	// resolved here (the SAME resolver), then PackEvent positions it into Topics[i].
	filters, err := s.buildLogFilters(ctx, cr, req.Args)
	if err != nil {
		return domain.ContractLogsResult{}, err
	}
	topics, _, err := dabi.Codec{}.PackEvent(src.abi, event, filters)
	if err != nil {
		return domain.ContractLogsResult{}, err
	}

	fromBlk, toBlk, err := s.resolveLogRange(ctx, cc, req.FromBlock, req.ToBlock)
	if err != nil {
		return domain.ContractLogsResult{}, err
	}
	// Cap the TOTAL span so one tool call can't fan out into tens of thousands of
	// eth_getLogs round-trips (e.g. a from_block:0..head query) — a DoS against the
	// operator's RPC reachable from the narrowed agent surface. The chunk splitter
	// (maxLogRange) bounds each request; this bounds their count. The caller pages
	// through a wider history with explicit ranges.
	if toBlk-fromBlk+1 > maxLogSpan {
		return domain.ContractLogsResult{}, domain.Newf(domain.CodeUsage+".log_range_too_wide",
			"block span %d exceeds the %d-block limit for one query; narrow --from-block/--to-block (or page through the range)",
			toBlk-fromBlk+1, maxLogSpan)
	}

	to := dest.Address
	var logs []domain.DecodedLog
	span := s.maxLogRange()
	for start := fromBlk; start <= toBlk; start += span {
		end := start + span - 1
		if end > toBlk {
			end = toBlk
		}
		q := ethereum.FilterQuery{
			Addresses: []common.Address{to},
			Topics:    topics,
			FromBlock: new(big.Int).SetUint64(start),
			ToBlock:   new(big.Int).SetUint64(end),
		}
		raw, ferr := cc.FilterLogs(ctx, q)
		if ferr != nil {
			return domain.ContractLogsResult{}, mapRPCErr(ferr)
		}
		for _, lg := range raw {
			decoded, derr := dabi.Codec{}.UnpackLog(src.abi, event, lg.Topics, lg.Data)
			if derr != nil {
				return domain.ContractLogsResult{}, derr
			}
			logs = append(logs, domain.DecodedLog{
				TxHash:    lg.TxHash.Hex(),
				LogIndex:  lg.Index,
				Block:     lg.BlockNumber,
				BlockHash: lg.BlockHash.Hex(),
				Event:     event,
				Args:      toDomainDecoded(decoded),
			})
		}
		if span == 0 { // guard against a zero span (no splitter configured)
			break
		}
	}
	return domain.ContractLogsResult{Contract: dest, Event: event, Logs: logs, Network: network}, nil
}

// EncodeCalldata is `daxie contract encode`: PURE — no chain, no signing, NO policy
// (§5.11, §11 D12). resolve ABI → coerce args → abi.PackCall → 0x. Classifying a hex
// string encode merely emits would gate nothing — encode carries no policy.
func (s *Service) EncodeCalldata(ctx context.Context, _ domain.Principal, req domain.EncodeRequest) (domain.EncodeResult, error) {
	network := s.networkName(req.Network)
	cr := ChainRequest{Network: req.Network}
	// The contract ref for encode is only used to resolve a registered alias's ABI; the
	// frontend passes the alias via req.ABI.Alias.
	src, err := s.resolveABISource(ctx, network, req.ABI.Alias, req.ABI)
	if err != nil {
		return domain.EncodeResult{}, err
	}
	method, err := methodName(req.Method, src)
	if err != nil {
		return domain.EncodeResult{}, err
	}
	args, _, err := dabi.Codec{}.CoerceArgs(src.abi, method, req.Args, s.addrResolverFor(ctx, cr))
	if err != nil {
		return domain.EncodeResult{}, err
	}
	data, err := dabi.Codec{}.PackCall(src.abi, method, args)
	if err != nil {
		return domain.EncodeResult{}, err
	}
	return domain.EncodeResult{Calldata: hexBytes(data)}, nil
}

// DecodeCalldata is `daxie contract decode`: PURE — no chain, no signing, NO policy
// (§5.11, §11 D12). resolve ABI → abi.UnpackCalldata → method + selector + labeled args.
func (s *Service) DecodeCalldata(ctx context.Context, _ domain.Principal, req domain.DecodeRequest) (domain.DecodeResult, error) {
	network := s.networkName(req.Network)
	src, err := s.resolveABISource(ctx, network, req.ABI.Alias, req.ABI)
	if err != nil {
		return domain.DecodeResult{}, err
	}
	calldata, err := parseHexBytes(req.Calldata)
	if err != nil {
		return domain.DecodeResult{}, err
	}
	method, selector, args, err := dabi.Codec{}.UnpackCalldata(src.abi, calldata)
	if err != nil {
		return domain.DecodeResult{}, err
	}
	return domain.DecodeResult{Method: method, Selector: selector, Args: toDomainDecoded(args)}, nil
}

// ── §5.1 contract send (SIGNS; through the authorize kernel) ──────────────────

// ContractSend is `daxie contract send`: the broadest-reach signing path (§5.1). It
// resolves the ABI, coerces args (address args resolved+ECHOED before signing),
// abi.PackCall → the Intent data, Contract → the Intent To (the policy destination,
// resolved+echoed via EvResolved), --value → native value (folds into SpendWei), and
// hands the Intent to the EXISTING runSend kernel. ClassifyCalldata runs at stage 2
// inside authorize (tx.go). gas/wait/RBF are identical to tx send; the 21000-EOA gas
// exception does NOT apply.
func (s *Service) ContractSend(ctx context.Context, p domain.Principal, req domain.ContractSendRequest, sink domain.EventSink) (domain.TxResult, error) {
	in, err := s.resolveContractSendIntent(ctx, p, req, sink)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer in.cc.Close()

	if err := s.previewGas(ctx, &in, gasReqFromContractSend(req), sink); err != nil {
		return domain.TxResult{}, err
	}
	if req.DryRun {
		return s.dryRun(ctx, &in)
	}
	unlocker, zero, err := s.withUnlocker(false)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer zero()
	in.unlocker = unlocker
	return s.runSend(ctx, p, &in, req.Wait, sink)
}

// resolveContractSendIntent builds the prefetch-stage Intent for a contract send
// (§2.7): resolve From (the signing ref), the contract destination (the policy subject,
// resolved+echoed), the ABI (precedence), coerce args, abi.PackCall → data, --value →
// native value. It marks the Intent isContractSend so authorize/dryRun run
// ClassifyCalldata at stage 2 (tx.go classifyContractSend).
func (s *Service) resolveContractSendIntent(ctx context.Context, p domain.Principal, req domain.ContractSendRequest, sink domain.EventSink) (Intent, error) {
	cr := ChainRequest{Network: req.Network, RPC: req.RPC}

	// ── From: the signing ref (flag>env>meta.json default) ──
	fromStr := req.From
	if fromStr == "" {
		fromStr = s.activeDefault(ctx)
	}
	if fromStr == "" {
		return Intent{}, domain.New(domain.CodeUsage+".no_account",
			"no --from given and no default account set (run `daxie account use`)")
	}
	fromRef, err := domain.ParseAccountRef(fromStr)
	if err != nil {
		return Intent{}, err
	}
	from, err := s.keys.AddressOf(fromRef)
	if err != nil {
		return Intent{}, err
	}

	network := s.networkName(req.Network)

	// ── ABI + the contract destination (REGISTRY-ONLY alias resolution) ──
	src, err := s.resolveABISource(ctx, network, req.Contract, req.ABI)
	if err != nil {
		return Intent{}, err
	}
	method, err := methodName(req.Method, src)
	if err != nil {
		return Intent{}, err
	}
	dest, err := s.resolveContractDest(ctx, cr, network, req.Contract)
	if err != nil {
		return Intent{}, err
	}
	emitResolvedDest(sink, "contract ", dest)

	// ── coerce args (address args resolved + ECHOED before signing, §4 always-echo) ──
	args, prov, err := dabi.Codec{}.CoerceArgs(src.abi, method, req.Args, s.addrResolverFor(ctx, cr))
	if err != nil {
		return Intent{}, err
	}
	for _, pv := range prov {
		if pv.Addr != (common.Address{}) {
			emitResolvedDest(sink, "arg "+pv.Input+" ", domain.Dest{Address: pv.Addr, Name: pv.ENSName, Via: pv.Via, ENSName: pv.ENSName})
		}
	}
	data, err := dabi.Codec{}.PackCall(src.abi, method, args)
	if err != nil {
		return Intent{}, err
	}

	// ── --value → native value (folds into SpendWei for EVERY contract send) ──
	value, err := parseEthAmount(req.Value)
	if err != nil {
		return Intent{}, err
	}

	// ── dial + chain id ──
	cc, err := s.chains.ClientFor(ctx, cr)
	if err != nil {
		return Intent{}, err
	}
	chainID, cerr := cc.ChainID(ctx)
	if cerr != nil {
		cc.Close()
		return Intent{}, mapRPCErr(cerr)
	}

	return Intent{
		chainID: chainID,
		network: network,
		rpc:     req.RPC,
		cc:      cc,
		from:    from,
		ref:     fromRef,
		// dest is the CONTRACT (the policy destination, resolved+echoed) — the tx To.
		dest:  dest,
		to:    dest.Address,
		value: value,
		data:  data,
		// acked carries the DELIBERATE --unlimited acknowledgement (req.AckUnlimited), NOT
		// the bare --yes (req.Confirm only skips the TTY confirmation). A recognized
		// unlimited approval encoded as raw calldata therefore fires the IDENTICAL ack
		// ceremony the typed `token approve --unlimited --yes` path does — an agent doing a
		// plain `contract send --yes` carrying approve(spender, MAX) is denied
		// unlimited_unacked (exit 3) unless it ALSO passes --unlimited (§4.2 line 1561,
		// §11 D12: the generic noun must not silently defeat the typed ceremony).
		// classifyContractSend leaves Check.Acked = in.acked untouched, so the engine's
		// stage-6 unlimited gate reads it.
		acked:          req.AckUnlimited,
		kind:           journal.KindContractCall,
		asset:          journal.Asset{Kind: "contract", Amount: strPtr(value.String())},
		nonce:          req.Nonce,
		source:         sourceOf(p),
		isContractSend: true,
	}, nil
}

// gasReqFromContractSend projects a ContractSendRequest's gas/network/endpoint fields
// into the TxRequest shape previewGas/buildGas consume.
func gasReqFromContractSend(req domain.ContractSendRequest) domain.TxRequest {
	r := domain.TxRequest{
		Network:     req.Network,
		RPC:         req.RPC,
		GasLimit:    req.GasLimit,
		MaxFee:      req.MaxFee,
		PriorityFee: req.PriorityFee,
		GasPrice:    req.GasPrice,
		Speed:       req.Speed,
		Legacy:      req.Legacy,
	}
	return r
}

// ── helpers ───────────────────────────────────────────────────────────────────

// resolveMsgSender resolves the OPTIONAL --from msg.sender for a read (eth_call): a 0x
// literal / a keystore-or-standalone ref (AddressOf) / an ENS name (resolveDest). No
// unlock — it is a read.
func (s *Service) resolveMsgSender(ctx context.Context, cr ChainRequest, from string) (common.Address, error) {
	ref, err := domain.ParseAccountRef(from)
	if err == nil && ref.Kind == domain.RefAddress {
		return ref.Addr, nil
	}
	if err == nil && (ref.Kind == domain.RefHDIndex || ref.Kind == domain.RefHDAlias || ref.Kind == domain.RefNamed) {
		return s.keys.AddressOf(ref)
	}
	// ENS / contact: resolveDest.
	dest, derr := s.resolveDest(ctx, cr, from)
	if derr != nil {
		return common.Address{}, derr
	}
	return dest.Address, nil
}

// buildLogFilters maps the request's indexed-arg filters into the abi.PackEvent map:
// the key is the arg name, the value is the coerced literal (an address value is
// ref/ENS-resolved here). PackEvent rejects a filter on a NON-indexed arg.
func (s *Service) buildLogFilters(ctx context.Context, cr ChainRequest, args []domain.LogFilter) (map[string]any, error) {
	if len(args) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(args))
	for _, f := range args {
		v := strings.TrimSpace(f.Value)
		// A raw 0x address must be packed as a common.Address (MakeTopics left-pads it to
		// the 32-byte indexed-address topic); a bare hex string would not pack.
		if common.IsHexAddress(v) {
			out[f.Name] = common.HexToAddress(v)
			continue
		}
		// An ENS name resolves through the same resolver to its address.
		if ref, err := domain.ParseAccountRef(v); err == nil && ref.Kind == domain.RefENS {
			dest, derr := s.resolveDest(ctx, cr, v)
			if derr != nil {
				return nil, derr
			}
			out[f.Name] = dest.Address
			continue
		}
		// A numeric value (indexed uintN) is packed as a *big.Int; everything else is
		// handed verbatim and PackEvent's MakeTopics coerces it to the topic word.
		if n, ok := new(big.Int).SetString(v, 10); ok {
			out[f.Name] = n
			continue
		}
		out[f.Name] = v
	}
	return out, nil
}

// resolveLogRange resolves the from/to block range: empty FromBlock → 0; empty ToBlock
// → the chain head (BlockNumber). A bad number is usage.*.
func (s *Service) resolveLogRange(ctx context.Context, cc chain.Client, fromStr, toStr string) (uint64, uint64, error) {
	var from uint64
	if strings.TrimSpace(fromStr) != "" {
		b, err := parseBlock(fromStr)
		if err != nil {
			return 0, 0, err
		}
		if b != nil {
			from = b.Uint64()
		}
	}
	var to uint64
	if strings.TrimSpace(toStr) == "" {
		head, err := cc.BlockNumber(ctx)
		if err != nil {
			return 0, 0, mapRPCErr(err)
		}
		to = head
	} else {
		b, err := parseBlock(toStr)
		if err != nil {
			return 0, 0, err
		}
		if b != nil {
			to = b.Uint64()
		}
	}
	if to < from {
		return 0, 0, domain.Newf(domain.CodeUsage+".bad_block_range",
			"--to-block %d is before --from-block %d", to, from)
	}
	return from, to, nil
}

// maxLogSpan caps the total block range a single `contract logs` query may cover.
// At the default 1000-block chunk this bounds one call to ~100 eth_getLogs requests,
// killing the from_block:0..head fan-out while still allowing a generous window
// (~2 weeks on mainnet; callers page for more).
const maxLogSpan uint64 = 100_000

// maxLogRange returns the §5.8 receive.max-log-range block-chunk span (default 1000).
// It reuses the existing receive config key — no new config key for contract logs.
func (s *Service) maxLogRange() uint64 {
	if n := s.cfg.Receive.MaxLogRange; n > 0 {
		return uint64(n)
	}
	return 1000
}

// parseBlock parses a --block / --from-block / --to-block value. Empty ⇒ nil (latest);
// a decimal or 0x-hex number ⇒ that block; the safe/finalized tags are reserved (not
// v1) and rejected as usage.*.
func parseBlock(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "latest" {
		return nil, nil
	}
	switch s {
	case "safe", "finalized", "pending", "earliest":
		return nil, domain.Newf(domain.CodeUsage+".bad_block",
			"block tag %q is not supported in v1 (use a number, or omit for latest)", s)
	}
	var (
		n  *big.Int
		ok bool
	)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, ok = new(big.Int).SetString(s[2:], 16)
	} else {
		n, ok = new(big.Int).SetString(s, 10)
	}
	if !ok || n.Sign() < 0 {
		return nil, domain.Newf(domain.CodeUsage+".bad_block", "invalid block %q (want a non-negative number)", s)
	}
	return n, nil
}

// parseHexBytes parses 0x… calldata into bytes. A missing 0x prefix or odd length is
// usage.bad_calldata (exit 2).
func parseHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil, domain.Newf(domain.CodeUsage+".bad_calldata", "calldata %q must be 0x-prefixed hex", s)
	}
	h := s[2:]
	if len(h)%2 != 0 {
		return nil, domain.New(domain.CodeUsage+".bad_calldata", "calldata has an odd number of hex digits")
	}
	out := make([]byte, len(h)/2)
	for i := 0; i < len(out); i++ {
		hi, lo := hexNibble(h[i*2]), hexNibble(h[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, domain.Newf(domain.CodeUsage+".bad_calldata", "calldata %q contains a non-hex digit", s)
		}
		// hi/lo are each a 0..15 nibble (guarded above), so the packed byte is 0..255 —
		// the &0xff keeps gosec's int→byte overflow check satisfied without changing the value.
		out[i] = byte((hi<<4 | lo) & 0xff)
	}
	return out, nil
}

// hexNibble maps one hex digit to its value, or -1 for a non-hex byte.
func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// mapCallErr maps an eth_call error to the §5.11 taxonomy: a revert → tx.reverted
// (exit 7, the decoded reason rides the message); anything else → rpc.unreachable.
func mapCallErr(err error) error {
	msg := lowerErr(err)
	if containsAny(msg, "revert", "execution reverted") {
		return domain.Wrap(domain.CodeTxReverted, "eth_call reverted: "+err.Error(), err)
	}
	return mapRPCErr(err)
}

// toDomainDecoded maps the abi-layer DecodedValue slice (an anonymous-struct alias)
// onto the named domain.DecodedValue wire type field-for-field. They are byte-identical
// (the abi alias exists to keep abi free of a dep on the domain wire-result struct), so
// this is a pure 1:1 relabel — no value reinterpretation.
func toDomainDecoded(in []dabi.DecodedValue) []domain.DecodedValue {
	if in == nil {
		return nil
	}
	out := make([]domain.DecodedValue, len(in))
	for i, v := range in {
		out[i] = domain.DecodedValue{Name: v.Name, Type: v.Type, Value: v.Value}
	}
	return out
}

// contractRow projects a registry Contract + its parsed ABI into the wire ContractRow
// (the function/event COUNTS for list; the names are filled by show via abiSignatures).
func contractRow(ct registry.Contract, network string, parsed *gethabi.ABI) domain.ContractRow {
	row := domain.ContractRow{
		Alias:   ct.Alias,
		Address: ct.Address.Hex(),
		Network: network,
	}
	if parsed != nil {
		row.FuncCount = len(parsed.Methods)
		row.EvtCount = len(parsed.Events)
	}
	return row
}

// abiSignatures returns the sorted function + event signatures of an ABI (the `show`
// summary). Each is the canonical "name(types)" form (gethabi Sig).
func abiSignatures(parsed *gethabi.ABI) (funcs, events []string) {
	if parsed == nil {
		return nil, nil
	}
	for _, m := range parsed.Methods {
		funcs = append(funcs, m.Sig)
	}
	for _, e := range parsed.Events {
		events = append(events, e.Sig)
	}
	sort.Strings(funcs)
	sort.Strings(events)
	return funcs, events
}
