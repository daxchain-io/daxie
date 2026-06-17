package service

import (
	"context"
	"errors"
	"math/big"
	"strings"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/erc"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/registry"
	"github.com/ethereum/go-ethereum/common"
)

// nft.go is the M6 NFT (ERC-721 + ERC-1155) use-case layer (design §2.8, §4.2/§4.3,
// §5.1, §7.8, cli-spec §`daxie nft`). It holds:
//
//   - the registry CRUD use cases (NFTAdd/NFTAlias/NFTAliases) over the §7.8
//     per-network collections[]/nft_aliases[] store;
//   - resolveNFT — the ONE chokepoint that turns a `--nft` reference (an
//     individual-NFT alias | <collection>#<tokenId> with the collection an alias or
//     a raw 0x) into a concrete {collection addr, kind, token_id}. Alias forms
//     resolve REGISTRY-ONLY (a miss is ref.not_found — never an on-chain name()
//     lookup; the anti-spoofing wall, identical to tokens). A raw 0x collection is
//     always allowed; its kind is read once via ERC-165 ONLY when it is not a
//     registered collection (display/standard selection, never alias resolution);
//   - SendNFT — the §5.1 transfer that routes an erc-built safeTransferFrom through
//     the EXACT §2.7 authorize→broadcast→settle/abort kernel (runSend), as a
//     KindTransfer. The policy destination is the RECIPIENT (--to), NEVER the
//     collection contract (§4.2/§4.3); the §4.3 fail-closed-no-allowlist rule
//     applies (ETH exempt, NFT NOT — wired via Intent.isTokenOp recognizing the NFT
//     kinds in tx.go);
//   - NFTShow/NFTList — the read-only ownership/metadata reads (721 ownerOf, 1155
//     balanceOf(id)); no IPFS/tokenURI fetch in v1.
//
// token_id is a DECIMAL STRING end to end (IDs exceed 2^53) and only ever parsed
// to *big.Int via math/big for the calldata — never an int64/float (§7.8).

// resolvedNFT is the network-confirmed NFT a send/show consumes: the resolveNFT
// output (registry resolution + the on-chain kind for an unregistered raw
// collection). It mirrors resolvedAsset's role for the token paths.
type resolvedNFT struct {
	collection      common.Address // the collection contract (the tx `To`; NEVER the policy dest)
	kind            string         // "erc721" | "erc1155"
	tokenID         string         // DECIMAL STRING (never int64/float)
	collectionAlias string         // the registry alias when it came from one ("" for a raw 0x)
	nftAlias        string         // the individual-NFT alias when the ref was one
}

// resolveNFT is the ONE NFT chokepoint (§5.1): it turns a `--nft` reference into a
// resolved {collection, kind, token_id} on a network. The registry resolves the
// alias forms (registry-only — a miss is ref.not_found, never an on-chain name()
// lookup). When the reference was a RAW 0x collection NOT in the registry, the
// stored kind is empty, so service detects it ONCE via ERC-165 (display/standard
// selection only — NEVER alias resolution); a non-NFT address is ErrNotNFT (exit 2).
// A registered collection (alias or a raw 0x that matches one) uses its STORED kind
// with no chain read.
func (s *Service) resolveNFT(ctx context.Context, cc chain.Client, network, ref string) (resolvedNFT, error) {
	rn, err := s.nfts.ResolveNFT(ctx, network, ref)
	if err != nil {
		return resolvedNFT{}, err
	}
	out := resolvedNFT{
		collection:      rn.Collection,
		kind:            rn.Kind,
		tokenID:         rn.TokenID,
		collectionAlias: rn.CollectionAlias,
		nftAlias:        rn.NFTAlias,
	}
	if out.kind == "" {
		// A raw 0x collection that is not registered: detect the standard ONCE via
		// ERC-165 (display/standard only). DetectKind propagates a transport error
		// (retryable) and returns ErrNotNFT (exit 2) for a non-NFT address.
		if cc == nil {
			return resolvedNFT{}, domain.New(domain.CodeRPCUnreachable,
				"a chain endpoint is required to detect the standard of an unregistered collection")
		}
		kind, derr := s.detectKind(ctx, cc, out.collection)
		if derr != nil {
			return resolvedNFT{}, derr
		}
		out.kind = kind
	}
	return out, nil
}

// detectKind wraps erc.DetectKind with the ERC-165-specific revert→not-NFT mapping
// (see notNFTOrTransport): a contract that REVERTS the supportsInterface eth_call
// (a plain ERC-20, an EOA's empty code, a non-165 contract) is "not an NFT" (exit 2,
// usage.not_nft), NOT an unreachable endpoint (exit 6). A genuine transport failure
// stays retryable. This is the §10.1 detection check's correctness boundary: the
// non-negotiable is that a non-NFT address is rejected as not_nft, and a real node
// surfaces the revert as an eth_call error (the chain layer cannot tell a revert
// from a transport failure, so the NFT-detection caller — where a revert
// unambiguously means "not an NFT" — applies the mapping).
func (s *Service) detectKind(ctx context.Context, cc chain.Client, contract common.Address) (string, error) {
	kind, err := s.erc.DetectKind(ctx, cc, contract)
	if err != nil {
		return "", notNFTOrTransport(err)
	}
	return kind, nil
}

// notNFTOrTransport classifies a DetectKind error: a reverted supportsInterface
// eth_call (the call failed ON-CHAIN — the contract does not implement ERC-165) is
// erc.ErrNotNFT (exit 2, usage.not_nft); anything else is a genuine transport
// failure passed through mapRPCErr (retryable). erc.ErrNotNFT itself (the clean
// "neither 721 nor 1155" verdict from DetectKind) passes through unchanged.
//
// The discriminator is the on-chain "execution reverted" signal the node returns
// for a call to a contract that does not implement the queried selector. This is
// the ONE place daxie reads that signal, and only at NFT detection, where a revert
// is unambiguous; it never leaks into the general rpc.* taxonomy.
func notNFTOrTransport(err error) error {
	if errors.Is(err, erc.ErrNotNFT) {
		return err // the clean not-an-NFT verdict
	}
	if isExecutionReverted(err) {
		return erc.ErrNotNFT
	}
	return mapRPCErr(err)
}

// isExecutionReverted reports whether err carries an on-chain "execution reverted"
// signal (an eth_call that the contract reverted — i.e. it does not implement the
// queried function). It checks the wrapped cause's text since the chain adapter
// flattens an eth_call revert into the rpc.unreachable wrapper; this is read ONLY at
// NFT detection (notNFTOrTransport), never as a general taxonomy decision.
func isExecutionReverted(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "execution reverted")
}

// ── registry use cases: add / alias / aliases ─────────────────────────────────

// NFTAdd registers a collection alias→contract on a network (`daxie nft add <0x>
// [--name]`). The contract MUST be a raw 0x address; the kind (erc721|erc1155) is
// DETECTED on-chain via ERC-165 at add (the §10.1 detection check) and STORED. The
// alias defaults to the case-folded on-chain name() when --name is empty (a display
// read via erc.Name — the registry never touches the chain to resolve; an NFT
// with no readable name must be named with --name). A non-NFT address is rejected
// (ErrNotNFT, exit 2 — daxie refuses to register a non-NFT).
func (s *Service) NFTAdd(ctx context.Context, _ domain.Principal, req domain.NFTAddRequest) (domain.NFTCollectionResult, error) {
	network := s.networkName(req.Network)
	if !common.IsHexAddress(strings.TrimSpace(req.Contract)) {
		return domain.NFTCollectionResult{}, domain.Newf(domain.CodeUsage+".bad_address",
			"collection contract %q is not a 0x address", req.Contract)
	}
	contract := common.HexToAddress(strings.TrimSpace(req.Contract))

	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.NFTCollectionResult{}, err
	}
	defer cc.Close()

	// ERC-165 detection (REAL, at add): 721 vs 1155 is decided here and STORED. A
	// non-NFT (EOA / ERC-20 / non-165) → ErrNotNFT (exit 2, usage.not_nft), whether
	// the node reports "neither interface" or REVERTS the supportsInterface call. A
	// genuine transport error stays retryable (detectKind separates the two).
	kind, err := s.detectKind(ctx, cc, contract)
	if err != nil {
		return domain.NFTCollectionResult{}, err
	}

	// Display name (for the echo) + the alias default: the on-chain name(), read for
	// DISPLAY only (resolution never matches on it — the anti-spoofing wall). A
	// failure leaves it empty.
	name, _ := s.erc.Name(ctx, cc, contract)

	alias := strings.TrimSpace(req.Name)
	if alias == "" {
		// Default the alias to the case-folded on-chain name(). If the name cannot
		// fold to a valid §3.1 alias, the registry AddCollection rejects it
		// (usage.bad_name); an empty name here requires an explicit --name.
		alias = strings.ToLower(name)
		if alias == "" {
			return domain.NFTCollectionResult{}, domain.New(domain.CodeUsage+".no_name",
				"the collection has no readable name; give it an alias with --name")
		}
	}

	col := registry.Collection{
		Alias:   alias,
		Address: contract,
		Kind:    kind, // erc.Kind721/Kind1155 == registry.KindERC721/KindERC1155 by value
	}
	if err := s.nfts.AddCollection(ctx, network, col); err != nil {
		return domain.NFTCollectionResult{}, err
	}
	return domain.NFTCollectionResult{Collection: domain.NFTCollectionRow{
		Alias:    col.Alias,
		Contract: contract.Hex(),
		Kind:     kind,
		Network:  network,
		Name:     name,
	}}, nil
}

// NFTAlias registers an individual-NFT alias (`daxie nft alias <collection#tokenId>
// <alias>`). The collection part of the reference MUST be a REGISTERED collection
// alias (the nft alias binds to a known contract registry-only; a raw 0x collection
// cannot be aliased without first being added). token_id is stored as a decimal
// string (§7.8). No chain read — a pure registry mutation.
func (s *Service) NFTAlias(ctx context.Context, _ domain.Principal, req domain.NFTAliasRequest) (domain.NFTAliasResult, error) {
	network := s.networkName(req.Network)

	// The reference must be a <collection>#<tokenId> form; a bare alias cannot be
	// re-aliased. ParseNFTRef does the syntactic split (token_id stays a string).
	ref, err := domain.ParseNFTRef(req.Ref)
	if err != nil {
		return domain.NFTAliasResult{}, err
	}
	if ref.IsAlias() {
		return domain.NFTAliasResult{}, domain.Newf(domain.CodeUsage+".bad_nft_ref",
			"%q is an NFT alias, not a <collection>#<tokenId> reference to alias", req.Ref)
	}
	// The collection must be a REGISTERED collection alias (an nft alias binds to a
	// known contract registry-only). A raw 0x collection is refused with a clear
	// instruction to `nft add` it first.
	if common.IsHexAddress(ref.Collection) {
		return domain.NFTAliasResult{}, domain.Newf(domain.CodeUsage+".bad_nft_ref",
			"alias the collection first (`daxie nft add %s --name <alias>`), then alias the NFT by <alias>#%s", ref.Collection, ref.TokenID)
	}

	if err := s.nfts.AliasNFT(ctx, network, req.Alias, ref.Collection, ref.TokenID); err != nil {
		return domain.NFTAliasResult{}, err
	}
	// Echo the stored row (resolve the canonical decimal token id + the canonical
	// collection alias via the registry).
	rn, rerr := s.nfts.ResolveNFT(ctx, network, strings.TrimSpace(req.Alias))
	if rerr != nil {
		// The alias write succeeded; an echo-resolution failure is non-fatal.
		return domain.NFTAliasResult{Alias: domain.NFTAliasRow{
			Alias: strings.ToLower(strings.TrimSpace(req.Alias)), Collection: strings.ToLower(ref.Collection),
			TokenID: ref.TokenID, Network: network,
		}}, nil
	}
	return domain.NFTAliasResult{Alias: domain.NFTAliasRow{
		Alias:      rn.NFTAlias,
		Collection: rn.CollectionAlias,
		TokenID:    rn.TokenID,
		Network:    network,
	}}, nil
}

// NFTAliases lists the individual-NFT aliases on a network (`daxie nft aliases`),
// alias-sorted. Pure registry read.
func (s *Service) NFTAliases(ctx context.Context, _ domain.Principal, req domain.NFTAliasesRequest) (domain.NFTAliasesResult, error) {
	network := s.networkName(req.Network)
	rows, err := s.nfts.ListNFTAliases(ctx, network)
	if err != nil {
		return domain.NFTAliasesResult{}, err
	}
	out := make([]domain.NFTAliasRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, domain.NFTAliasRow{
			Alias: r.Alias, Collection: r.Collection, TokenID: r.TokenID, Network: network,
		})
	}
	return domain.NFTAliasesResult{Network: network, Aliases: out}, nil
}

// ── reads: show / list (read-only; no signing, no policy) ─────────────────────

// NFTShow reads ownership/metadata for one NFT (`daxie nft show <ref>` or
// `--contract 0x --token-id N`). 721 reports ownerOf; 1155 reports
// balanceOf(account, id) when an account is given (else just the kind + id). It is
// a pure read — no signing, no policy. No IPFS/tokenURI fetch in v1 (a nice-to-have
// staged later, per the milestone scope).
func (s *Service) NFTShow(ctx context.Context, _ domain.Principal, req domain.NFTShowRequest, emit domain.EventSink) (domain.NFTShowResult, error) {
	network := s.networkName(req.Network)
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.NFTShowResult{}, err
	}
	defer cc.Close()

	ref := nftRefForShow(req)
	rn, err := s.resolveNFT(ctx, cc, network, ref)
	if err != nil {
		return domain.NFTShowResult{}, err
	}

	res := domain.NFTShowResult{
		Network:    network,
		Collection: rn.collection.Hex(),
		Alias:      rn.collectionAlias,
		NFTAlias:   rn.nftAlias,
		Kind:       rn.kind,
		TokenID:    rn.tokenID,
	}

	tokenID, ok := new(big.Int).SetString(rn.tokenID, 10)
	if !ok {
		return domain.NFTShowResult{}, domain.Newf(domain.CodeUsage+".bad_token_id",
			"token id %q is not a non-negative decimal integer", rn.tokenID)
	}

	emitResolved(emit, rn.collection.Hex(), "nft "+rn.collection.Hex()+"#"+rn.tokenID)

	switch rn.kind {
	case registry.KindERC721:
		owner, oerr := s.erc.OwnerOf(ctx, cc, rn.collection, tokenID)
		if oerr != nil {
			return domain.NFTShowResult{}, mapRPCErr(oerr)
		}
		res.Owner = owner.Hex()
		if acct, aerr := s.showAccount(ctx, req.Account); aerr == nil && acct != (common.Address{}) {
			res.Account = acct.Hex()
			res.OwnedByYou = acct == owner
		}
	case registry.KindERC1155:
		// 1155 has no ownerOf; report balanceOf(account, id) when an account is
		// available (the request account, else the default account). Without one, the
		// show reports kind + id only.
		acct, aerr := s.showAccount(ctx, req.Account)
		if aerr == nil && acct != (common.Address{}) {
			bal, berr := s.erc.BalanceOf1155(ctx, cc, rn.collection, acct, tokenID)
			if berr != nil {
				return domain.NFTShowResult{}, mapRPCErr(berr)
			}
			res.Account = acct.Hex()
			res.Balance = bal.String()
			res.OwnedByYou = bal.Sign() > 0
		}
	}
	return res, nil
}

// NFTList lists owned NFTs across REGISTERED collections (`daxie nft list
// [--account]`). v1 enumerates the registry collections + the account's
// individual-NFT aliases and reports ownership per the §10.3 discovery note (no
// on-chain enumeration of arbitrary holdings — an indexer is the future seam). For
// each individual-NFT alias whose collection is registered, it reads ownership
// (721 ownerOf == account / 1155 balanceOf > 0) and includes the ones the account
// actually holds.
func (s *Service) NFTList(ctx context.Context, _ domain.Principal, req domain.NFTListRequest, emit domain.EventSink) (domain.NFTListResult, error) {
	network := s.networkName(req.Network)

	acct, err := s.showAccount(ctx, req.Account)
	if err != nil {
		return domain.NFTListResult{}, err
	}
	if acct == (common.Address{}) {
		return domain.NFTListResult{}, domain.New(domain.CodeUsage+".no_account",
			"no --account given and no default account set (run `daxie account use`)")
	}

	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.NFTListResult{}, err
	}
	defer cc.Close()

	collections, err := s.nfts.ListCollections(ctx, network)
	if err != nil {
		return domain.NFTListResult{}, err
	}
	// Index collections by alias so an nft alias resolves its kind/address locally.
	byAlias := make(map[string]registry.Collection, len(collections))
	for _, c := range collections {
		byAlias[c.Alias] = c
	}

	aliases, err := s.nfts.ListNFTAliases(ctx, network)
	if err != nil {
		return domain.NFTListResult{}, err
	}

	emitResolved(emit, acct.Hex(), "nfts of "+acct.Hex())

	owned := make([]domain.NFTShowResult, 0, len(aliases))
	for _, na := range aliases {
		col, ok := byAlias[na.Collection]
		if !ok {
			continue // an nft alias whose collection vanished (hand-edited) — skip
		}
		tokenID, ok := new(big.Int).SetString(na.TokenID, 10)
		if !ok {
			continue
		}
		row := domain.NFTShowResult{
			Network:    network,
			Collection: col.Address.Hex(),
			Alias:      col.Alias,
			NFTAlias:   na.Alias,
			Kind:       col.Kind,
			TokenID:    na.TokenID,
			Account:    acct.Hex(),
		}
		switch col.Kind {
		case registry.KindERC721:
			owner, oerr := s.erc.OwnerOf(ctx, cc, col.Address, tokenID)
			if oerr != nil {
				continue // a burned/nonexistent token or a transient read — skip in the list view
			}
			if owner != acct {
				continue // not owned by this account
			}
			row.Owner = owner.Hex()
			row.OwnedByYou = true
		case registry.KindERC1155:
			bal, berr := s.erc.BalanceOf1155(ctx, cc, col.Address, acct, tokenID)
			if berr != nil || bal.Sign() == 0 {
				continue // not held
			}
			row.Balance = bal.String()
			row.OwnedByYou = true
		default:
			continue
		}
		owned = append(owned, row)
	}

	return domain.NFTListResult{Network: network, Address: acct.Hex(), Owned: owned}, nil
}

// ── send (a transfer through the SAME pipeline → a TxResult) ──────────────────

// SendNFT builds and broadcasts an NFT safeTransferFrom through the §2.7
// authorize→broadcast→settle/abort kernel (runSend) as a KindTransfer (§5.1). It
// mirrors SendTx's token branch + runApprove exactly: resolve From (the signer),
// resolve To (the RECIPIENT — the policy subject), dial, resolve the NFT
// (registry-only + ERC-165 for a raw collection), build the standard-correct
// safeTransferFrom calldata (721 vs 1155 by the stored/detected kind), and hand an
// Intent to runSend. The policy destination is the RECIPIENT, NEVER the collection
// (§4.2/§4.3); the §4.3 fail-closed-no-allowlist gate fires for it.
func (s *Service) SendNFT(ctx context.Context, p domain.Principal, req domain.NFTSendRequest, sink domain.EventSink) (domain.TxResult, error) {
	in, err := s.resolveNFTSendIntent(ctx, p, req, sink)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer in.cc.Close()

	// Preview the gas quote BEFORE the lock (§5.1), exactly like a token send. The
	// safeTransferFrom calldata is non-empty so estimateGas reflects the real cost.
	if err := s.previewGas(ctx, &in, domain.TxRequest{Network: req.Network, RPC: req.RPC}, sink); err != nil {
		return domain.TxResult{}, err
	}

	// --dry-run: the check-only policy verdict (no reservation), then stop before sign.
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

// resolveNFTSendIntent builds the prefetch-stage Intent for an NFT send (§2.7). The
// tx `to` is the COLLECTION contract; the policy dest is the RECIPIENT.
func (s *Service) resolveNFTSendIntent(ctx context.Context, p domain.Principal, req domain.NFTSendRequest, sink domain.EventSink) (Intent, error) {
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

	// ── To = the RECIPIENT (the policy subject; 0x | contact; ENS is M7) ──
	dest, err := s.resolveDest(ctx, ChainRequest{Network: req.Network, RPC: req.RPC}, req.To)
	if err != nil {
		return Intent{}, err
	}
	emitResolvedDest(sink, "to ", dest)

	// ── dial + chain id ──
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return Intent{}, err
	}
	network := s.networkName(req.Network)
	chainID, err := cc.ChainID(ctx)
	if err != nil {
		cc.Close()
		return Intent{}, mapRPCErr(err)
	}

	// ── resolve the NFT (registry-only for alias forms; raw 0x reads ERC-165 once) ──
	rn, err := s.resolveNFT(ctx, cc, network, req.NFT)
	if err != nil {
		cc.Close()
		return Intent{}, err
	}

	tokenID, ok := new(big.Int).SetString(rn.tokenID, 10)
	if !ok {
		cc.Close()
		return Intent{}, domain.Newf(domain.CodeUsage+".bad_token_id",
			"token id %q is not a non-negative decimal integer", rn.tokenID)
	}

	// ── amount selection (the standard switch) ──
	amount, qtyStr, kind, err := nftSendAmount(rn.kind, req.Amount)
	if err != nil {
		cc.Close()
		return Intent{}, err
	}

	// ── build the standard-correct safeTransferFrom calldata ──
	// from == the signer (the EVM `from` arg); to == the recipient. The erc builder
	// picks 721 (amount==nil → 0x42842e0e) vs 1155 (amount!=nil → 0xf242432a, empty
	// bytes) — byte-for-byte the golden vectors.
	data := s.erc.SafeTransferFromCalldata(from, dest.Address, tokenID, amount)

	collectionHex := strings.ToLower(rn.collection.Hex())
	tokenIDStr := rn.tokenID
	asset := journal.Asset{
		Kind:     kind,
		Contract: &collectionHex,
		Alias:    rn.collectionAlias,
		TokenID:  &tokenIDStr,
	}
	if kind == registry.KindERC1155 {
		// The 1155 quantity rides in the asset Amount (display only); 721 has none.
		asset.Amount = &qtyStr
	}

	jkind := journal.KindERC721Transfer
	if kind == registry.KindERC1155 {
		jkind = journal.KindERC1155Transfer
	}

	in := Intent{
		chainID: chainID,
		network: network,
		rpc:     req.RPC,
		cc:      cc,
		from:    from,
		ref:     fromRef,
		// dest is the RECIPIENT for the result echo + the policy subject (policyDest).
		dest:  dest,
		to:    rn.collection, // the tx goes TO the collection contract
		value: big.NewInt(0), // an NFT transfer carries no ETH
		data:  data,          // the safeTransferFrom calldata
		// THE policy subject = the RECIPIENT (NOT the collection contract) (§4.2/§4.3).
		// policyKind stays policyKindDefault → policyCheckKind() returns the journal
		// kind string ("erc721-transfer"/"erc1155-transfer") → the engine's
		// effectiveKind() defaults it to KindTransfer; isTokenOp() (tx.go) recognizes
		// the NFT kinds so checkAsset()/tokenTag() return the collection contract and
		// the §4.3 fail-closed-no-allowlist gate fires (ETH exempt, NFT NOT).
		policyDest: dest.Address,
		kind:       jkind,
		asset:      asset,
		nonce:      req.Nonce,
		source:     sourceOf(p),
	}
	return in, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// nftSendAmount applies the §5.1 standard switch to the --amount for an NFT send:
//
//   - erc721: --amount MUST be empty or "1" (a plain 721 carries no quantity);
//     anything else is usage.bad_amount. The calldata amount is nil → the erc
//     builder emits the 721 safeTransferFrom(from,to,tokenId) (0x42842e0e). The
//     quantity string is "1" for the echo.
//   - erc1155: --amount defaults to "1" when omitted; it is a plain integer QUANTITY
//     (NOT decimals-scaled — 1155 amounts are raw unit counts). The calldata amount
//     is big.Int(amount) → the erc builder emits
//     safeTransferFrom(from,to,id,amount,"") (0xf242432a, empty bytes).
//
// It returns the calldata amount (nil for 721, non-nil for 1155), the display
// quantity string, and the normalized kind. A nil/zero/negative 1155 quantity is
// usage.bad_amount (a transfer of zero is meaningless and most 1155s revert on it).
func nftSendAmount(kind, amount string) (*big.Int, string, string, error) {
	amount = strings.TrimSpace(amount)
	switch kind {
	case registry.KindERC721:
		if amount != "" && amount != "1" {
			return nil, "", "", domain.Newf(domain.CodeUsage+".bad_amount",
				"--amount %q is invalid for an ERC-721 (a 721 transfers exactly one token; omit --amount or pass 1)", amount)
		}
		// nil ⇒ the erc builder emits the 721 safeTransferFrom(from,to,tokenId).
		return nil, "1", registry.KindERC721, nil
	case registry.KindERC1155:
		if amount == "" {
			amount = "1"
		}
		qty, ok := new(big.Int).SetString(amount, 10)
		if !ok || qty.Sign() <= 0 {
			return nil, "", "", domain.Newf(domain.CodeUsage+".bad_amount",
				"--amount %q is not a positive integer quantity (ERC-1155 amounts are raw unit counts)", amount)
		}
		return qty, qty.String(), registry.KindERC1155, nil
	default:
		return nil, "", "", erc.ErrNotNFT
	}
}

// nftRefForShow builds the resolveNFT reference for `nft show`: it prefers the
// explicit --nft, else assembles a <contract>#<tokenId> from the --contract +
// --token-id form. An empty input is left to resolveNFT/ResolveNFT to reject with
// usage.bad_nft_ref.
func nftRefForShow(req domain.NFTShowRequest) string {
	if strings.TrimSpace(req.NFT) != "" {
		return strings.TrimSpace(req.NFT)
	}
	c := strings.TrimSpace(req.Contract)
	id := strings.TrimSpace(req.TokenID)
	if c == "" || id == "" {
		return "" // resolveNFT rejects cleanly (usage.bad_nft_ref)
	}
	return c + "#" + id
}

// showAccount resolves the read subject for a 1155 balance / a list: the request
// ref, else the §7.7 default account. A raw 0x or a keystore ref resolves via the
// read-only AddressOf (no unlock). An empty ref + no default yields the zero
// address (the caller decides whether that is an error: NFTShow tolerates it for a
// 721; NFTList requires it). A bad ref surfaces its parse/lookup error.
func (s *Service) showAccount(ctx context.Context, ref string) (common.Address, error) {
	refStr := strings.TrimSpace(ref)
	if refStr == "" {
		refStr = s.activeDefault(ctx)
	}
	if refStr == "" {
		return common.Address{}, nil
	}
	ar, err := domain.ParseAccountRef(refStr)
	if err != nil {
		return common.Address{}, err
	}
	return s.keys.AddressOf(ar)
}
