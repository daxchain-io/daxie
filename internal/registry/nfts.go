package registry

// nfts.go is the per-network NFT registry: collection aliases (collections[]) and
// individual-NFT aliases (nft_aliases[]), co-located in registry/<network>.json
// with the tokens (§7.8). It is a peer of Tokens and deliberately REUSES Tokens'
// load/save + the shared registry flock + WriteAtomic discipline so the whole
// per-network envelope — tokens, collections, nft_aliases — is ONE atomic unit
// under ONE lock; collections/nft_aliases can never drift from the tokens beside
// them. NFTs holds a *Tokens and calls its unexported load/save (same package).
//
// ANTI-SPOOFING (§7.8, identical to tokens, applied to collections too): both
// collection and individual-NFT alias resolution is REGISTRY-ONLY, case-folded,
// per-network. A miss is an error (ref.not_found) — NEVER an on-chain
// name()/symbol() lookup, because symbol spoofing is free. There are NO bundled
// NFT majors (unlike token majors): collection resolution is file-only.
//
// token_id is a DECIMAL STRING end to end (IDs exceed 2^53, §7.8) — validated as
// a non-negative base-10 integer of any magnitude via math/big, stored verbatim
// as its canonical decimal string; it is NEVER an int64/float.

import (
	"context"
	"math/big"
	"sort"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// CodeUsageBadKind is the rejection for AddCollection given a kind that is not
// erc721/erc1155 (service detects it via ERC-165 at add; the registry never
// touches the chain, so it only validates the kind it was handed). Exit 2 (usage).
const CodeUsageBadKind = domain.CodeUsage + ".bad_kind"

// CodeUsageBadTokenID is the rejection for a token id that is not a non-negative
// decimal integer. Exit 2 (usage).
const CodeUsageBadTokenID = domain.CodeUsage + ".bad_token_id"

// CodeUsageBadNFTRef is the rejection for an NFT reference that is neither an
// individual-NFT alias nor a <collection>#<tokenId> form. Exit 2 (usage).
const CodeUsageBadNFTRef = domain.CodeUsage + ".bad_nft_ref"

// NFTs is the per-network NFT registry store (state class). It holds no long-lived
// fd; like Tokens every operation opens/(locks for mutations)/reads/writes/releases
// on the SAME registry flock (withRegistryLock), so concurrent daxie processes
// serialize cleanly across contacts, token, AND NFT mutations on one envelope.
type NFTs struct {
	store *Tokens // shared envelope owner (same registryDir + flock + load/save)
}

// OpenNFTs binds to <registryDir> — the same dir Tokens/Contacts use. Lazy: it
// creates nothing on disk (a missing per-network file reads as an empty set).
func OpenNFTs(registryDir string) (*NFTs, error) {
	t, err := OpenTokens(registryDir)
	if err != nil {
		return nil, err
	}
	return &NFTs{store: t}, nil
}

// ── collections ────────────────────────────────────────────────────────────────

// AddCollection registers a collection alias→{address,kind} on a network under the
// registry lock (§7.8). col.Alias is canonicalized (lowercase + §3.1 grammar).
// col.Kind MUST be KindERC721 or KindERC1155 — service detected it via ERC-165 at
// add and passes it in; the registry never touches the chain. Rejects:
//   - a bad alias → usage.bad_name (exit 2, via canonicalName);
//   - a kind that is not erc721/erc1155 → usage.bad_kind (exit 2);
//   - an alias that collides (case-insensitive) with an existing collection on this
//     network → usage.duplicate (exit 2), instructing --name.
//
// There is no bundled-collection collision (no bundled NFT majors). A read-only
// state mount surfaces as the state-class read-only error (exit 10) via save().
func (n *NFTs) AddCollection(ctx context.Context, network string, col Collection) error {
	canon, err := canonicalName(col.Alias)
	if err != nil {
		return err
	}
	col.Alias = canon
	if col.Kind != KindERC721 && col.Kind != KindERC1155 {
		return domain.Newf(CodeUsageBadKind,
			"collection kind %q is not erc721 or erc1155", col.Kind)
	}
	return withRegistryLock(ctx, n.store.registryDir, func() error {
		f, lerr := n.store.load(network)
		if lerr != nil {
			return lerr
		}
		for _, e := range f.Collections {
			if e.Alias == canon {
				return domain.Newf(CodeUsageDuplicate,
					"a collection aliased %q already exists on %s; choose another alias with --name", canon, network)
			}
		}
		f.Collections = append(f.Collections, col)
		return n.store.save(network, f)
	})
}

// ResolveCollection maps a collection alias (case-insensitive) to its entry on a
// network. REGISTRY-ONLY (§7.8): a miss is found=false with a nil error — NEVER an
// on-chain name()/symbol() lookup (the anti-spoofing wall, identical to tokens). A
// non-grammar alias is also a clean miss (found=false, nil error) so a caller can
// fall through to a raw-0x branch without erroring.
func (n *NFTs) ResolveCollection(ctx context.Context, network, alias string) (Collection, bool, error) {
	_ = ctx
	canon, err := canonicalName(alias)
	if err != nil {
		return Collection{}, false, nil // not a valid alias ⇒ clean miss (no chain lookup)
	}
	f, lerr := n.store.load(network)
	if lerr != nil {
		return Collection{}, false, lerr
	}
	for _, e := range f.Collections {
		if e.Alias == canon {
			return e, true, nil
		}
	}
	return Collection{}, false, nil // miss — never an on-chain symbol() fallback
}

// ListCollections returns every collection on a network, alias-sorted. A missing
// per-network file lists nothing (no bundled NFT majors).
func (n *NFTs) ListCollections(ctx context.Context, network string) ([]Collection, error) {
	_ = ctx
	f, err := n.store.load(network)
	if err != nil {
		return nil, err
	}
	out := append([]Collection(nil), f.Collections...)
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out, nil
}

// RemoveCollection deletes a collection alias (case-insensitive) under the registry
// lock. An absent alias is ref.not_found (exit 10). (Exposed for parity with
// Tokens.Remove and the §10.2 "destruction is an operator act" rule; the cli may
// surface it in a later milestone.)
func (n *NFTs) RemoveCollection(ctx context.Context, network, alias string) error {
	canon, err := canonicalName(alias)
	if err != nil {
		return err
	}
	return withRegistryLock(ctx, n.store.registryDir, func() error {
		f, lerr := n.store.load(network)
		if lerr != nil {
			return lerr
		}
		idx := -1
		for i, e := range f.Collections {
			if e.Alias == canon {
				idx = i
				break
			}
		}
		if idx < 0 {
			return domain.Newf(domain.CodeRefNotFound, "no collection aliased %q on %s", canon, network)
		}
		f.Collections = append(f.Collections[:idx], f.Collections[idx+1:]...)
		return n.store.save(network, f)
	})
}

// ── individual-NFT aliases (collection#tokenId → alias) ──────────────────────────

// AliasNFT registers an individual-NFT alias (nft_aliases[]) on a network under the
// registry lock: alias → {collection (alias), token_id} (§7.8). The collection MUST
// already be a registered collection alias on this network — an nft alias binds to a
// KNOWN contract — else ref.not_found. token_id is a DECIMAL STRING (IDs exceed
// 2^53): validated as a non-negative base-10 integer of any magnitude and stored as
// its canonical decimal form. Rejects:
//   - a bad alias / collection alias → usage.bad_name (exit 2, via canonicalName);
//   - an invalid token id → usage.bad_token_id (exit 2);
//   - a missing collection → ref.not_found (exit 10);
//   - a collision with an existing nft alias on this network → usage.duplicate.
func (n *NFTs) AliasNFT(ctx context.Context, network, alias, collectionAlias, tokenID string) error {
	canon, err := canonicalName(alias)
	if err != nil {
		return err
	}
	colCanon, err := canonicalName(collectionAlias)
	if err != nil {
		return err
	}
	id, ok := normalizeTokenID(tokenID)
	if !ok {
		return domain.Newf(CodeUsageBadTokenID,
			"token id %q is not a non-negative decimal integer", tokenID)
	}
	return withRegistryLock(ctx, n.store.registryDir, func() error {
		f, lerr := n.store.load(network)
		if lerr != nil {
			return lerr
		}
		// The collection must already exist (an nft alias binds to a registered
		// collection so the alias→contract chain is whole and registry-only).
		found := false
		for _, c := range f.Collections {
			if c.Alias == colCanon {
				found = true
				break
			}
		}
		if !found {
			return domain.Newf(domain.CodeRefNotFound,
				"no collection aliased %q on %s; register it with `daxie nft add` first", colCanon, network)
		}
		for _, e := range f.NFTAliases {
			if e.Alias == canon {
				return domain.Newf(CodeUsageDuplicate,
					"an NFT aliased %q already exists on %s; choose another alias", canon, network)
			}
		}
		f.NFTAliases = append(f.NFTAliases, NFTAlias{Alias: canon, Collection: colCanon, TokenID: id})
		return n.store.save(network, f)
	})
}

// ResolvedNFT is the fully-resolved individual NFT: the collection address + kind +
// the decimal-string token id, plus any aliases that produced it. It is what
// ResolveNFT returns and what service feeds the erc safeTransferFrom builder + the
// ownerOf/balanceOf reads. TokenID is a DECIMAL STRING (never int64/float).
type ResolvedNFT struct {
	Collection      common.Address // the collection contract
	Kind            string         // "erc721" | "erc1155" | "" (a raw collection not in the registry)
	TokenID         string         // DECIMAL STRING
	CollectionAlias string         // "" for a raw 0x collection not in the registry
	NFTAlias        string         // "" when the ref was not an individual-NFT alias
}

// ResolveNFT maps a --nft reference to a ResolvedNFT. The reference is one of:
//
//	(a) a bare individual-NFT alias ("my-punk") — looked up in nft_aliases[], then
//	    its collection alias resolved to {address,kind} via collections[];
//	(b) "<collection>#<tokenId>" where <collection> is a collection ALIAS — resolved
//	    registry-only to {address,kind}, with the literal tokenId;
//	(c) "<0xcollection>#<tokenId>" — a RAW collection address (always allowed, like a
//	    raw --token). Kind is "" unless the raw address happens to be a registered
//	    collection (then its stored kind is surfaced); when "", service detects the
//	    standard once via ERC-165 for display/standard-selection only.
//
// REGISTRY-ONLY for the alias forms (a) and (b): a collection-alias or nft-alias
// miss is ref.not_found — NEVER an on-chain name() lookup (the same anti-spoofing
// wall as tokens, applied identically to collections). token_id is validated as a
// non-negative decimal integer and returned as its canonical decimal string.
func (n *NFTs) ResolveNFT(ctx context.Context, network, ref string) (ResolvedNFT, error) {
	_ = ctx
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ResolvedNFT{}, domain.New(CodeUsageBadNFTRef,
			"an NFT reference is required (an NFT alias or <collection>#<tokenId>)")
	}
	f, lerr := n.store.load(network)
	if lerr != nil {
		return ResolvedNFT{}, lerr
	}

	// (a) no '#': a bare individual-NFT alias.
	if !strings.Contains(ref, "#") {
		canon, err := canonicalName(ref)
		if err != nil {
			return ResolvedNFT{}, domain.Newf(CodeUsageBadNFTRef,
				"%q is not an NFT alias or a <collection>#<tokenId> reference", ref)
		}
		for _, na := range f.NFTAliases {
			if na.Alias == canon {
				for _, c := range f.Collections {
					if c.Alias == na.Collection {
						return ResolvedNFT{
							Collection:      c.Address,
							Kind:            c.Kind,
							TokenID:         na.TokenID,
							CollectionAlias: c.Alias,
							NFTAlias:        na.Alias,
						}, nil
					}
				}
				// An nft alias whose collection vanished (hand-edited file) — fail
				// closed, never fall back to the chain.
				return ResolvedNFT{}, domain.Newf(domain.CodeRefNotFound,
					"NFT alias %q references unknown collection %q on %s", canon, na.Collection, network)
			}
		}
		return ResolvedNFT{}, domain.Newf(domain.CodeRefNotFound,
			"no NFT aliased %q on %s (use <collection>#<tokenId>)", canon, network)
	}

	// (b)/(c) <collection>#<tokenId>. Split on the FIRST '#'; a second '#' makes the
	// id part non-decimal → bad_token_id.
	colPart, idPart, _ := strings.Cut(ref, "#")
	colPart = strings.TrimSpace(colPart)
	id, ok := normalizeTokenID(idPart)
	if !ok {
		return ResolvedNFT{}, domain.Newf(CodeUsageBadTokenID,
			"token id %q is not a non-negative decimal integer", strings.TrimSpace(idPart))
	}

	// (c) raw 0x collection — always allowed (like a raw --token).
	if common.IsHexAddress(colPart) {
		addr := common.HexToAddress(colPart)
		// If the literal IS a registered collection, surface its alias + stored kind.
		for _, c := range f.Collections {
			if c.Address == addr {
				return ResolvedNFT{Collection: addr, Kind: c.Kind, TokenID: id, CollectionAlias: c.Alias}, nil
			}
		}
		return ResolvedNFT{Collection: addr, Kind: "", TokenID: id}, nil // kind unknown → service detects for display/standard
	}

	// (b) collection alias — registry-only.
	colCanon, err := canonicalName(colPart)
	if err != nil {
		return ResolvedNFT{}, domain.Newf(CodeUsageBadNFTRef,
			"%q is not a 0x address or a valid collection alias", colPart)
	}
	for _, c := range f.Collections {
		if c.Alias == colCanon {
			return ResolvedNFT{Collection: c.Address, Kind: c.Kind, TokenID: id, CollectionAlias: c.Alias}, nil
		}
	}
	return ResolvedNFT{}, domain.Newf(domain.CodeRefNotFound,
		"no collection aliased %q on %s; register it with `daxie nft add <0x>` or pass a 0x address", colCanon, network)
}

// ListNFTAliases returns every individual-NFT alias on a network, alias-sorted.
func (n *NFTs) ListNFTAliases(ctx context.Context, network string) ([]NFTAlias, error) {
	_ = ctx
	f, err := n.store.load(network)
	if err != nil {
		return nil, err
	}
	out := append([]NFTAlias(nil), f.NFTAliases...)
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out, nil
}

// RemoveNFTAlias deletes an individual-NFT alias (case-insensitive) under the
// registry lock. An absent alias is ref.not_found (exit 10).
func (n *NFTs) RemoveNFTAlias(ctx context.Context, network, alias string) error {
	canon, err := canonicalName(alias)
	if err != nil {
		return err
	}
	return withRegistryLock(ctx, n.store.registryDir, func() error {
		f, lerr := n.store.load(network)
		if lerr != nil {
			return lerr
		}
		idx := -1
		for i, e := range f.NFTAliases {
			if e.Alias == canon {
				idx = i
				break
			}
		}
		if idx < 0 {
			return domain.Newf(domain.CodeRefNotFound, "no NFT aliased %q on %s", canon, network)
		}
		f.NFTAliases = append(f.NFTAliases[:idx], f.NFTAliases[idx+1:]...)
		return n.store.save(network, f)
	})
}

// normalizeTokenID validates that a token id is a non-negative base-10 integer of
// ANY magnitude (math/big — IDs exceed 2^53, §7.8) and returns its canonical
// decimal string (leading zeros stripped: "007" → "7"). ok=false on an empty,
// negative, or non-decimal input. The value is never an int64/float.
func normalizeTokenID(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 {
		return "", false
	}
	return v.String(), true // canonical decimal; magnitude-safe
}
