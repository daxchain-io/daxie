package registry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
	"github.com/ethereum/go-ethereum/common"
)

// tokensVersion is the per-network registry schema version (§7.8). v=1 carried the
// tokens/collections/nft_aliases keys (M5 fungible + M6 NFT shapes); M10 BUMPS it to 2
// for the additive contracts[] key (§7.8). A v=1 file (no contracts key) is
// forward-migrated by treating a missing contracts as empty (load() leaves it nil; save()
// stamps v=2 + emits an empty array). Both a Tokens mutation and a Contracts mutation
// rewrite the whole v=2 envelope preserving each other's keys (load reads all keys; save
// emits all keys) — no data loss across the namespaces sharing the per-network file.
const tokensVersion = 2

// tokensMaxReadableVersion is the highest on-disk v this binary will read. It equals
// tokensVersion (this binary reads what it writes). A v greater than this is refused (a
// newer binary wrote a breaking schema) — state.corrupt, fail closed. A v=1 file written
// by an older M5/M6 binary forward-reads here (its missing contracts key is empty).
const tokensMaxReadableVersion = 2

// KindERC20 is the fungible kind string stored on a Token (§7.8 "kind":"erc20").
// KindERC721/KindERC1155 are the M6 NFT kinds — defined now so the shared schema and
// kind-detection vocabulary live in one place; M5 stores only KindERC20.
const (
	KindERC20   = "erc20"
	KindERC721  = "erc721"
	KindERC1155 = "erc1155"
)

// CodeUsageDuplicate is the §7.8 "collision-requires-an-explicit-name" rejection: an
// alias (case-insensitive) that already names a file entry OR a bundled major on this
// network. The caller (cli/service) surfaces it instructing `--name <other>`. Exit 2
// (usage family).
const CodeUsageDuplicate = domain.CodeUsage + ".duplicate"

// CodeUsageBundledImmutable is the rejection for a rename/remove targeting a bundled
// major directly: bundled majors are compiled in, not on disk, so they cannot be
// renamed-in-place or removed. (A user who wants a different alias for a bundled
// token registers a file entry under the new alias, which then overrides the bundled
// one.) Exit 2 (usage family).
const CodeUsageBundledImmutable = domain.CodeUsage + ".bundled_immutable"

// Token is one registry entry (§7.8). For M5 it is always an ERC-20 (Kind ==
// KindERC20); the ERC-721/1155 kinds are reserved for M6. Alias is stored lowercase,
// matched case-insensitively, and follows the §3.1 name grammar. Kind is detected at
// `add` and stored. Decimals and Symbol are DISPLAY metadata only: resolution NEVER
// matches on Symbol (the anti-spoofing property — symbol spoofing is free, §7.8).
type Token struct {
	Alias    string         `json:"alias"`
	Address  common.Address `json:"address"`
	Kind     string         `json:"kind"`     // "erc20" (M6: "erc721"/"erc1155")
	Decimals uint8          `json:"decimals"` // 0 for non-fungible kinds
	Symbol   string         `json:"symbol"`   // display only; NEVER resolved against
}

// Collection is an M6 NFT collection alias (§7.8 collections[]). The file carries the
// array now so an M6 binary reads the same shape; M5 leaves it empty and implements
// no NFT logic.
type Collection struct {
	Alias   string         `json:"alias"`
	Address common.Address `json:"address"`
	Kind    string         `json:"kind"` // "erc721" | "erc1155"
}

// NFTAlias is an M6 NFT instance alias (§7.8 nft_aliases[]). TokenID is a decimal
// string because IDs exceed 2^53. M5 leaves it empty.
type NFTAlias struct {
	Alias      string `json:"alias"`
	Collection string `json:"collection"`
	TokenID    string `json:"token_id"`
}

// tokensFile is the on-disk envelope for registry/<network>.json (§7.8). The
// collections/nft_aliases arrays are always present (M6 shape). The contracts[] array is
// the M10 contract-registry namespace co-located in the same per-network file (§7.8) —
// modeled here so EVERY mutation (a Tokens add, an NFT add, a Contract add) round-trips
// ALL keys: load reads them all, save emits them all, so two namespaces sharing the file
// never drop each other's data. A v=1 file (no contracts key) reads with Contracts==nil
// (forward-migration §7.10); save() normalizes nil to an empty array.
type tokensFile struct {
	V           int          `json:"v"`
	Network     string       `json:"network"`
	Tokens      []Token      `json:"tokens"`
	Collections []Collection `json:"collections"`
	NFTAliases  []NFTAlias   `json:"nft_aliases"`
	Contracts   []Contract   `json:"contracts"`
}

// ResolvedToken is a registry entry plus its provenance: Bundled is true when it came
// from the compiled-in majors (not the on-disk file). The cli shows provenance in
// `token list`.
type ResolvedToken struct {
	Token
	Bundled bool `json:"bundled"`
}

// Tokens is the per-network token registry store (state class). Like Contacts it
// holds no long-lived fd: every operation opens/(locks for mutations)/reads/writes/
// releases on the SAME registry flock contacts use (withRegistryLock on
// locks/registry.lock, registry.go), so concurrent daxie processes serialize cleanly
// across contacts AND token mutations.
type Tokens struct {
	registryDir string
}

// OpenTokens binds to <registryDir>. Lazy: it creates nothing on disk; a missing
// per-network file reads as the bundled-majors-only set. registryDir is
// config.Paths.RegistryDir (DAXIE_REGISTRY_DIR or <State>/registry) — the same dir
// contacts and the locks/ subdir live under.
func OpenTokens(registryDir string) (*Tokens, error) {
	return &Tokens{registryDir: registryDir}, nil
}

// path is <registryDir>/<network>.json (per-network keying, §7.8). network is a
// caller-supplied canonical network name (e.g. "mainnet", "sepolia"); it is the
// network of the active chain and is filename-safe by construction (the chain layer
// validates network names).
func (t *Tokens) path(network string) string {
	return filepath.Join(t.registryDir, network+".json")
}

// Add registers an alias→{address,kind,decimals,symbol} on a network under the
// registry lock (§7.8). tok.Alias must be a §3.1-grammar name (the caller — service —
// supplies it, defaulting to the case-folded on-chain symbol when the user gave no
// --name; the registry never touches the chain). Add canonicalizes the alias
// (lowercase + grammar check) and rejects:
//   - a bad alias → usage.bad_name (exit 2);
//   - an alias that collides (case-insensitive) with an existing FILE entry OR a
//     bundled major on this network → usage.duplicate (exit 2), instructing --name;
//   - a read-only state mount → the state-class read-only sibling of config.read_only
//     (exit 10, §7.8).
//
// The cross-namespace collision guard (alias vs contact/wallet name) is service's
// responsibility (the §3.2 ref.ambiguous rule); this store enforces only within-
// network alias uniqueness (file ∪ bundled).
func (t *Tokens) Add(ctx context.Context, network string, tok Token) error {
	canon, err := canonicalName(tok.Alias)
	if err != nil {
		return err
	}
	tok.Alias = canon
	if tok.Kind == "" {
		tok.Kind = KindERC20
	}
	return withRegistryLock(ctx, t.registryDir, func() error {
		f, lerr := t.load(network)
		if lerr != nil {
			return lerr
		}
		// Collision against a bundled major (compiled in) requires --name.
		if _, isBundled := bundledLookup(network, canon); isBundled {
			return domain.Newf(CodeUsageDuplicate,
				"alias %q is a bundled token on %s; choose a different alias with --name", canon, network)
		}
		// Collision against an existing file entry requires --name.
		for _, existing := range f.Tokens {
			if existing.Alias == canon {
				return domain.Newf(CodeUsageDuplicate,
					"a token aliased %q already exists on %s; remove it first or choose another alias with --name", canon, network)
			}
		}
		f.Tokens = append(f.Tokens, tok)
		return t.save(network, f)
	})
}

// Rename changes a FILE entry's alias on a network under the registry lock. A bundled
// major cannot be renamed in place (it is compiled in) → usage.bundled_immutable; the
// way to "rename" a bundled token is to `token add` it under the desired alias, which
// then overrides the bundled one. An absent old alias is ref.not_found (exit 10); a
// new alias colliding (case-insensitive) with a file entry OR a bundled major is
// usage.duplicate (exit 2).
func (t *Tokens) Rename(ctx context.Context, network, oldAlias, newAlias string) error {
	oldCanon, err := canonicalName(oldAlias)
	if err != nil {
		return err
	}
	newCanon, err := canonicalName(newAlias)
	if err != nil {
		return err
	}
	return withRegistryLock(ctx, t.registryDir, func() error {
		f, lerr := t.load(network)
		if lerr != nil {
			return lerr
		}
		// Renaming a bundled major in place is not possible.
		if _, isBundled := bundledLookup(network, oldCanon); isBundled {
			return domain.Newf(CodeUsageBundledImmutable,
				"%q is a bundled token on %s and cannot be renamed; add it under the new alias instead", oldCanon, network)
		}
		idx := -1
		for i, existing := range f.Tokens {
			if existing.Alias == oldCanon {
				idx = i
				break
			}
		}
		if idx < 0 {
			return tokenNotFound(oldCanon, network)
		}
		// New alias must not collide with a bundled major or another file entry.
		if _, isBundled := bundledLookup(network, newCanon); isBundled {
			return domain.Newf(CodeUsageDuplicate,
				"alias %q is a bundled token on %s; choose a different alias", newCanon, network)
		}
		for i, existing := range f.Tokens {
			if i != idx && existing.Alias == newCanon {
				return domain.Newf(CodeUsageDuplicate,
					"a token aliased %q already exists on %s", newCanon, network)
			}
		}
		f.Tokens[idx].Alias = newCanon
		return t.save(network, f)
	})
}

// Remove deletes a FILE entry by alias (case-insensitive) on a network under the
// registry lock. A bundled major cannot be removed (it is compiled in) →
// usage.bundled_immutable. An absent alias is ref.not_found (exit 10).
func (t *Tokens) Remove(ctx context.Context, network, alias string) error {
	canon, err := canonicalName(alias)
	if err != nil {
		return err
	}
	return withRegistryLock(ctx, t.registryDir, func() error {
		f, lerr := t.load(network)
		if lerr != nil {
			return lerr
		}
		idx := -1
		for i, existing := range f.Tokens {
			if existing.Alias == canon {
				idx = i
				break
			}
		}
		if idx < 0 {
			if _, isBundled := bundledLookup(network, canon); isBundled {
				return domain.Newf(CodeUsageBundledImmutable,
					"%q is a bundled token on %s and cannot be removed", canon, network)
			}
			return tokenNotFound(canon, network)
		}
		f.Tokens = append(f.Tokens[:idx], f.Tokens[idx+1:]...)
		return t.save(network, f)
	})
}

// List returns the MERGED known set for a network: bundled majors OVERLAID by file
// entries (a file entry with the same alias wins; §7.8), alias-sorted, each row
// marked Bundled so the cli can show provenance. A missing per-network file lists
// just the bundled majors (a fresh install). This is the §10.3 Discovery
// KnownAssets — the --all balance path iterates it.
func (t *Tokens) List(ctx context.Context, network string) ([]ResolvedToken, error) {
	_ = ctx
	f, err := t.load(network)
	if err != nil {
		return nil, err
	}
	return mergeBundled(network, f.Tokens), nil
}

// Resolve maps an alias (case-insensitive) to its resolved token on a network.
// Resolution is REGISTRY-ONLY (§7.8 / requirements §2 — the core anti-spoofing
// property): file entries first, then bundled majors. A miss returns found=false
// (and a nil error) — it is NEVER promoted to an on-chain symbol() lookup; the caller
// (service) raises ref.not_found. A non-grammar alias is also a clean miss
// (found=false) so a caller that tries the registry before a raw-0x branch falls
// through without erroring.
func (t *Tokens) Resolve(ctx context.Context, network, alias string) (ResolvedToken, bool, error) {
	_ = ctx
	canon, err := canonicalName(alias)
	if err != nil {
		// Not a valid alias ⇒ it is not a registry name; clean miss (no chain lookup).
		return ResolvedToken{}, false, nil
	}
	f, lerr := t.load(network)
	if lerr != nil {
		return ResolvedToken{}, false, lerr
	}
	// File entries override bundled majors.
	for _, tk := range f.Tokens {
		if tk.Alias == canon {
			return ResolvedToken{Token: tk, Bundled: false}, true, nil
		}
	}
	// Then bundled majors.
	if tk, ok := bundledLookup(network, canon); ok {
		return ResolvedToken{Token: tk, Bundled: true}, true, nil
	}
	// A miss — NEVER an on-chain symbol() fallback (the anti-spoofing wall, §7.8).
	return ResolvedToken{}, false, nil
}

// ── Discovery seam (§2.10 / §10.3) ────────────────────────────────────────────

// Discovery answers "what is this alias?" and "what assets are known for this
// network?". It is the registry read seam (§10.3 "Indexer-based discovery"): M5 ships
// ONE impl, *Tokens, backed by the local registry + bundled majors. A future indexer
// implements the SAME interface to answer from on-chain/index data ("what does this
// address actually hold?") WITHOUT changing any service call site — service holds a
// registry.Discovery, the concrete store stays *Tokens.
//
// The anti-spoofing contract is part of the interface: ResolveAsset is registry-only
// in the local impl; a miss is found=false (the caller errors ref.not_found), NEVER an
// on-chain symbol() lookup.
type Discovery interface {
	// ResolveAsset maps a registry alias to its resolved token on a network. A miss
	// is found=false (the caller errors ref.not_found). Registry-only in the local
	// impl; never an on-chain symbol() lookup (§7.8).
	ResolveAsset(ctx context.Context, network, alias string) (ResolvedToken, bool, error)
	// KnownAssets lists every asset Discovery knows for a network (the local impl:
	// bundled majors ∪ file tokens, alias-sorted). The --all balance path iterates
	// these and reads each balanceOf. owner is unused by the local impl (it lists the
	// registry, not holdings) but is in the signature so a future indexer impl can
	// enumerate what owner actually holds.
	KnownAssets(ctx context.Context, network string, owner common.Address) ([]ResolvedToken, error)
}

// ResolveAsset satisfies Discovery for the local registry-backed impl (it delegates
// to Resolve). *Tokens is the concrete type service holds behind registry.Discovery.
func (t *Tokens) ResolveAsset(ctx context.Context, network, alias string) (ResolvedToken, bool, error) {
	return t.Resolve(ctx, network, alias)
}

// KnownAssets satisfies Discovery for the local registry-backed impl (it delegates to
// List, ignoring owner — the local impl enumerates the registry, not holdings).
func (t *Tokens) KnownAssets(ctx context.Context, network string, owner common.Address) ([]ResolvedToken, error) {
	_ = owner
	return t.List(ctx, network)
}

// staticAssertDiscovery proves *Tokens satisfies Discovery at compile time (the M5
// seam impl). A future indexer impl is a second type satisfying the same interface.
var _ Discovery = (*Tokens)(nil)

// ── load / save ───────────────────────────────────────────────────────────────

// load reads and parses registry/<network>.json. A missing file is an empty,
// current-version envelope (lazy, fresh install). A corrupt file is state.corrupt
// (exit 11). A version higher than this binary forward-reads (tokensMaxReadableVersion)
// is refused (fail closed). The caller need not hold the lock for a read; mutations
// call load while holding it. The collections/nft_aliases arrays are read into the
// envelope so a mutation rewrite preserves any M6 NFT data already on disk.
func (t *Tokens) load(network string) (*tokensFile, error) {
	b, err := os.ReadFile(t.path(network))
	if err != nil {
		if os.IsNotExist(err) {
			return &tokensFile{V: tokensVersion, Network: network}, nil
		}
		return nil, domain.Wrap("state.corrupt", "cannot read the token registry file", err)
	}
	var f tokensFile
	if jerr := json.Unmarshal(b, &f); jerr != nil {
		return nil, domain.Wrap("state.corrupt", "the token registry file is corrupt (not valid JSON)", jerr)
	}
	if f.V > tokensMaxReadableVersion {
		return nil, domain.Newf("state.corrupt",
			"the token registry file is schema version %d, newer than this binary supports (%d); upgrade daxie",
			f.V, tokensMaxReadableVersion)
	}
	return &f, nil
}

// save atomically writes registry/<network>.json (0600) under the registry lock (the
// caller holds it). It MkdirAll's the registry dir first (lazy, §7.3). A read-only
// mount maps to the state-class read-only sibling of config.read_only (exit 10). It
// always stamps v=2 (tokensVersion) and emits ALL keys (tokens/collections/nft_aliases/
// contracts) — load() read them all, so a mutation in any one namespace preserves the
// others verbatim (the §7.8 co-located-namespaces invariant; no data loss).
func (t *Tokens) save(network string, f *tokensFile) error {
	f.V = tokensVersion
	f.Network = network
	// Normalize nil slices to empty arrays so the on-disk schema always shows the
	// keys (§7.8 shape), matching the contacts file's explicit-array convention.
	if f.Tokens == nil {
		f.Tokens = []Token{}
	}
	if f.Collections == nil {
		f.Collections = []Collection{}
	}
	if f.NFTAliases == nil {
		f.NFTAliases = []NFTAlias{}
	}
	if f.Contracts == nil {
		f.Contracts = []Contract{}
	}
	if err := fsx.MkdirAll(t.registryDir, dirMode); err != nil {
		if fsx.IsReadOnly(err) {
			return errReadOnly()
		}
		return domain.Wrap("state.corrupt", "cannot create the registry directory", err)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return domain.Wrap("state.corrupt", "cannot encode the token registry file", err)
	}
	if werr := fsx.WriteAtomic(t.path(network), b, fileMode); werr != nil {
		if fsx.IsReadOnly(werr) {
			return errReadOnly()
		}
		return domain.Wrap("state.corrupt", "cannot write the token registry file", werr)
	}
	return nil
}

// tokenNotFound is the ref.not_found error for a missing token alias (exit 10).
func tokenNotFound(alias, network string) error {
	return domain.Newf(domain.CodeRefNotFound, "no token aliased %q on %s", alias, network)
}

// sortResolved sorts a ResolvedToken slice by alias for a stable listing.
func sortResolved(rs []ResolvedToken) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Alias < rs[j].Alias })
}
