package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// contracts.go is the M10 per-network contract registry (§7.8 / requirements #29). It is
// co-located in the SAME per-network registry/<network>.json envelope as tokens/NFTs (the
// contracts[] key), so it shares the Tokens store's registryDir + locks/registry.lock +
// fsx.WriteAtomic discipline and the v=2 forward-migration — a contract mutation and a
// token mutation both rewrite the whole envelope preserving each other's keys.
//
// Anti-spoofing model, identical to tokens (§7.8): per-network, aliases stored lowercase +
// matched case-insensitively, resolution REGISTRY-ONLY (a miss is found=false, NEVER an
// on-chain symbol()/name() lookup). The alias binds BOTH the address AND the inline ABI as
// ONE atomically-written record so they can never drift. No bundled contracts (there is no
// canonical "majors" set for arbitrary contracts, unlike token majors).
//
// ABI VALIDATION SPLIT (matrix discipline): the FULL ABI parse-validation (canonical
// Solidity ABI via internal/abi.ParseJSON) is the SERVICE layer's job at the `contract add`
// use case, BEFORE it calls Add — registry must not import internal/abi (the only
// sanctioned abi inbound edge is policy→abi; arch_test §2.2). This store does a defensive
// STRUCTURAL check here (the ABI must be a non-empty JSON array) so a malformed blob can
// never reach disk even if a caller skipped the service-layer validation, and re-checks the
// shape defensively on read. The service contract add wires abi.ParseJSON ahead of Add so
// the §7.8 "invalid ABI rejected at add with usage.*" guarantee holds end-to-end.

// Contract is one per-network contract registry entry (§7.8). Alias is stored lowercase,
// matched case-insensitively, and follows the §3.1 name grammar (canonicalName). The alias
// binds BOTH Address AND ABI as the anti-spoofing unit. ABI is the canonical Solidity ABI
// JSON array, stored verbatim (the service validated it via internal/abi.ParseJSON at add).
type Contract struct {
	Alias   string          `json:"alias"`
	Address common.Address  `json:"address"`
	ABI     json.RawMessage `json:"abi"`
}

// Contracts is the per-network contract registry store (state class). Like NFTs it embeds
// the shared Tokens envelope owner (same registryDir + flock + load/save), so concurrent
// daxie processes serialize cleanly across contacts, token, NFT, AND contract mutations on
// one per-network file.
type Contracts struct {
	store *Tokens // shared envelope owner (same registryDir + flock + load/save)
}

// OpenContracts binds to <registryDir> — the same dir Tokens/NFTs/Contacts use. Lazy: it
// creates nothing on disk (a missing per-network file reads as an empty set).
func OpenContracts(registryDir string) (*Contracts, error) {
	t, err := OpenTokens(registryDir)
	if err != nil {
		return nil, err
	}
	return &Contracts{store: t}, nil
}

// Add registers a contract alias→{address, ABI} on a network under the registry lock
// (§7.8). It canonicalizes the alias (lowercase + §3.1 grammar) and rejects:
//   - a bad alias → usage.bad_name (exit 2, via canonicalName);
//   - a structurally-invalid ABI (not a non-empty JSON array) → usage.bad_abi (exit 2),
//     never stored (the service layer additionally validated it via internal/abi.ParseJSON);
//   - an alias colliding (case-insensitive) with an existing contract on this network →
//     usage.duplicate (exit 2), instructing --name;
//   - a read-only state mount → the state-class read-only error (exit 10) via save().
//
// The cross-namespace collision guard (alias vs token/contact/wallet name) is service's
// responsibility (the §3.2 ref.ambiguous rule); this store enforces only within-network
// contract-alias uniqueness. Contract aliases are looked up only in the contract verb, so a
// token/contract alias sharing a name in the same file is a non-issue in v1.
func (c *Contracts) Add(ctx context.Context, network string, ct Contract) error {
	canon, err := canonicalName(ct.Alias)
	if err != nil {
		return err
	}
	ct.Alias = canon
	normABI, err := normalizeABI(ct.ABI)
	if err != nil {
		return err
	}
	ct.ABI = normABI
	return withRegistryLock(ctx, c.store.registryDir, func() error {
		f, lerr := c.store.load(network)
		if lerr != nil {
			return lerr
		}
		for _, existing := range f.Contracts {
			if existing.Alias == canon {
				return domain.Newf(CodeUsageDuplicate,
					"a contract aliased %q already exists on %s; remove it first or choose another alias with --name", canon, network)
			}
		}
		f.Contracts = append(f.Contracts, ct)
		return c.store.save(network, f)
	})
}

// List returns every registered contract on a network, alias-sorted. A missing per-network
// file lists nothing (a fresh install). There are no bundled contracts to merge.
func (c *Contracts) List(ctx context.Context, network string) ([]Contract, error) {
	_ = ctx
	f, err := c.store.load(network)
	if err != nil {
		return nil, err
	}
	out := append([]Contract(nil), f.Contracts...)
	sortContracts(out)
	return out, nil
}

// Resolve maps an alias (case-insensitive) to its registered contract on a network.
// Resolution is REGISTRY-ONLY (§7.8 / requirements §2 — the anti-spoofing wall): a miss
// returns found=false with a nil error, NEVER an on-chain name()/symbol() lookup. A
// non-grammar alias is also a clean miss (found=false, nil error) so a caller that tries
// the registry before a raw-0x/ENS branch falls through without erroring. The stored ABI
// is returned verbatim; the stored-ABI lie can never change the destination (the address)
// or — for `contract send` — the classified spender (ClassifyCalldata reads the calldata
// bytes, not the ABI claims).
func (c *Contracts) Resolve(ctx context.Context, network, alias string) (Contract, bool, error) {
	_ = ctx
	canon, err := canonicalName(alias)
	if err != nil {
		return Contract{}, false, nil // not a valid alias ⇒ clean miss (no chain lookup)
	}
	f, lerr := c.store.load(network)
	if lerr != nil {
		return Contract{}, false, lerr
	}
	for _, ct := range f.Contracts {
		if ct.Alias == canon {
			return ct, true, nil
		}
	}
	return Contract{}, false, nil // a miss — NEVER an on-chain fallback (§7.8)
}

// Remove deletes a contract entry by alias (case-insensitive) on a network under the
// registry lock. An absent alias is ref.not_found (exit 10).
func (c *Contracts) Remove(ctx context.Context, network, alias string) error {
	canon, err := canonicalName(alias)
	if err != nil {
		return err
	}
	return withRegistryLock(ctx, c.store.registryDir, func() error {
		f, lerr := c.store.load(network)
		if lerr != nil {
			return lerr
		}
		idx := -1
		for i, existing := range f.Contracts {
			if existing.Alias == canon {
				idx = i
				break
			}
		}
		if idx < 0 {
			return domain.Newf(domain.CodeRefNotFound, "no contract aliased %q on %s", canon, network)
		}
		f.Contracts = append(f.Contracts[:idx], f.Contracts[idx+1:]...)
		return c.store.save(network, f)
	})
}

// normalizeABI does the defensive STRUCTURAL validation (a non-empty JSON array) the
// registry guarantees regardless of the caller, and compacts the bytes for a stable
// on-disk form. It does NOT parse the ABI semantically (that is internal/abi.ParseJSON at
// the service layer — registry must not import abi, the matrix rule). An empty/whitespace,
// non-array, or empty-array ABI is usage.bad_abi (exit 2), never stored.
func normalizeABI(raw json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, domain.New(domain.CodeUsage+".bad_abi",
			"the contract ABI is empty (expected a canonical Solidity ABI JSON array)")
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, domain.Wrap(domain.CodeUsage+".bad_abi",
			"the contract ABI is not a valid JSON array (expected a canonical Solidity ABI)", err)
	}
	if len(arr) == 0 {
		return nil, domain.New(domain.CodeUsage+".bad_abi",
			"the contract ABI is an empty array (no functions or events to bind)")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, domain.Wrap(domain.CodeUsage+".bad_abi", "cannot normalize the contract ABI", err)
	}
	return json.RawMessage(buf.Bytes()), nil
}

// sortContracts orders contracts by alias for a stable listing.
func sortContracts(cs []Contract) {
	sort.Slice(cs, func(i, j int) bool { return cs[i].Alias < cs[j].Alias })
}
