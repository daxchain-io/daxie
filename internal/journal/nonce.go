package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/daxchain-io/daxie/internal/fsx"
)

// NonceManager owns the account lock + nonce derivation (§5.6). Single-writer-per-
// account is the documented rule (parallel hosts are out of contract). It holds a
// per-(chain,account) nonce cache file under <stateDir>/nonce/<chainID>-<addr>.json,
// guarded by the account flock <stateDir>/locks/account-<chainID>-<addr>.lock. The
// nonce cache is an ACCELERATOR; the journal is the source of truth for consumed
// nonces. Lock ordering is ALWAYS account-lock → journal-lock (binding, §5.6).
type NonceManager struct {
	dir   string           // <stateDir>/nonce
	locks string           // <stateDir>/locks
	store *Store           // the journal — folded for journalNext
	clock func() time.Time // for the single-writer-violation warning timestamp (unused detail; kept for symmetry)
}

// NewNonceManager binds to the same state dir + journal store. Lazy: it creates
// nothing until the first AcquireNonce (a fresh install has no cache).
func NewNonceManager(stateDir string, store *Store) (*NonceManager, error) {
	if stateDir == "" {
		return nil, errJournal(CodeStateCorrupt, "nonce: empty state dir")
	}
	if store == nil {
		return nil, errJournal(CodeStateCorrupt, "nonce: nil journal store")
	}
	return &NonceManager{
		dir:   filepath.Join(stateDir, "nonce"),
		locks: filepath.Join(stateDir, "locks"),
		store: store,
		clock: store.clock,
	}, nil
}

// nonceCache is the on-disk per-(chain,account) accelerator: the next nonce the
// local view believes is free. It is advisory — derivation always folds the journal
// and chain too — so a stale or missing cache never causes a double-allocation.
type nonceCache struct {
	V       int    `json:"v"`
	ChainID uint64 `json:"chain_id"`
	Account string `json:"account"`
	Next    uint64 `json:"next"`
	TS      string `json:"ts"`
}

// ── path helpers ──────────────────────────────────────────────────────────────

func (m *NonceManager) cachePath(chainID uint64, addr common.Address) string {
	return filepath.Join(m.dir, fmt.Sprintf("%d-%s.json", chainID, strings.ToLower(addr.Hex())))
}

// accountLockBase is the base path the account flock is taken against (fsx.Lock
// appends ".lock"). One lock object per (chain, account) so two accounts never
// serialize against each other, but two sends from the SAME account do.
func (m *NonceManager) accountLockBase(chainID uint64, addr common.Address) string {
	return filepath.Join(m.locks, fmt.Sprintf("account-%d-%s", chainID, strings.ToLower(addr.Hex())))
}

func (m *NonceManager) ensureDirs() error {
	for _, d := range []string{m.dir, m.locks} {
		if err := fsx.MkdirAll(d, 0o700); err != nil {
			if fsx.IsReadOnly(err) {
				return errWrap(CodeStateCorrupt, "nonce directory is read-only", err)
			}
			return errWrap(CodeStateCorrupt, "cannot create nonce directory", err)
		}
	}
	return nil
}

// ── derivation ────────────────────────────────────────────────────────────────

// NextNonce is the pure derivation (§5.6), exported for tests:
//
//	NextNonce = max(chainPending, localNext, journalNext)
//
// where localNext is the cached next value (0 if no cache) and journalNext =
// max(nonce over ALL non-failed records that consumed an on-chain nonce) + 1 (0 if
// no such records). Folding over terminal records too makes "the journal is the
// source of truth for nonces" literally true: a consumed nonce can never be
// re-allocated even when the cache is stale and the RPC lags. It reads under the
// JOURNAL lock only (via store.read) — callers that also need exclusivity hold the
// account lock first (AcquireNonce), preserving account→journal ordering.
func (m *NonceManager) NextNonce(ctx context.Context, chainID uint64, addr common.Address, chainPending uint64) (uint64, error) {
	journalNext, _, err := m.journalNext(ctx, chainID, addr)
	if err != nil {
		return 0, err
	}
	localNext, _, err := m.readCache(chainID, addr)
	if err != nil {
		return 0, err
	}
	return maxU64(chainPending, localNext, journalNext), nil
}

// journalNext folds the journal for addr on chainID and returns (next, hasInFlight)
// where next = max(consumed nonce)+1 over all non-failed records, and hasInFlight is
// true if any non-terminal record exists (used to decide whether a chainPending
// jump is a single-writer violation vs. normal chain progress). next is 0 when no
// record consumed a nonce.
func (m *NonceManager) journalNext(ctx context.Context, chainID uint64, addr common.Address) (next uint64, hasInFlight bool, err error) {
	var maxNonce uint64
	var any bool
	rerr := m.store.read(ctx, chainID, func(latest map[string]*Record) {
		for _, r := range latest {
			if common.HexToAddress(r.From) != addr {
				continue
			}
			if !r.Status.consumesNonce() {
				continue // a failed (refused-broadcast) record never burned the nonce
			}
			any = true
			if r.Nonce >= maxNonce {
				maxNonce = r.Nonce
			}
			if !r.Status.IsTerminal() {
				hasInFlight = true
			}
		}
	})
	if rerr != nil {
		return 0, false, rerr
	}
	if !any {
		return 0, hasInFlight, nil
	}
	return maxNonce + 1, hasInFlight, nil
}

// ── lease lifecycle ───────────────────────────────────────────────────────────

// AcquireNonce takes the ACCOUNT lock (bounded by lockTimeout → state.lock_timeout
// exit 11), runs restart reconciliation implicitly by folding the journal, computes
// NextNonce, and returns a Lease holding the lock (§5.6). When forced != nil it pins
// --nonce N: derivation is bypassed but the lock is still taken (and the caller still
// journals). chainPending is supplied by the caller (service reads cc.Nonce(addr,
// pending=true)); the manager never dials the chain itself (it is a provider with no
// chain seam — service composes that).
//
// Lock ordering: this account lock is taken FIRST; the journal fold inside takes the
// (shared) journal lock SECOND. No path inverts that, so a status/list query (journal
// lock only) can never deadlock against an in-flight AcquireNonce.
func (m *NonceManager) AcquireNonce(ctx context.Context, chainID uint64, addr common.Address, chainPending uint64, forced *uint64, lockTimeout time.Duration) (*Lease, error) {
	if err := m.ensureDirs(); err != nil {
		return nil, err
	}
	if lockTimeout <= 0 {
		lockTimeout = 30 * time.Second
	}
	lctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lctx, m.accountLockBase(chainID, addr))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, errJournal(CodeStateLockTimeout, "timed out acquiring the account lock; another daxie process may be sending from this account")
		}
		return nil, errWrap(CodeStateLockTimeout, "cannot acquire the account lock", err)
	}

	// From here on, any error path must release the lock (the lease is not yet
	// returned to the caller, so its defer cannot run for us).
	var nonce uint64
	if forced != nil {
		nonce = *forced
	} else {
		journalNext, hasInFlight, jerr := m.journalNext(ctx, chainID, addr)
		if jerr != nil {
			unlock()
			return nil, jerr
		}
		localNext, _, cerr := m.readCache(chainID, addr)
		if cerr != nil {
			unlock()
			return nil, cerr
		}
		// Single-writer-violation detection (§5.6): chainPending ahead of the local
		// view with no in-flight records means another writer (or a foreign tx)
		// advanced the account. Warn once and adopt the chain value (which max()
		// already does); we only emit the diagnostic.
		if chainPending > journalNext && chainPending > localNext && !hasInFlight {
			_, _ = fmt.Fprintf(m.store.violationWriter(),
				"daxie: nonce: chain pending nonce %d for %s exceeds the local view (journal %d, cache %d); adopting the chain value (single-writer rule may be violated)\n",
				chainPending, addr.Hex(), journalNext, localNext)
		}
		nonce = maxU64(chainPending, localNext, journalNext)
	}

	return &Lease{
		nonce:   nonce,
		unlock:  unlock,
		mgr:     m,
		chainID: chainID,
		addr:    addr,
	}, nil
}

// Lease holds the account lock for one send (§5.6). Exactly one of Commit/Release
// runs for the live process (service's defer guarantees it); the §5.1 reconciliation
// handles the crashed process. Calling either twice is a no-op after the first.
type Lease struct {
	nonce    uint64
	unlock   func()
	mgr      *NonceManager
	chainID  uint64
	addr     common.Address
	finished bool
}

// Nonce is the allocated nonce.
func (l *Lease) Nonce() uint64 { return l.nonce }

// Commit writes next = nonce+1 to the nonce cache and releases the lock (§5.1). It
// is called on accepted / already-known / ours-mined-race / transport-exhausted: any
// outcome where the bytes may have reached the mempool, so the nonce is spent. The
// journal is the source of truth; this cache write is an accelerator, so a cache
// write failure releases the lock and is non-fatal to correctness (the next
// derivation re-folds the journal) — but it is surfaced so a wedged FS is visible.
func (l *Lease) Commit() error {
	if l.finished {
		return nil
	}
	l.finished = true
	defer l.unlock()
	return l.mgr.writeCache(l.chainID, l.addr, l.nonce+1)
}

// Release frees the lock WITHOUT committing (the nonce cache is untouched) — the
// pre-sign-failure / permanently-rejected path (§5.1). A refused broadcast never
// burns the nonce. Idempotent.
func (l *Lease) Release() error {
	if l.finished {
		return nil
	}
	l.finished = true
	l.unlock()
	return nil
}

// ── nonce cache I/O ───────────────────────────────────────────────────────────

// readCache returns the cached next nonce for (chain, account). A missing cache
// reads as (0, false) — a fresh install with no local view. A present-but-unparseable
// cache is treated as state.corrupt: it is the accelerator, but a garbage cache is a
// tamper/FS tripwire the caller should see (derivation would still be safe via the
// journal, but we surface the corruption rather than silently trust 0).
func (m *NonceManager) readCache(chainID uint64, addr common.Address) (next uint64, present bool, err error) {
	path := m.cachePath(chainID, addr)
	data, rerr := os.ReadFile(path) // #nosec G304 -- per-account nonce cache under the state dir
	if rerr != nil {
		if errors.Is(rerr, os.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, errWrap(CodeStateCorrupt, "cannot read nonce cache", rerr)
	}
	var c nonceCache
	if jerr := json.Unmarshal(data, &c); jerr != nil {
		return 0, false, errWrap(CodeStateCorrupt, "nonce cache is corrupt", jerr)
	}
	return c.Next, true, nil
}

// writeCache atomically writes the next-nonce accelerator for (chain, account) via
// fsx.WriteAtomic (temp+fsync+rename), perms 0600.
func (m *NonceManager) writeCache(chainID uint64, addr common.Address, next uint64) error {
	c := nonceCache{
		V:       1,
		ChainID: chainID,
		Account: strings.ToLower(addr.Hex()),
		Next:    next,
		TS:      m.clock().UTC().Format(time.RFC3339Nano),
	}
	b, merr := json.Marshal(&c)
	if merr != nil {
		return errWrap(CodeStateCorrupt, "cannot encode nonce cache", merr)
	}
	if werr := fsx.WriteAtomic(m.cachePath(chainID, addr), b, 0o600); werr != nil {
		if fsx.IsReadOnly(werr) {
			return errWrap(CodeStateCorrupt, "nonce cache is read-only", werr)
		}
		return errWrap(CodeStateCorrupt, "cannot write nonce cache", werr)
	}
	return nil
}

// maxU64 returns the maximum of its arguments (the §5.6 NextNonce fold).
func maxU64(vs ...uint64) uint64 {
	var m uint64
	for _, v := range vs {
		if v > m {
			m = v
		}
	}
	return m
}
