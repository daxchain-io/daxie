package policy

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
	"github.com/ethereum/go-ethereum/common"
)

// counter.go is the §4.4 per-(network, account) spend counter — the rolling-24h
// window accumulator. It lives at $DAXIE_STATE_DIR/spend/<network>/<from>.json,
// one logical entry per (from, account_nonce) with candidates[] for every RBF
// candidate; the wei counted is the MAX across candidates (value_wei and
// gas_max_wei independently), preferring gas_actual_wei once a receipt settles it
// (down-only). Pruning at every locked write drops entries with ts<now−24h whose
// every candidate is terminal.
//
// LIMIT SCOPE (§4.1). The daily limit is AGGREGATE-across-all-accounts on a
// network, not per account: the unit of compromise is the keystore passphrase, so
// a per-account cap would silently multiply the limit by the account count. The
// rolling-24h window therefore sums EVERY account's in-window debits, and the
// counter lock is per-NETWORK (not per-account) — one serialization point for the
// cross-account read-sum-then-reserve so two parallel sends on DIFFERENT accounts
// cannot jointly overshoot max_day (R2a, now closed by the network-scoped lock).
// The on-disk counter files stay per-account (the debit lands in the signing
// account's own file); only the lock and the window-sum are network-wide.
//
// Mutual exclusion is two-layered (§4.4): an in-process per-network mutex taken
// BEFORE the cross-process flock (so N concurrent MCP calls don't each park in a
// blocking flock syscall). Acquisition ordering, fixed: mutex → flock → read →
// mutate → write → funlock → release mutex. All readers (sumWindow/Show) take the
// SAME lock — a Daxie-internal consistency measure (Windows rename safety is
// fsx.WriteAtomic's job, §7.9). policy owns NO platform-specific code; every
// atomic write + perm goes through fsx.

// counterCandidateState mirrors the reservation states for a single RBF candidate
// within a counter entry.
const (
	candReserved  = "reserved"
	candCommitted = "committed"
	candReleased  = "released"
	candReplaced  = "replaced"
)

// counterFile is the on-disk per-(network,account) counter document (§4.4 shape).
type counterFile struct {
	Version     int            `json:"version"`
	PolicyNonce uint64         `json:"policy_nonce"`
	Network     string         `json:"network"`
	From        string         `json:"from"`
	Entries     []counterEntry `json:"entries"`
}

// counterEntry is one logical spend keyed by (from, account_nonce). candidates[]
// holds every RBF candidate for that nonce; id is the reservation ULID the
// reservation log shares (the cross-link).
type counterEntry struct {
	ID           string             `json:"id"`
	TS           string             `json:"ts"` // RFC3339(Nano) UTC of the first reserve
	AccountNonce *uint64            `json:"account_nonce,omitempty"`
	Kind         string             `json:"kind"`
	Asset        string             `json:"asset"`
	Candidates   []counterCandidate `json:"candidates"`
}

// counterCandidate is one RBF candidate's accounting within an entry.
type counterCandidate struct {
	TxHash       string  `json:"tx_hash,omitempty"`
	ValueWei     string  `json:"value_wei"`
	GasMaxWei    string  `json:"gas_max_wei"`
	GasActualWei *string `json:"gas_actual_wei"`
	State        string  `json:"state"`
}

// counterVersion is the current counter-file format version.
const counterVersion = 1

// ── lock + path plumbing ─────────────────────────────────────────────────────

// keyMu returns the in-process mutex for a network counter key, lazily created in
// the engine's sync.Map. It is taken BEFORE the flock (§4.4 ordering).
func (e *Engine) keyMu(network string) *sync.Mutex {
	k := networkKey(network)
	v, _ := e.mu.LoadOrStore(k, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// networkKey is the canonical per-network lock key (§4.1 the daily limit is
// aggregate across all accounts on a network, so the lock is network-scoped).
func networkKey(network string) string {
	return strings.ToLower(network)
}

// counterPath is the per-(network,account) counter file. The window SUM is
// network-wide (§4.1) but each account's debits land in its own file.
func (e *Engine) counterPath(network string, addr common.Address) string {
	return filepath.Join(e.dir, "spend", strings.ToLower(network), strings.ToLower(addr.Hex())+".json")
}

// counterLockPath is the per-NETWORK flock sibling base (fsx appends ".lock") —
// the single serialization point for the across-all-accounts aggregate (§4.1/R2a).
func (e *Engine) counterLockPath(network string) string {
	return filepath.Join(e.dir, "locks", "policy-net-"+networkKey(network))
}

// withNetworkLock runs fn while holding the in-process mutex AND the cross-process
// flock for the network — the §4.4 two-layered exclusion in the fixed order. This
// is the per-(network) day lock the aggregate-across-accounts cap requires (§4.1):
// it is held across read-sum-of-all-accounts + reserve so concurrent sends on
// DIFFERENT accounts cannot jointly overshoot max_day. A lock timeout maps to
// state.lock_timeout (exit 11). The locks dir is created first (lazy, §7.3).
func (e *Engine) withNetworkLock(ctx context.Context, network string, fn func() error) error {
	mu := e.keyMu(network)
	mu.Lock()
	defer mu.Unlock()

	if err := fsx.MkdirAll(filepath.Dir(e.counterLockPath(network)), 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.New(domain.CodeConfigReadOnly,
				"the state directory is read-only; policy counters cannot be written")
		}
		return domain.Wrap("policy.state_error", "cannot create the policy locks directory", err)
	}
	lctx, cancel := context.WithTimeout(ctx, reservationLockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lctx, e.counterLockPath(network))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return domain.New(domain.CodeStateLockTimeout,
				"timed out acquiring the policy network lock; another daxie process may be holding it")
		}
		return domain.New(domain.CodeStateLockTimeout, "cannot acquire the policy network lock: "+err.Error())
	}
	defer unlock()
	return fn()
}

// ── read / write ─────────────────────────────────────────────────────────────

// loadCounter reads the per-account counter file (a missing file reads as an
// empty document, lazy). An unparseable file is policy.state_error (fail-closed,
// §4.9 — counters unreadable). The caller MUST hold the account lock.
func (e *Engine) loadCounter(network string, addr common.Address) (*counterFile, error) {
	path := e.counterPath(network, addr)
	b, err := os.ReadFile(path) // #nosec G304 -- fixed per-account counter path under the state dir
	if err != nil {
		if os.IsNotExist(err) {
			return &counterFile{
				Version: counterVersion,
				Network: strings.ToLower(network),
				From:    strings.ToLower(addr.Hex()),
			}, nil
		}
		return nil, domain.WithData(
			domain.Wrap("policy.state_error", "cannot read the policy counter file", err),
			map[string]any{"path": path, "cause": err.Error()})
	}
	var cf counterFile
	if jerr := json.Unmarshal(b, &cf); jerr != nil {
		return nil, domain.WithData(
			domain.Wrap("policy.state_error", "the policy counter file is corrupt", jerr),
			map[string]any{"path": path, "cause": jerr.Error()})
	}
	if cf.Network == "" {
		cf.Network = strings.ToLower(network)
	}
	if cf.From == "" {
		cf.From = strings.ToLower(addr.Hex())
	}
	return &cf, nil
}

// writeCounter prunes terminal+old entries then atomically writes the file. The
// caller MUST hold the account lock. A read-only volume maps to config.read_only.
func (e *Engine) writeCounter(network string, addr common.Address, cf *counterFile, now time.Time) error {
	cf.Version = counterVersion
	pruneCounter(cf, now)
	path := e.counterPath(network, addr)
	if err := fsx.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.New(domain.CodeConfigReadOnly,
				"the state directory is read-only; policy counters cannot be written")
		}
		return domain.WithData(
			domain.Wrap("policy.state_error", "cannot create the policy spend directory", err),
			map[string]any{"path": path, "cause": err.Error()})
	}
	b, err := json.Marshal(cf)
	if err != nil {
		return domain.Wrap("policy.state_error", "cannot encode the policy counter file", err)
	}
	if err := fsx.WriteAtomic(path, b, 0o600); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.New(domain.CodeConfigReadOnly,
				"the state directory is read-only; policy counters cannot be written")
		}
		return domain.WithData(
			domain.Wrap("policy.state_error", "cannot write the policy counter file", err),
			map[string]any{"path": path, "cause": err.Error()})
	}
	return nil
}

// ── the rolling-24h window sum ───────────────────────────────────────────────

// sumWindow computes spentWindowWei: Σ over entries with ts > now−24h of
// (max-across-candidates value_wei + max-across-candidates gas, preferring
// gas_actual_wei when set — down-only). This is where the rolling-24h window
// POLICY lives (§4.1); Evaluate is window-agnostic. Released/replaced candidates
// still count toward the max EXCEPT a fully-released entry contributes nothing
// (its only candidates are released — over-count is the safe direction, but a
// released-before-sign reservation never spent). The caller MUST hold the lock.
func sumWindow(cf *counterFile, now time.Time) *big.Int {
	cutoff := now.Add(-24 * time.Hour)
	sum := new(big.Int)
	for i := range cf.Entries {
		e := &cf.Entries[i]
		ts := parseTS(e.TS)
		if !ts.IsZero() && ts.Before(cutoff) {
			continue
		}
		if entryAllReleased(e) {
			continue // never reached the chain ⇒ no spend
		}
		sum.Add(sum, maxValueWei(e))
		sum.Add(sum, maxGasWei(e))
	}
	return sum
}

// sumWindowExcluding is sumWindow with ONE entry omitted by id — the RBF
// superseded entry, whose envelope the daily-limit gate re-adds as max(orig,new)
// so a speedup/cancel counts only the positive gas delta and never re-counts value
// (§5.5). The caller MUST hold the network lock.
func sumWindowExcluding(cf *counterFile, now time.Time, excludeID string) *big.Int {
	cutoff := now.Add(-24 * time.Hour)
	sum := new(big.Int)
	for i := range cf.Entries {
		e := &cf.Entries[i]
		if e.ID == excludeID {
			continue
		}
		ts := parseTS(e.TS)
		if !ts.IsZero() && ts.Before(cutoff) {
			continue
		}
		if entryAllReleased(e) {
			continue
		}
		sum.Add(sum, maxValueWei(e))
		sum.Add(sum, maxGasWei(e))
	}
	return sum
}

// entryAllReleased reports whether every candidate of an entry is released (a
// pre-sign release — no spend reached the chain).
func entryAllReleased(e *counterEntry) bool {
	if len(e.Candidates) == 0 {
		return true
	}
	for _, c := range e.Candidates {
		if c.State != candReleased {
			return false
		}
	}
	return true
}

// maxValueWei is the max value_wei across an entry's non-released candidates.
func maxValueWei(e *counterEntry) *big.Int {
	max := new(big.Int)
	for _, c := range e.Candidates {
		if c.State == candReleased {
			continue
		}
		if v, ok := new(big.Int).SetString(c.ValueWei, 10); ok && v.Cmp(max) > 0 {
			max = v
		}
	}
	return max
}

// maxGasWei is the max gas across an entry's non-released candidates, preferring
// gas_actual_wei over gas_max_wei when a receipt has settled a candidate
// (down-only — the actual is never above the worst case by construction).
func maxGasWei(e *counterEntry) *big.Int {
	max := new(big.Int)
	for _, c := range e.Candidates {
		if c.State == candReleased {
			continue
		}
		g := new(big.Int)
		if c.GasActualWei != nil {
			if v, ok := new(big.Int).SetString(*c.GasActualWei, 10); ok {
				g = v
			}
		} else if v, ok := new(big.Int).SetString(c.GasMaxWei, 10); ok {
			g = v
		}
		if g.Cmp(max) > 0 {
			max = g
		}
	}
	return max
}

// ── pruning ──────────────────────────────────────────────────────────────────

// pruneCounter drops entries whose ts < now−24h AND whose every candidate is
// terminal (committed-and-settled, released, or replaced). The journal is the
// permanent audit record; counters are a working set (§4.4). An entry inside the
// window, or with any non-terminal candidate, is always kept.
func pruneCounter(cf *counterFile, now time.Time) {
	cutoff := now.Add(-24 * time.Hour)
	kept := cf.Entries[:0]
	for _, e := range cf.Entries {
		ts := parseTS(e.TS)
		old := !ts.IsZero() && ts.Before(cutoff)
		if old && allCandidatesTerminal(&e) {
			continue
		}
		kept = append(kept, e)
	}
	cf.Entries = kept
}

// allCandidatesTerminal reports whether every candidate of an entry is finished:
// released, replaced, or committed-and-settled (gas_actual recorded).
func allCandidatesTerminal(e *counterEntry) bool {
	for _, c := range e.Candidates {
		switch c.State {
		case candReleased, candReplaced:
			// terminal
		case candCommitted:
			if c.GasActualWei == nil {
				return false // committed but unsettled ⇒ keep
			}
		default:
			return false // reserved ⇒ keep
		}
	}
	return true
}

// ── entry mutation helpers (used by the engine reserve/commit/settle/release) ──

// findEntry locates the entry for a reservation id, or nil.
func (cf *counterFile) findEntry(id string) *counterEntry {
	for i := range cf.Entries {
		if cf.Entries[i].ID == id {
			return &cf.Entries[i]
		}
	}
	return nil
}

// findEntryByNonce locates the entry for an account nonce (the RBF supersession
// bucket), or nil.
func (cf *counterFile) findEntryByNonce(nonce *uint64) *counterEntry {
	if nonce == nil {
		return nil
	}
	for i := range cf.Entries {
		if cf.Entries[i].AccountNonce != nil && *cf.Entries[i].AccountNonce == *nonce {
			return &cf.Entries[i]
		}
	}
	return nil
}

// ── small shared helpers ─────────────────────────────────────────────────────

// parseTS parses an RFC3339(Nano) timestamp, returning the zero time on failure
// (a zero ts is treated as inside the window — the safe direction).
func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

// sortEntriesByTS sorts entries oldest-first (stable on-disk ordering for diffs).
func sortEntriesByTS(cf *counterFile) {
	sort.SliceStable(cf.Entries, func(i, j int) bool {
		return parseTS(cf.Entries[i].TS).Before(parseTS(cf.Entries[j].TS))
	})
}
