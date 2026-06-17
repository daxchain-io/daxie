package policy

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
	"github.com/ethereum/go-ethereum/common"
)

// reservation states (§5.1 lifecycle). A reservation is born "reserved" (the
// durable pre-sign debit), promoted to "committed" once the signed bytes reach
// the chain, or rolled back to "released" on a pre-sign / permanently-rejected
// failure. Only "reserved" reservations are orphans the reconciliation resolves.
const (
	stateReserved  = "reserved"
	stateCommitted = "committed"
	stateReleased  = "released"
)

// Reservation is the durable spend reservation (§5.1). The shape is REAL in M3:
// service persists ID into the journal `reservation_id`, and the §5.1
// reconciliation resolves the id back via journal.ByReservation. M4 ADDS fields
// (the per-account rolling-24h window bucket key, the actual-vs-worst delta
// accounting, the policy generation nonce) WITHOUT removing or renaming any field
// here — the contract is frozen.
//
// All wei quantities are decimal strings (no float, §2.5; survive >2^53).
type Reservation struct {
	ID           string         `json:"id"`                       // ULID (policy-generated; provider, entropy OK)
	Account      common.Address `json:"account"`                  // the signing account
	Dest         common.Address `json:"dest"`                     // the resolved recipient/spender
	SpendWei     string         `json:"spend_wei"`                // native value moved (decimal)
	MaxGasWei    string         `json:"max_gas_wei"`              // worst-case gasLimit × maxFeePerGas (decimal)
	State        string         `json:"state"`                    // reserved | committed | released
	Hash         string         `json:"hash,omitempty"`           // set on Commit(hash)
	ActualGasWei *string        `json:"actual_gas_wei,omitempty"` // set on SettleActual (down-only)
	TS           string         `json:"ts"`                       // RFC3339Nano (UTC) from the injected clock

	// ── M4 additive fields (no rename, no removal — the contract is frozen) ──
	Network     string `json:"network,omitempty"`      // per-network bucket key (mainnet vs an L2)
	PolicyNonce uint64 `json:"policy_nonce,omitempty"` // §4.6 rollback tripwire generation

	// ── transient (never persisted) cross-link fields ──
	skipReserve bool   // a permit: allowed, gasless, never reserves (no record written)
	entryID     string // the counter entry id this reservation debits (RBF: the superseded entry)
}

// reservationsDir is the policy sub-dir holding the durable reservation log.
func (e *Engine) reservationsDir() string { return filepath.Join(e.dir, "policy") }

// reservationsPath is the single JSONL reservation log. One line per mutation;
// last-wins-per-id on read (the same fold the journal uses, §5.6) so a Commit /
// Release is an append, never an in-place edit — torn writes can never corrupt an
// earlier record. The file is rewritten compacted (latest-per-id) on each
// mutation under the lock, so it stays small (the stub's working set is the
// in-flight reservations; terminal entries are pruned at write time).
func (e *Engine) reservationsPath() string {
	return filepath.Join(e.reservationsDir(), "reservations.jsonl")
}

// lockPath is the policy RESERVATION-LOG flock sibling. All reservation-log
// mutations and reads of the orphan set serialize on this one global lock so
// concurrent daxie processes (or N MCP tool calls) never interleave a
// read-modify-write of the JSONL log. The COUNTER (rolling-24h window) uses a
// separate per-NETWORK lock (counter.go withNetworkLock, §4.1) because the daily
// limit is aggregate across all accounts on a network; the two lock domains are
// disjoint and never nested in the opposite order.
func (e *Engine) lockPath() string {
	return filepath.Join(e.dir, "locks", "policy")
}

// lockTimeout bounds reservation lock acquisition. A timeout maps to
// state.lock_timeout (exit 11) — contention, retryable.
const reservationLockTimeout = 30 * time.Second

// withLock runs fn while holding the exclusive policy flock, mapping a lock
// timeout to state.lock_timeout. It MkdirAll's the locks dir first so the .lock
// sibling can be created (lazy, §7.3 — nothing exists until the first Reserve).
func (e *Engine) withLock(ctx context.Context, fn func() error) error {
	if err := fsx.MkdirAll(filepath.Dir(e.lockPath()), 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.New(domain.CodeConfigReadOnly,
				"the state directory is read-only; policy reservations cannot be written")
		}
		return domain.Wrap("state.corrupt", "cannot create the policy locks directory", err)
	}
	lctx, cancel := context.WithTimeout(ctx, reservationLockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lctx, e.lockPath())
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return domain.New(domain.CodeStateLockTimeout,
				"timed out acquiring the policy lock; another daxie process may be holding it")
		}
		return domain.New(domain.CodeStateLockTimeout, "cannot acquire the policy lock: "+err.Error())
	}
	defer unlock()
	return fn()
}

// loadAll reads the reservation log and folds it to the latest record per id
// (last-wins, §5.6). A missing file reads as empty (fresh install, lazy). A torn
// final line is tolerated (dropped) the same way the journal tolerates a crash
// mid-append — every complete prior line is a durable record. The caller MUST
// hold the policy lock.
func (e *Engine) loadAll() (map[string]*Reservation, []string, error) {
	path := e.reservationsPath()
	b, err := os.ReadFile(path) // #nosec G304 -- path is the fixed reservations log under the state dir
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]*Reservation{}, nil, nil
		}
		return nil, nil, domain.Wrap("state.corrupt", "cannot read the policy reservation log", err)
	}

	lines := splitLines(b)
	// The index of the last non-empty line — the only line a crash mid-append can
	// tear (one write(2) per line). An unparseable line at that index is dropped;
	// an unparseable interior line is real corruption.
	lastNonEmpty := -1
	for i := len(lines) - 1; i >= 0; i-- {
		if len(lines[i]) > 0 {
			lastNonEmpty = i
			break
		}
	}

	byID := map[string]*Reservation{}
	var order []string // first-seen order of ids, for stable compaction output
	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		var r Reservation
		if jerr := json.Unmarshal(line, &r); jerr != nil {
			if i == lastNonEmpty {
				continue // tolerable torn final write
			}
			return nil, nil, domain.Wrap("state.corrupt",
				"the policy reservation log is corrupt (an interior line is not valid JSON)", jerr)
		}
		if r.ID == "" {
			continue
		}
		if _, seen := byID[r.ID]; !seen {
			order = append(order, r.ID)
		}
		rr := r
		byID[r.ID] = &rr
	}
	return byID, order, nil
}

// appendAndCompact rewrites the reservation log compacted to latest-per-id, with
// terminal+old entries pruned, plus the supplied mutated record. It writes the
// whole file via fsx.WriteAtomic (0600) — a process killed mid-write leaves the
// prior log intact (never torn), and the in-flight working set is small. The
// caller MUST hold the policy lock.
//
// Pruning rule: a "released" reservation, and a "committed" one that has been
// settled (ActualGasWei set), is terminal — it is dropped on the next compaction
// (the journal is the permanent audit record; reservations are a working set,
// §4.4). "reserved" and unsettled "committed" entries are always kept so the
// orphan surface and SettleActual can still find them.
func (e *Engine) appendAndCompact(byID map[string]*Reservation, order []string, mutated *Reservation) error {
	if err := fsx.MkdirAll(e.reservationsDir(), 0o700); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.New(domain.CodeConfigReadOnly,
				"the state directory is read-only; policy reservations cannot be written")
		}
		return domain.Wrap("state.corrupt", "cannot create the policy reservations directory", err)
	}

	// Splice the mutated record into the fold, preserving first-seen order and
	// appending a brand-new id at the end.
	if _, seen := byID[mutated.ID]; !seen {
		order = append(order, mutated.ID)
	}
	byID[mutated.ID] = mutated

	var buf []byte
	for _, id := range order {
		r := byID[id]
		if r == nil {
			continue
		}
		if isTerminal(r) && r.ID != mutated.ID {
			// Drop terminal entries on compaction — except never drop the record we
			// just mutated this call (so a Release/SettleActual is observable to the
			// immediate follow-up reader before the NEXT compaction removes it).
			continue
		}
		b, err := json.Marshal(r)
		if err != nil {
			return domain.Wrap("state.corrupt", "cannot encode a policy reservation", err)
		}
		buf = append(buf, b...)
		buf = append(buf, '\n')
	}

	if err := fsx.WriteAtomic(e.reservationsPath(), buf, 0o600); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.New(domain.CodeConfigReadOnly,
				"the state directory is read-only; policy reservations cannot be written")
		}
		return domain.Wrap("state.corrupt", "cannot write the policy reservation log", err)
	}
	return nil
}

// isTerminal reports whether a reservation is finished and droppable on the next
// compaction: released, or committed-and-settled.
func isTerminal(r *Reservation) bool {
	if r.State == stateReleased {
		return true
	}
	if r.State == stateCommitted && r.ActualGasWei != nil {
		return true
	}
	return false
}

// newReservation builds a fresh {state:reserved} record from a Check, stamping
// the id and ts from the injected clock.
func (e *Engine) newReservation(c Check) Reservation {
	now := e.now()
	return Reservation{
		ID:        ulid(now),
		Account:   c.Account,
		Dest:      c.Dest,
		SpendWei:  weiString(c.spendWei()),
		MaxGasWei: weiString(c.maxGasWei()),
		State:     stateReserved,
		TS:        now.UTC().Format(time.RFC3339Nano),
		Network:   c.Network,
	}
}

// weiString renders a *big.Int as a base-10 string (nil → "0").
func weiString(v *big.Int) string {
	if v == nil {
		return "0"
	}
	return v.String()
}

// now returns the engine's clock time (injected, deterministic in tests).
func (e *Engine) now() time.Time { return e.clock() }

// ── tiny JSONL line helpers (shared by loadAll) ──────────────────────────────

// splitLines splits b on '\n' WITHOUT a trailing empty element, returning the
// raw byte slices (no copy). It is the read half of the one-line-per-write JSONL
// discipline.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		// A final line with no trailing newline — a torn write. Keep it; loadAll
		// decides whether it parses.
		out = append(out, b[start:])
	}
	return out
}
