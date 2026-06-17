package journal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/daxchain-io/daxie/internal/fsx"
)

// lockTimeout bounds every journal flock acquisition. Exceeding it maps to
// state.lock_timeout (exit 11). It mirrors the keystore lock's bounded wait; the
// nonce manager applies the caller-supplied tx.lock-timeout to the ACCOUNT lock
// (the long-held one), while the journal flock is held only for one fold+write and
// so uses this short internal bound.
const lockTimeout = 30 * time.Second

// Store is the per-process journal handle (§5.6). It holds no long-lived fd: every
// mutation acquires the journal flock for the target chain, opens the file fresh by
// path (O_APPEND), folds the current max seq, writes one line, fsyncs, and releases.
// This is the property that lets an append land in the live file even after another
// process compaction-renamed the old inode. Reads fold latest-per-id.
type Store struct {
	dir   string           // <stateDir>/journal
	locks string           // <stateDir>/locks
	clock func() time.Time // record timestamp source (the service's injected clock)

	// warn / warnViolation route the non-fatal torn/corrupt-line and the
	// single-writer-violation diagnostics. They are per-Store (not package
	// globals) so the cli frontend can repoint them and parallel tests never race
	// on shared mutable state. A nil sink falls back to os.Stderr via warnWriter /
	// violationWriter.
	warn          io.Writer
	warnViolation io.Writer
}

// warnWriter returns the torn/corrupt-line warning sink, defaulting to os.Stderr.
func (s *Store) warnWriter() io.Writer {
	if s.warn != nil {
		return s.warn
	}
	return os.Stderr
}

// violationWriter returns the single-writer-violation warning sink, defaulting to
// os.Stderr. The nonce manager routes its warning through here so a Store and its
// NonceManager share one diagnostic destination.
func (s *Store) violationWriter() io.Writer {
	if s.warnViolation != nil {
		return s.warnViolation
	}
	return os.Stderr
}

// SetWarnSinks repoints both diagnostic sinks (torn/corrupt line + single-writer
// violation). The cli frontend calls this to route journal warnings into its
// stderr router; tests call it to capture them. A nil writer restores os.Stderr.
func (s *Store) SetWarnSinks(warn, violation io.Writer) {
	s.warn = warn
	s.warnViolation = violation
}

// Open binds the store to <stateDir>/journal and <stateDir>/locks. It is LAZY: it
// creates no directories or files until the first append (§7.3 — a fresh install
// reads as empty). clock supplies record timestamps; passing it in keeps `ts`
// deterministic under the service test clock. A nil clock defaults to time.Now (a
// provider may read the wall clock; only service/domain are determinism-guarded).
func Open(stateDir string, clock func() time.Time) (*Store, error) {
	if stateDir == "" {
		return nil, errJournal(CodeStateCorrupt, "journal: empty state dir")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Store{
		dir:   filepath.Join(stateDir, "journal"),
		locks: filepath.Join(stateDir, "locks"),
		clock: clock,
	}, nil
}

// Close is a no-op flush — the store keeps no long-lived fd (§5.6). It exists for
// the Service.Close lifecycle symmetry.
func (s *Store) Close() error { return nil }

// ── path helpers ────────────────────────────────────────────────────────────────

// filePath is <stateDir>/journal/<chainID>.jsonl (one append-only file per chain).
func (s *Store) filePath(chainID uint64) string {
	return filepath.Join(s.dir, fmt.Sprintf("%d.jsonl", chainID))
}

// lockPath is the sidecar lock object for a chain's journal file. fsx.Lock appends
// the ".lock" suffix itself, so this returns the BASE path it locks against. Using a
// dedicated sidecar under <stateDir>/locks (not the data file) keeps lock continuity
// across the compaction temp+rename (§7.9).
func (s *Store) lockPath(chainID uint64) string {
	return filepath.Join(s.locks, fmt.Sprintf("journal-%d.lock", chainID))
}

// ensureDirs creates <stateDir>/journal and <stateDir>/locks (owner-only) before the
// first write. A read-only target maps to state.corrupt — the journal is a state
// class whose unwritability is unrecoverable for a signing op (the caller surfaces
// it before any spend).
func (s *Store) ensureDirs() error {
	for _, d := range []string{s.dir, s.locks} {
		if err := fsx.MkdirAll(d, 0o700); err != nil {
			if fsx.IsReadOnly(err) {
				return errWrap(CodeStateCorrupt, "journal directory is read-only", err)
			}
			return errWrap(CodeStateCorrupt, "cannot create journal directory", err)
		}
	}
	return nil
}

// withLock runs fn while holding the EXCLUSIVE journal flock for chainID, bounded by
// lockTimeout. A timeout maps to state.lock_timeout (exit 11). Lock ordering is
// always account-lock → journal-lock (binding, §5.6): every caller that also holds
// an account lock takes it FIRST, so a status/list query (journal lock only) never
// deadlocks against an in-flight send.
func (s *Store) withLock(ctx context.Context, chainID uint64, fn func() error) error {
	if err := s.ensureDirs(); err != nil {
		return err
	}
	lctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lctx, s.lockPath(chainID))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return errJournal(CodeStateLockTimeout, "timed out acquiring the journal lock; another daxie process may be holding it")
		}
		return errWrap(CodeStateLockTimeout, "cannot acquire the journal lock", err)
	}
	defer unlock()
	return fn()
}

// ── mutations ───────────────────────────────────────────────────────────────────

// Append writes rec as a new line under the journal flock for rec.ChainID, assigning
// rec.Seq = currentMaxSeq+1, rec.V, rec.ID (a fresh ULID if empty), and rec.TS from
// the clock (if empty). It is the §5.1 "journal.Append(signed, raw_tx,
// reservation_id)" call. The assigned id/seq are written back into rec. Compaction
// may run opportunistically after the write (still under the same lock).
func (s *Store) Append(ctx context.Context, rec *Record) error {
	if rec == nil {
		return errJournal(CodeStateCorrupt, "journal: nil record")
	}
	return s.withLock(ctx, rec.ChainID, func() error {
		recs, maxSeq, err := s.readAll(rec.ChainID, true)
		if err != nil {
			return err
		}
		if rec.V == 0 {
			rec.V = recordVersion
		}
		if rec.ID == "" {
			id, ierr := newULID()
			if ierr != nil {
				return errWrap(CodeStateCorrupt, "journal: cannot generate record id", ierr)
			}
			rec.ID = id
		}
		if rec.TS == "" {
			rec.TS = s.clock().UTC().Format(time.RFC3339Nano)
		}
		rec.Seq = maxSeq + 1
		if err := s.appendLine(rec.ChainID, rec); err != nil {
			return err
		}
		// +1 for the line we just appended; readAll's count is pre-write.
		return s.maybeCompact(rec.ChainID, recs, rec)
	})
}

// SetState appends a NEW line for an existing id carrying the transitioned fields
// (status + any non-nil mutation field). Every other field is copied from the prior
// latest record so a fold still reconstructs the full record. Last-wins-per-id means
// a query folds to this latest line. It backs "journal SetState(broadcast)" /
// SetState(failed) / mined / confirmed / replaced (§5.1). An unknown id is
// ErrNotFound.
func (s *Store) SetState(ctx context.Context, chainID uint64, id string, mut StateMutation) error {
	if id == "" {
		return errJournal(CodeStateCorrupt, "journal: empty id in SetState")
	}
	return s.withLock(ctx, chainID, func() error {
		recs, maxSeq, err := s.readAll(chainID, true)
		if err != nil {
			return err
		}
		prior, ok := foldLatest(recs)[id]
		if !ok {
			return fmt.Errorf("%w: id %s on chain %d", ErrNotFound, id, chainID)
		}
		next := prior.clone()
		mut.applyTo(next)
		next.Seq = maxSeq + 1
		next.TS = s.clock().UTC().Format(time.RFC3339Nano)
		if err := s.appendLine(chainID, next); err != nil {
			return err
		}
		return s.maybeCompact(chainID, recs, next)
	})
}

// StateMutation is the set of fields a SetState transition may change; the rest are
// copied from the prior latest record. A nil pointer leaves that field unchanged
// (e.g. SetState(broadcast) sets Status + TxHash but leaves Receipt nil until mined).
// Status is always required (the zero "" Status would be invalid; callers pass the
// target status explicitly).
type StateMutation struct {
	Status     Status
	TxHash     *string
	Receipt    *Receipt
	ReplacedBy *string
	Replaces   *string
	Error      *string
}

// applyTo mutates dst with the non-nil fields of m. Status is always applied (a
// SetState always names the target status). The receipt/error pointers are applied
// as-given so a caller can explicitly clear (set to a pointer-to-empty) — but the
// common path only ever SETS them, never clears.
func (m StateMutation) applyTo(dst *Record) {
	if m.Status != "" {
		dst.Status = m.Status
	}
	if m.TxHash != nil {
		dst.TxHash = *m.TxHash
	}
	if m.Receipt != nil {
		dst.Receipt = m.Receipt
	}
	if m.ReplacedBy != nil {
		dst.ReplacedBy = m.ReplacedBy
	}
	if m.Replaces != nil {
		dst.Replaces = m.Replaces
	}
	if m.Error != nil {
		dst.Error = m.Error
	}
}

// ── queries (all fold latest-per-id) ──────────────────────────────────────────────

// ByReservation returns the latest record for reservationID on chainID, or
// ErrNotFound. CHAIN-SCOPED: the §5.1 reconciliation reads each reservation's
// journal record per chain. Reads take only the journal flock (never an account
// lock — the §5.6 deadlock-free rule).
func (s *Store) ByReservation(ctx context.Context, chainID uint64, reservationID string) (*Record, error) {
	var found *Record
	err := s.read(ctx, chainID, func(latest map[string]*Record) {
		for _, r := range latest {
			if r.ReservationID == reservationID {
				if found == nil || r.Seq > found.Seq {
					found = r
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("%w: reservation %s on chain %d", ErrNotFound, reservationID, chainID)
	}
	return found, nil
}

// ByHash returns the latest record for a tx hash on chainID, or ErrNotFound. It
// backs tx status/wait/speedup/cancel. Comparison is on the canonical lowercase hex.
func (s *Store) ByHash(ctx context.Context, chainID uint64, hash common.Hash) (*Record, error) {
	want := hash.Hex()
	var found *Record
	err := s.read(ctx, chainID, func(latest map[string]*Record) {
		for _, r := range latest {
			if common.HexToHash(r.TxHash) == common.HexToHash(want) && r.TxHash != "" {
				if found == nil || r.Seq > found.Seq {
					found = r
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("%w: hash %s on chain %d", ErrNotFound, want, chainID)
	}
	return found, nil
}

// ByID returns the latest record for a journal id on chainID, or ErrNotFound. It
// backs the deferred-abort status re-read (§5.1): the kernel holds the journal id
// and must learn whether settle already recorded a broadcast before deciding
// whether the abort may terminalize the record. Reads take only the journal flock.
func (s *Store) ByID(ctx context.Context, chainID uint64, id string) (*Record, error) {
	var found *Record
	err := s.read(ctx, chainID, func(latest map[string]*Record) {
		if r, ok := latest[id]; ok {
			found = r
		}
	})
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, fmt.Errorf("%w: id %s on chain %d", ErrNotFound, id, chainID)
	}
	return found, nil
}

// Unresolved returns every non-terminal record on chainID (status NOT in
// {confirmed, reverted, replaced, failed}) — the restart-reconciliation worklist
// (§5.6). Newest-first by seq. A fresh/empty journal returns an empty slice, nil.
func (s *Store) Unresolved(ctx context.Context, chainID uint64) ([]*Record, error) {
	var out []*Record
	err := s.read(ctx, chainID, func(latest map[string]*Record) {
		for _, r := range latest {
			if !r.Status.IsTerminal() {
				out = append(out, r)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	sortBySeqDesc(out)
	return out, nil
}

// List returns latest-per-id records on chainID filtered by `from` (the zero address
// = all accounts), newest-first — it backs `tx list`. Terminal records are KEPT (the
// journal IS the history). A fresh/empty journal returns an empty slice, nil.
func (s *Store) List(ctx context.Context, chainID uint64, from common.Address) ([]*Record, error) {
	all := from == (common.Address{})
	var out []*Record
	err := s.read(ctx, chainID, func(latest map[string]*Record) {
		for _, r := range latest {
			if all || common.HexToAddress(r.From) == from {
				out = append(out, r)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	sortBySeqDesc(out)
	return out, nil
}

// read folds the chain's journal under a SHARED journal lock and hands the
// latest-per-id map to fn. A missing file (fresh install) folds to empty. Reads take
// the shared lock so a concurrent compaction's temp+rename never tears a read (§7.9).
func (s *Store) read(ctx context.Context, chainID uint64, fn func(latest map[string]*Record)) error {
	if err := s.ensureDirs(); err != nil {
		return err
	}
	lctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	unlock, err := fsx.RLock(lctx, s.lockPath(chainID))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return errJournal(CodeStateLockTimeout, "timed out acquiring the journal read lock")
		}
		return errWrap(CodeStateLockTimeout, "cannot acquire the journal read lock", err)
	}
	defer unlock()
	recs, _, rerr := s.readAll(chainID, false)
	if rerr != nil {
		return rerr
	}
	fn(foldLatest(recs))
	return nil
}

// foldLatest reduces a seq-ordered slice of records to the latest line per id
// (last-wins-per-id, §5.6). A higher seq always wins, so a torn mid-file line that
// was skipped only costs at most one transition (re-derivable from the chain).
func foldLatest(recs []*Record) map[string]*Record {
	latest := make(map[string]*Record, len(recs))
	for _, r := range recs {
		if cur, ok := latest[r.ID]; !ok || r.Seq >= cur.Seq {
			latest[r.ID] = r
		}
	}
	return latest
}

// sortBySeqDesc orders records newest-first (highest seq first), the stable order
// `tx list` / Unresolved present.
func sortBySeqDesc(rs []*Record) {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Seq > rs[j].Seq })
}
