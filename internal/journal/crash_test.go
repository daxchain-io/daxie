package journal

import (
	"context"
	"testing"
	"time"
)

// The crash matrix injects a fault at each §5.1 point and asserts the post-restart
// journal state lets recovery (a) never double-broadcast and (b) never double-allocate
// a nonce. The journal package cannot broadcast (no chain seam — service does), so the
// crash tests assert the JOURNAL invariants the §5.1 reconciliation discriminator and
// the nonce fold rely on:
//
//   - signed (no recorded broadcast) ⇒ the record stays `signed` with the SAME raw_tx,
//     so recovery rebroadcasts identical bytes; the nonce is folded as consumed
//     (signed consumes a nonce) so it is never re-allocated.
//   - reserved-but-killed-before-sign ⇒ no journal record at all ⇒ no nonce consumed,
//     the reservation is releasable (service drives that via policy.Orphans).
//   - broadcast recorded ⇒ folds to broadcast, nonce consumed, recovery commits.
//
// "Crash" is modeled by NOT calling the next step and re-opening a fresh Store over the
// same dir (no shared in-memory state — the journal keeps no long-lived fd, so a fresh
// Store sees exactly what a restarted process would).

// reopen returns a fresh Store + NonceManager over the same dir, simulating a process
// restart (the only durable state is on disk).
func reopen(t *testing.T, dir string) (*Store, *NonceManager) {
	t.Helper()
	s, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("reopen Open: %v", err)
	}
	m, err := NewNonceManager(dir, s)
	if err != nil {
		t.Fatalf("reopen NewNonceManager: %v", err)
	}
	return s, m
}

func TestCrashAfterAppendSignedBeforeBroadcast(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, m := reopen(t, dir)
	ctx := context.Background()

	// Live process: acquire nonce 0, append a `signed` record (raw_tx persisted),
	// then "crash" before broadcast — i.e. we DO NOT Commit the lease, DO NOT
	// SetState(broadcast). The lease lock is process-bound; a restart re-derives.
	lease, err := m.AcquireNonce(ctx, 1, testAddr, 0, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rawTx := "0x02f8b1signedbytes"
	rec := ethTransfer(1, testAddr, lease.Nonce(), "res-crash", rawTx)
	if err := s.Append(ctx, rec); err != nil {
		t.Fatal(err)
	}
	// crash: drop the lease without Commit/Release (process death). In-process we must
	// release the OS lock so the test's reopen can re-acquire; this models the OS
	// reclaiming the flock on process exit.
	_ = lease.Release()

	// Restart.
	s2, m2 := reopen(t, dir)

	// (a) The signed record survives with the SAME raw_tx — recovery rebroadcasts
	// identical bytes, never re-runs send logic.
	got, err := s2.ByReservation(ctx, 1, "res-crash")
	if err != nil {
		t.Fatalf("ByReservation after restart: %v", err)
	}
	if got.Status != StatusSigned {
		t.Errorf("status after crash = %q, want signed (no recorded broadcast)", got.Status)
	}
	if got.RawTx != rawTx {
		t.Errorf("raw_tx mutated across crash: %q, want %q", got.RawTx, rawTx)
	}

	// (b) The nonce is folded as consumed (signed consumes a nonce), so a fresh
	// acquire returns the NEXT nonce, never re-allocating 0.
	lease2, err := m2.AcquireNonce(ctx, 1, testAddr, 0, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease2.Release() }()
	if lease2.Nonce() != 1 {
		t.Errorf("post-crash nonce = %d, want 1 (signed record at 0 must not be re-allocated)", lease2.Nonce())
	}
}

func TestCrashBeforeSignNoRecordNoNonceConsumed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, m := reopen(t, dir)
	ctx := context.Background()

	// Live process: acquire nonce 0, then "crash" BEFORE sign — no journal record was
	// ever appended. (policy.Reserve would have written a durable reservation; service
	// releases it via policy.Orphans since the journal shows no record. That bridge is
	// service's; here we assert the JOURNAL side: nonce 0 is NOT consumed.)
	lease, err := m.AcquireNonce(ctx, 1, testAddr, 0, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = lease.Release() // crash: lock reclaimed, no Commit, no Append.

	_, m2 := reopen(t, dir)
	lease2, err := m2.AcquireNonce(ctx, 1, testAddr, 0, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease2.Release() }()
	if lease2.Nonce() != 0 {
		t.Errorf("post-crash nonce = %d, want 0 (no record ⇒ nonce 0 still free)", lease2.Nonce())
	}
}

func TestCrashAfterBroadcastRecorded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, m := reopen(t, dir)
	ctx := context.Background()

	// Live: acquire, append signed, SetState(broadcast) — then crash before the
	// lease Commit. The journal records the broadcast; the cache may lag.
	lease, err := m.AcquireNonce(ctx, 1, testAddr, 0, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rec := ethTransfer(1, testAddr, lease.Nonce(), "res-bc", "0xraw")
	if err := s.Append(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, 1, rec.ID, StateMutation{Status: StatusBroadcast, TxHash: strptr("0xhash")}); err != nil {
		t.Fatal(err)
	}
	_ = lease.Release() // crash before Commit: cache still says 0.

	// Restart: the cache is stale (0) but the journal shows nonce 0 consumed
	// (broadcast). The fold must still advance to 1 — proving the journal, not the
	// cache, is the source of truth and the nonce is never double-allocated.
	s2, m2 := reopen(t, dir)
	got, err := s2.ByReservation(ctx, 1, "res-bc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusBroadcast {
		t.Errorf("status = %q, want broadcast (recovery commits)", got.Status)
	}
	lease2, err := m2.AcquireNonce(ctx, 1, testAddr, 0, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease2.Release() }()
	if lease2.Nonce() != 1 {
		t.Errorf("post-crash nonce = %d, want 1 (broadcast at 0 consumed despite stale cache)", lease2.Nonce())
	}
}

func TestCrashMatrixManySequentialSendsNeverDoubleAllocate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctx := context.Background()

	// Simulate a stream of sends each interrupted at a different §5.1 point, restarting
	// between each, and assert nonces form a strict 0,1,2,… sequence with no gap and no
	// reuse. chainPending stays 0 throughout (a lagging RPC) so the journal fold is the
	// sole authority.
	wantNonce := uint64(0)
	for i := 0; i < 8; i++ {
		s, m := reopen(t, dir)
		lease, err := m.AcquireNonce(ctx, 1, testAddr, 0, nil, time.Second)
		if err != nil {
			t.Fatalf("iter %d acquire: %v", i, err)
		}
		if lease.Nonce() != wantNonce {
			t.Fatalf("iter %d nonce = %d, want %d", i, lease.Nonce(), wantNonce)
		}
		rec := ethTransfer(1, testAddr, lease.Nonce(), "res-seq-"+string(rune('a'+i)), "0xraw"+string(rune('a'+i)))
		if err := s.Append(ctx, rec); err != nil {
			t.Fatalf("iter %d append: %v", i, err)
		}
		// Interleave the §5.1 fault points across iterations.
		switch i % 3 {
		case 0:
			// crash at signed (no broadcast). Nonce still consumed (signed consumes).
			_ = lease.Release()
		case 1:
			// reach broadcast, crash before commit.
			if err := s.SetState(ctx, 1, rec.ID, StateMutation{Status: StatusBroadcast, TxHash: strptr("0xh" + string(rune('a'+i)))}); err != nil {
				t.Fatal(err)
			}
			_ = lease.Release()
		case 2:
			// clean commit.
			if err := s.SetState(ctx, 1, rec.ID, StateMutation{Status: StatusBroadcast, TxHash: strptr("0xh" + string(rune('a'+i)))}); err != nil {
				t.Fatal(err)
			}
			if err := lease.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		wantNonce++
	}

	// Final: every nonce 0..7 appears exactly once across all records.
	s, _ := reopen(t, dir)
	all, err := s.List(ctx, 1, testAddr)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint64]int{}
	for _, r := range all {
		seen[r.Nonce]++
	}
	for n := uint64(0); n < 8; n++ {
		if seen[n] != 1 {
			t.Errorf("nonce %d appeared %d times, want exactly 1 (no double-allocation, no gap)", n, seen[n])
		}
	}
}
