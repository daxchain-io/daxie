package policy

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestOrphansSurfacesOnlyReserved confirms Orphans returns exactly the
// {state:reserved} reservations — not committed, not released. This is the §5.1
// reconciliation worklist service.Open consumes.
func TestOrphansSurfacesOnlyReserved(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	// Three reservations: one left reserved (a crash), one committed, one released.
	reserved, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve reserved: %v", err)
	}
	committed, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve committed: %v", err)
	}
	if err := e.Commit(ctx, committed.ID, common.HexToHash("0xaa")); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	released, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve released: %v", err)
	}
	if err := e.Release(ctx, released.ID); err != nil {
		t.Fatalf("Release: %v", err)
	}

	orphans, err := e.Orphans(ctx)
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	if len(orphans) != 1 {
		t.Fatalf("want exactly 1 orphan (the reserved one), got %d: %+v", len(orphans), orphans)
	}
	if orphans[0].ID != reserved.ID {
		t.Fatalf("orphan id = %q, want the reserved id %q", orphans[0].ID, reserved.ID)
	}
}

// TestReconcileBroadcastRecordedCommits models the §5.1 discriminator's commit
// arm: the journal showed a recorded broadcast ⇒ service calls CommitOrphan ⇒ the
// reservation leaves the orphan set as committed.
func TestReconcileBroadcastRecordedCommits(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// Process 1: reserve, then "crash" (no commit/release).
	e1, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("Open e1: %v", err)
	}
	r, err := e1.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	// Process 2: service.Open reconciliation. The journal (resolved by service, not
	// modeled here) showed a recorded broadcast ⇒ CommitOrphan.
	e2, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("Open e2: %v", err)
	}
	orphans, err := e2.Orphans(ctx)
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	if len(orphans) != 1 {
		t.Fatalf("want 1 orphan after crash, got %d", len(orphans))
	}
	hash := common.HexToHash("0x9f1c000000000000000000000000000000000000000000000000000000000000")
	if err := e2.CommitOrphan(ctx, r.ID, hash); err != nil {
		t.Fatalf("CommitOrphan: %v", err)
	}

	// No longer an orphan; the record reflects the commit.
	orphans, err = e2.Orphans(ctx)
	if err != nil {
		t.Fatalf("Orphans after CommitOrphan: %v", err)
	}
	if len(orphans) != 0 {
		t.Fatalf("a committed orphan must leave the orphan set; got %d", len(orphans))
	}
	got := mustLoad(t, e2, r.ID)
	if got.State != stateCommitted || got.Hash != hash.Hex() {
		t.Fatalf("after CommitOrphan: state=%q hash=%q, want committed + %s", got.State, got.Hash, hash.Hex())
	}
}

// TestReconcileNoBroadcastReleases models the §5.1 discriminator's release arm:
// the journal showed NO recorded broadcast (still signed / no record) ⇒ service
// calls ReleaseOrphan ⇒ the reservation is released (crashes only under-spend).
func TestReconcileNoBroadcastReleases(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	e1, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("Open e1: %v", err)
	}
	r, err := e1.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	e2, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("Open e2: %v", err)
	}
	if err := e2.ReleaseOrphan(ctx, r.ID); err != nil {
		t.Fatalf("ReleaseOrphan: %v", err)
	}

	orphans, err := e2.Orphans(ctx)
	if err != nil {
		t.Fatalf("Orphans after ReleaseOrphan: %v", err)
	}
	if len(orphans) != 0 {
		t.Fatalf("a released orphan must leave the orphan set; got %d", len(orphans))
	}
	got := mustLoad(t, e2, r.ID)
	if got.State != stateReleased {
		t.Fatalf("after ReleaseOrphan: state=%q, want released", got.State)
	}
}

// TestCommitOrphanMatchesCommit confirms the reconcile and live paths share a body
// (a committed orphan and a committed live reservation are indistinguishable).
func TestCommitOrphanMatchesCommit(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	r, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	hash := common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555")
	if err := e.CommitOrphan(ctx, r.ID, hash); err != nil {
		t.Fatalf("CommitOrphan: %v", err)
	}
	got := mustLoad(t, e, r.ID)
	if got.State != stateCommitted || got.Hash != hash.Hex() {
		t.Fatalf("CommitOrphan did not commit: state=%q hash=%q", got.State, got.Hash)
	}
}
