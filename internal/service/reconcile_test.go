package service

import (
	"context"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/policy"
	"github.com/ethereum/go-ethereum/common"
)

// reconcile_test.go proves the §5.1 reconciliation discriminator: a reserved
// orphan whose journal record is still `signed` (no recorded broadcast) is
// RELEASED; one whose record shows a recorded broadcast is COMMITTED. Crashes only
// ever under-spend (the safe direction).

// craftOrphan writes a reservation + a journal record at the given status, mimicking
// a crash that left a `reserved` orphan. It returns the reservation id.
func craftOrphan(t *testing.T, svc *Service, from, to common.Address, status journal.Status) string {
	t.Helper()
	ctx := context.Background()
	r, err := svc.policy.Reserve(ctx, policy.Check{
		Account:   from,
		Dest:      to,
		SpendWei:  bigOrZero("1000"),
		MaxGasWei: bigOrZero("2000"),
		Kind:      string(journal.KindETHTransfer),
	})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	rec := &journal.Record{
		V:               1,
		ChainID:         1,
		Network:         "mainnet",
		Kind:            journal.KindETHTransfer,
		Status:          status,
		Source:          "cli",
		From:            from.Hex(),
		To:              to.Hex(),
		Nonce:           0,
		TxHash:          common.HexToHash("0xfeed").Hex(),
		RawTx:           "0x02aabb",
		ValueWei:        "1000",
		ReservationID:   r.ID,
		WorstCaseGasWei: "2000",
	}
	if err := svc.journal.Append(ctx, rec); err != nil {
		t.Fatalf("Append: %v", err)
	}
	return r.ID
}

func TestReconcile_SignedRecord_ReleasesReservation(t *testing.T) {
	from, to := someAddr(60), someAddr(61)
	svc, _, _ := sendService(t, from)

	id := craftOrphan(t, svc, from, to, journal.StatusSigned)

	// Before: the reservation is a reserved orphan.
	orphans, _ := svc.policy.Orphans(context.Background())
	if !containsReservation(orphans, id) {
		t.Fatal("setup: reservation should be a reserved orphan")
	}

	if err := svc.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// After: the `signed` record (no recorded broadcast) ⇒ released ⇒ no longer an
	// orphan.
	orphans2, _ := svc.policy.Orphans(context.Background())
	if containsReservation(orphans2, id) {
		t.Error("a signed-record reservation must be RELEASED by reconciliation (no recorded broadcast)")
	}
}

func TestReconcile_BroadcastRecord_CommitsReservation(t *testing.T) {
	from, to := someAddr(62), someAddr(63)
	svc, _, _ := sendService(t, from)

	id := craftOrphan(t, svc, from, to, journal.StatusBroadcast)

	if err := svc.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// A `broadcast` record ⇒ the spend happened ⇒ committed ⇒ no longer a reserved
	// orphan (committed reservations are not returned by Orphans).
	orphans, _ := svc.policy.Orphans(context.Background())
	if containsReservation(orphans, id) {
		t.Error("a broadcast-record reservation must be COMMITTED by reconciliation (recorded broadcast)")
	}
	// And committing it again must be idempotent (no error) — proving it is in the
	// committed state, not released.
	if err := svc.policy.Commit(context.Background(), id, common.HexToHash("0xfeed")); err != nil {
		t.Errorf("re-Commit of a committed reservation should be idempotent, got %v", err)
	}
}

func TestReconcile_NoRecord_ReleasesReservation(t *testing.T) {
	from, to := someAddr(64), someAddr(65)
	svc, _, _ := sendService(t, from)

	// A reservation with NO journal record at all (the crash happened between
	// Reserve and Append) ⇒ no recorded broadcast ⇒ released.
	r, err := svc.policy.Reserve(context.Background(), policy.Check{
		Account: from, Dest: to, SpendWei: bigOrZero("1"), MaxGasWei: bigOrZero("1"),
	})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := svc.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	orphans, _ := svc.policy.Orphans(context.Background())
	if containsReservation(orphans, r.ID) {
		t.Error("a reservation with no journal record must be RELEASED (crash before Append)")
	}
}

// TestReconcile_RunsAtOpen proves Open wires the reconciliation bridge: an orphan
// left by a "previous process" is resolved when a NEW service opens on the same
// state dir.
func TestReconcile_RunsAtOpen(t *testing.T) {
	from, to := someAddr(66), someAddr(67)
	// First process: craft a signed orphan, then "crash" (just stop using svc).
	svc, _, _ := sendService(t, from)
	id := craftOrphan(t, svc, from, to, journal.StatusSigned)
	_ = svc.Close()

	// Second process on the SAME state dir (the env vars persist within the test).
	svc2, err := Open(context.Background(), Options{})
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	t.Cleanup(func() { _ = svc2.Close() })
	svc2.chains = &stubProvider{cc: fake.New()}

	// Open already ran reconcile: the signed orphan is released.
	orphans, _ := svc2.policy.Orphans(context.Background())
	if containsReservation(orphans, id) {
		t.Error("Open must run reconciliation; the signed orphan should be released")
	}
}

func containsReservation(rs []policy.Reservation, id string) bool {
	for _, r := range rs {
		if r.ID == id {
			return true
		}
	}
	return false
}
