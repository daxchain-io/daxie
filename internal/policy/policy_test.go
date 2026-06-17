package policy

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// fixedClock returns a deterministic clock so reservation timestamps and ULID
// time prefixes are reproducible (the engine never reads the wall clock except
// through this injected func).
func fixedClock() func() time.Time {
	t := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func newEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := Open(t.TempDir(), fixedClock())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return e
}

func sampleCheck() Check {
	return Check{
		Account:   common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
		Dest:      common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
		SpendWei:  big.NewInt(1_000_000_000_000_000_000), // 1 ETH
		MaxGasWei: big.NewInt(2_100_000_000_000_000),     // 21000 × 100 gwei
	}
}

// TestEvaluateAlwaysAllows confirms the M3 stub verdict is unconditional allow and
// writes NO reservation (the check-only path backing --dry-run).
func TestEvaluateAlwaysAllows(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	dec, err := e.Evaluate(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !dec.Allowed {
		t.Fatalf("Evaluate returned Allowed=false; the M3 stub must always allow")
	}
	if dec.Code != "" {
		t.Fatalf("allowed Decision must carry an empty Code, got %q", dec.Code)
	}

	// Evaluate must not have written a reservation.
	orphans, err := e.Orphans(ctx)
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	if len(orphans) != 0 {
		t.Fatalf("Evaluate wrote %d reservation(s); the check-only path must write none", len(orphans))
	}
}

// TestReserveIsDurable confirms Reserve writes a real {state:reserved} record with
// the Check fields faithfully captured, and that it survives a re-Open (durable
// before sign — the §5.1 ordering the reconciliation depends on).
func TestReserveIsDurable(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	e, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	c := sampleCheck()
	r, err := e.Reserve(ctx, c)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if r.ID == "" {
		t.Fatal("Reserve returned an empty reservation id")
	}
	if r.State != stateReserved {
		t.Fatalf("new reservation state = %q, want %q", r.State, stateReserved)
	}
	if r.Account != c.Account || r.Dest != c.Dest {
		t.Fatalf("reservation account/dest mismatch: got %s/%s", r.Account, r.Dest)
	}
	if r.SpendWei != c.SpendWei.String() {
		t.Fatalf("reservation spend_wei = %q, want %q", r.SpendWei, c.SpendWei.String())
	}
	if r.MaxGasWei != c.MaxGasWei.String() {
		t.Fatalf("reservation max_gas_wei = %q, want %q", r.MaxGasWei, c.MaxGasWei.String())
	}

	// A second engine over the same dir must see the durable reservation as an
	// orphan (it survives process restart — the durable-before-sign property).
	e2, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	orphans, err := e2.Orphans(ctx)
	if err != nil {
		t.Fatalf("Orphans after re-Open: %v", err)
	}
	if len(orphans) != 1 || orphans[0].ID != r.ID {
		t.Fatalf("re-Open did not see the durable reservation; orphans=%+v", orphans)
	}
}

// TestReserveCommit walks reserve→commit: after Commit, the reservation is
// {state:committed, hash} and is no longer an orphan.
func TestReserveCommit(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	r, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	hash := common.HexToHash("0xabc0000000000000000000000000000000000000000000000000000000000def")
	if err := e.Commit(ctx, r.ID, hash); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	orphans, err := e.Orphans(ctx)
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	if len(orphans) != 0 {
		t.Fatalf("a committed reservation must not be an orphan; got %d", len(orphans))
	}
}

// TestReserveRelease walks reserve→release: after Release, the reservation is no
// longer an orphan (it never reached the chain).
func TestReserveRelease(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	r, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := e.Release(ctx, r.ID); err != nil {
		t.Fatalf("Release: %v", err)
	}

	orphans, err := e.Orphans(ctx)
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	if len(orphans) != 0 {
		t.Fatalf("a released reservation must not be an orphan; got %d", len(orphans))
	}
}

// TestReleaseIsIdempotentAndMissingIsNoError confirms Release is idempotent and a
// missing id is NOT an error (the safe direction — nothing to undo).
func TestReleaseIsIdempotentAndMissingIsNoError(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	if err := e.Release(ctx, "01ARZ3NDEKTSV4RRFFQ69G5FAV"); err != nil {
		t.Fatalf("Release of a never-reserved id should be a no-op, got: %v", err)
	}
	if err := e.Release(ctx, ""); err != nil {
		t.Fatalf("Release of an empty id should be a no-op, got: %v", err)
	}

	r, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := e.Release(ctx, r.ID); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := e.Release(ctx, r.ID); err != nil {
		t.Fatalf("second Release (idempotent) must succeed, got: %v", err)
	}
}

// TestReleaseAfterCommitIsNoOp confirms the §4.4 invariant: once a reservation is
// committed (signed bytes broadcast), nothing releases it.
func TestReleaseAfterCommitIsNoOp(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	r, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	hash := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	if err := e.Commit(ctx, r.ID, hash); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Release must not undo a committed reservation.
	if err := e.Release(ctx, r.ID); err != nil {
		t.Fatalf("Release after Commit should be a no-op, got: %v", err)
	}
	// It is still committed (not an orphan, and a re-Commit is idempotent).
	if err := e.Commit(ctx, r.ID, hash); err != nil {
		t.Fatalf("re-Commit (idempotent) must succeed, got: %v", err)
	}
}

// TestSettleActualShrinks confirms SettleActual records actual_gas_wei (down-only)
// on a committed reservation.
func TestSettleActualShrinks(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	r, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	hash := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	if err := e.Commit(ctx, r.ID, hash); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	actual := big.NewInt(420_000_000_000_000) // 21000 × 20 gwei, far below worst case
	if err := e.SettleActual(ctx, r.ID, actual); err != nil {
		t.Fatalf("SettleActual: %v", err)
	}

	got := mustLoad(t, e, r.ID)
	if got.ActualGasWei == nil {
		t.Fatal("SettleActual did not record actual_gas_wei")
	}
	if *got.ActualGasWei != actual.String() {
		t.Fatalf("actual_gas_wei = %q, want %q", *got.ActualGasWei, actual.String())
	}

	// Down-only: a later, larger actual must NOT re-inflate.
	bigger := big.NewInt(1_000_000_000_000_000)
	if err := e.SettleActual(ctx, r.ID, bigger); err != nil {
		t.Fatalf("second SettleActual: %v", err)
	}
	got = mustLoad(t, e, r.ID)
	if *got.ActualGasWei != actual.String() {
		t.Fatalf("SettleActual is not down-only: actual_gas_wei = %q, want %q (the smaller)", *got.ActualGasWei, actual.String())
	}
}

// TestSettleActualClampsToWorstCase confirms an actual above the reserved worst
// case is clamped (never creates retroactive headroom for M4's counter).
func TestSettleActualClampsToWorstCase(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	c := sampleCheck()
	r, err := e.Reserve(ctx, c)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	hash := common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")
	if err := e.Commit(ctx, r.ID, hash); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	tooBig := new(big.Int).Mul(c.MaxGasWei, big.NewInt(10))
	if err := e.SettleActual(ctx, r.ID, tooBig); err != nil {
		t.Fatalf("SettleActual: %v", err)
	}
	got := mustLoad(t, e, r.ID)
	if *got.ActualGasWei != c.MaxGasWei.String() {
		t.Fatalf("actual_gas_wei = %q, want it clamped to worst case %q", *got.ActualGasWei, c.MaxGasWei.String())
	}
}

// TestCommitMissingIsIntegrityError confirms committing/settling a vanished
// reservation is tx.integrity.reservation_missing (exit 12).
func TestCommitMissingIsIntegrityError(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	hash := common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444")
	err := e.Commit(ctx, "01ARZ3NDEKTSV4RRFFQ69G5FAV", hash)
	assertCode(t, err, "tx.integrity.reservation_missing", domain.ExitIntegrity)

	err = e.SettleActual(ctx, "01ARZ3NDEKTSV4RRFFQ69G5FAV", big.NewInt(1))
	assertCode(t, err, "tx.integrity.reservation_missing", domain.ExitIntegrity)

	err = e.Commit(ctx, "", hash)
	assertCode(t, err, "tx.integrity.reservation_missing", domain.ExitIntegrity)
}

// TestReservationIDsUnique confirms two reservations get distinct ids even at the
// same (fixed) clock tick — entropy, not the time prefix, guarantees uniqueness.
func TestReservationIDsUnique(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	r1, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve 1: %v", err)
	}
	r2, err := e.Reserve(ctx, sampleCheck())
	if err != nil {
		t.Fatalf("Reserve 2: %v", err)
	}
	if r1.ID == r2.ID {
		t.Fatalf("two reservations share id %q; ids must be unique", r1.ID)
	}
	if len(r1.ID) != 26 {
		t.Fatalf("reservation id %q is not 26 chars (ULID)", r1.ID)
	}

	orphans, err := e.Orphans(ctx)
	if err != nil {
		t.Fatalf("Orphans: %v", err)
	}
	if len(orphans) != 2 {
		t.Fatalf("want 2 open reservations, got %d", len(orphans))
	}
}

// TestNilSpendAndGasReserveAsZero confirms a Check with nil amounts reserves "0"
// (a 0-value self-send / cancel still gets a real durable reservation).
func TestNilSpendAndGasReserveAsZero(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()

	r, err := e.Reserve(ctx, Check{
		Account: common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
		Dest:    common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
	})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if r.SpendWei != "0" || r.MaxGasWei != "0" {
		t.Fatalf("nil amounts must reserve as 0; got spend=%q gas=%q", r.SpendWei, r.MaxGasWei)
	}
}

// mustLoad reads the latest record for id directly off disk (bypassing the
// orphan filter) for assertions on committed/settled records.
func mustLoad(t *testing.T, e *Engine, id string) *Reservation {
	t.Helper()
	var got *Reservation
	if err := e.withLock(context.Background(), func() error {
		byID, _, err := e.loadAll()
		if err != nil {
			return err
		}
		got = byID[id]
		return nil
	}); err != nil {
		t.Fatalf("load %q: %v", id, err)
	}
	if got == nil {
		t.Fatalf("reservation %q not found on disk", id)
	}
	return got
}

// assertCode asserts err is a *domain.Error with the given code and exit.
func assertCode(t *testing.T, err error, wantCode string, wantExit domain.ExitCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("want error code %q, got nil", wantCode)
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("want *domain.Error, got %T: %v", err, err)
	}
	if de.Code != wantCode {
		t.Fatalf("error code = %q, want %q", de.Code, wantCode)
	}
	if de.Exit != wantExit {
		t.Fatalf("error exit = %d, want %d", de.Exit, wantExit)
	}
}
