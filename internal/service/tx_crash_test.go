package service

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/policy"
	"github.com/ethereum/go-ethereum/common"
)

// tx_crash_test.go is the §5.1 settle/abort crash matrix: it proves the deferred
// abort can NEVER terminalize a record whose broadcast is already RECORDED, and can
// NEVER free a nonce that is durably spent — the nonce DOUBLE-ALLOCATION the
// adversarial review caught. The injection is a real wedged filesystem (the nonce
// cache dir made read-only mid-send so lease.Commit's WriteAtomic fails), plus a
// direct kernel-level abort test for the policy.Commit-failure analog.

// nonceDir is the per-(chain,account) nonce cache dir under the service's state.
func nonceDir(s *Service) string { return filepath.Join(s.paths.State, "nonce") }

// TestSendTx_AcceptedSettleLeaseCommitFails_RecordStaysBroadcast_NonceNotReused
// reproduces the proven double-allocation: a clean first send, then the nonce dir
// is made read-only so the SECOND send's lease.Commit (WriteAtomic) fails AFTER
// settle has recorded the broadcast + committed the reservation. The deferred abort
// MUST leave the record `broadcast` (not flip it to `failed`) and MUST NOT free the
// nonce — so the third send derives a NEW nonce, never re-allocating the second's.
func TestSendTx_AcceptedSettleLeaseCommitFails_RecordStaysBroadcast_NonceNotReused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("0o500 dir perms do not block writes the same way on Windows")
	}
	from := someAddr(20)
	to := someAddr(21)
	svc, f, _ := sendService(t, from)

	// First send (clean): nonce 0, journal `broadcast`, nonce cache written.
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0x100"), nil
	}
	res0, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("first SendTx: %v", err)
	}
	if res0.Nonce != 0 {
		t.Fatalf("first nonce = %d, want 0", res0.Nonce)
	}

	// Wedge the nonce cache dir: read+exec only, so the in-dir temp file
	// WriteAtomic creates cannot be written → lease.Commit fails state.corrupt.
	nd := nonceDir(svc)
	if err := os.Chmod(nd, 0o500); err != nil {
		t.Fatalf("chmod nonce dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(nd, 0o700) })

	// Second send: broadcast succeeds, settle records broadcast + commits the
	// reservation, then lease.Commit FAILS. The deferred abort fires (settled was
	// false in the accepted branch) — with the guard it must NOT terminalize.
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0x200"), nil
	}
	_, serr := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if serr == nil {
		t.Fatal("expected the wedged nonce cache to surface a lease.Commit error")
	}

	// The second record (nonce 1) must be `broadcast`, NOT `failed`. (The fake
	// signer derives the hash from the tx, so we locate the record by nonce via
	// List rather than by a predicted hash.)
	rec2 := recordByNonce(t, svc, from, 1)
	if rec2.Status != journal.StatusBroadcast {
		t.Fatalf("second record status = %q, want broadcast (the deferred abort must NOT terminalize a recorded broadcast)", rec2.Status)
	}

	// Restore perms and send a THIRD time. The journal fold sees nonce 1 consumed
	// (the `broadcast` record), so the third send MUST derive nonce 2 — proving the
	// nonce was NOT freed by the abort (no double-allocation).
	if err := os.Chmod(nd, 0o700); err != nil {
		t.Fatalf("restore nonce dir perms: %v", err)
	}
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0x300"), nil
	}
	res3, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("third SendTx: %v", err)
	}
	if res3.Nonce != 2 {
		t.Errorf("third nonce = %d, want 2 (nonce 1 is durably consumed; NOT re-allocated)", res3.Nonce)
	}
}

// TestSendTx_TransportExhaustedLeaseCommitFails_StaysSignedRecoverable proves the
// lost-broadcast window is closed: a transport-exhausted send whose lease.Commit
// then fails (wedged nonce dir) must leave the record `signed` (recoverable), NOT
// let the deferred abort terminalize it and lose the raw_tx + free its nonce.
func TestSendTx_TransportExhaustedLeaseCommitFails_StaysSignedRecoverable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("0o500 dir perms do not block writes the same way on Windows")
	}
	from := someAddr(22)
	to := someAddr(23)
	svc, f, _ := sendService(t, from)

	// Wedge the nonce dir BEFORE the first send so lease.Commit fails. (ensureDirs
	// in AcquireNonce is a no-op MkdirAll on the already-present dir.)
	nd := nonceDir(svc)
	if err := os.MkdirAll(nd, 0o700); err != nil {
		t.Fatalf("mkdir nonce dir: %v", err)
	}
	if err := os.Chmod(nd, 0o500); err != nil {
		t.Fatalf("chmod nonce dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(nd, 0o700) })

	// Always a transport error → transport-exhausted; the lease.Commit then fails.
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.Hash{}, errString("dial tcp: connection refused")
	}
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err == nil {
		t.Fatal("expected a transport error")
	}

	// The record MUST stay `signed` (no recorded broadcast) so recovery can
	// resurrect the SAME bytes — never `failed`.
	rec, jerr := svc.journal.ByHash(context.Background(), 1, common.HexToHash(res.Hash))
	if jerr != nil {
		t.Fatalf("journal ByHash: %v", jerr)
	}
	if rec.Status != journal.StatusSigned {
		t.Errorf("record status = %q, want signed (lost-broadcast window must NOT terminalize)", rec.Status)
	}
	if rec.RawTx == "" {
		t.Error("raw_tx was lost (recovery cannot rebroadcast)")
	}
}

// TestAbort_BroadcastRecorded_NonDestructive is the kernel-level guard test (the
// policy.Commit-failure analog from the review): the deferred abort, given a record
// whose latest status is already `broadcast`, must NOT mark it failed and must NOT
// release the reservation — it commits the lease (the nonce is durably spent).
func TestAbort_BroadcastRecorded_NonDestructive(t *testing.T) {
	from := someAddr(24)
	to := someAddr(25)
	svc, f, _ := sendService(t, from)

	// Drive a normal, fully-settled send so a real `broadcast` record + a committed
	// reservation + an advanced nonce exist.
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0x400"), nil
	}
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("SendTx: %v", err)
	}
	rec, _ := svc.journal.ByHash(context.Background(), 1, common.HexToHash(res.Hash))
	if rec.Status != journal.StatusBroadcast {
		t.Fatalf("precondition: record status = %q, want broadcast", rec.Status)
	}

	// Acquire a fresh lease pinned to the broadcast record's OWN nonce (as the live
	// send's lease was) and hand it to abort alongside the broadcast record's
	// journal id — simulating the deferred abort firing after settle recorded the
	// broadcast (e.g. policy.Commit/lease.Commit failed). lease.Commit then writes
	// next = rec.Nonce+1, exactly as the real send's lease would.
	pinned := rec.Nonce
	lease, err := svc.nonce.AcquireNonce(context.Background(), 1, from, 0, &pinned, 0)
	if err != nil {
		t.Fatalf("AcquireNonce: %v", err)
	}
	a := authorized{
		hash:        common.HexToHash(res.Hash),
		nonce:       rec.Nonce,
		chainID:     1,
		journalID:   rec.ID,
		reservation: policy.Reservation{ID: rec.ReservationID},
		lease:       lease,
	}
	if aerr := svc.abort(context.Background(), a, errAbortIncomplete); aerr != nil {
		t.Fatalf("abort on a broadcast-recorded record: %v", aerr)
	}

	// The record must STILL be `broadcast` (not failed).
	rec2, _ := svc.journal.ByID(context.Background(), 1, rec.ID)
	if rec2.Status != journal.StatusBroadcast {
		t.Errorf("after abort, record status = %q, want broadcast (abort must not terminalize a recorded broadcast)", rec2.Status)
	}
	// The reservation must STILL be committed (no reserved orphan reappeared).
	orphans, _ := svc.policy.Orphans(context.Background())
	if len(orphans) != 0 {
		t.Errorf("abort released the committed reservation (%d orphans), want 0", len(orphans))
	}
	// The nonce must STILL be consumed: the next send derives nonce 1.
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0x500"), nil
	}
	res2, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("next SendTx: %v", err)
	}
	if res2.Nonce != 1 {
		t.Errorf("next nonce = %d, want 1 (the broadcast nonce 0 was NOT freed by abort)", res2.Nonce)
	}
}

// recordByNonce returns the latest journal record for from at the given nonce on
// chain 1, failing the test if none exists.
func recordByNonce(t *testing.T, svc *Service, from common.Address, nonce uint64) *journal.Record {
	t.Helper()
	recs, err := svc.journal.List(context.Background(), 1, from)
	if err != nil {
		t.Fatalf("journal List: %v", err)
	}
	for _, r := range recs {
		if r.Nonce == nonce {
			return r
		}
	}
	t.Fatalf("no journal record for %s at nonce %d", from.Hex(), nonce)
	return nil
}
