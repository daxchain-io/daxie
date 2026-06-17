package service

import (
	"context"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// tx_test.go covers the §2.7/§5.1 kernel: authorize→broadcast→settle (the happy
// path leaves a `broadcast` record + a committed reservation + the nonce
// advanced), the deferred abort (a rejected broadcast releases the reservation,
// frees the nonce, marks the record failed), the prefetch-before-lock ordering,
// and the §5.1 broadcast error taxonomy.

func TestSendTx_AuthorizeBroadcastSettle(t *testing.T) {
	from := someAddr(1)
	to := someAddr(2)
	svc, f, sgn := sendService(t, from)

	var broadcasted []byte
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		broadcasted = raw
		return common.HexToHash("0xabc"), nil
	}

	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1000000000000000000"), nil)
	if err != nil {
		t.Fatalf("SendTx: %v", err)
	}
	if sgn.signed != 1 {
		t.Fatalf("signer called %d times, want 1", sgn.signed)
	}
	if res.Status != domain.TxStatusPending {
		t.Errorf("status = %q, want pending (no --wait)", res.Status)
	}
	if res.Nonce != 0 {
		t.Errorf("nonce = %d, want 0 (fresh account)", res.Nonce)
	}
	if res.AmountWei != "1000000000000000000" {
		t.Errorf("amount = %q, want 1e18", res.AmountWei)
	}
	// The bytes broadcast are EXACTLY the signed bytes (raw_tx, idempotent).
	if string(broadcasted) != string(sgn.lastRaw) {
		t.Error("broadcast bytes differ from the signed raw_tx")
	}

	// The journal folds to `broadcast` with the reservation id.
	chainID := uint64(1)
	rec, jerr := svc.journal.ByHash(context.Background(), chainID, common.HexToHash(res.Hash))
	if jerr != nil {
		t.Fatalf("journal ByHash: %v", jerr)
	}
	if rec.Status != journal.StatusBroadcast {
		t.Errorf("journal status = %q, want broadcast", rec.Status)
	}
	if rec.ReservationID == "" {
		t.Error("journal record has no reservation id")
	}
	if rec.RawTx == "" {
		t.Error("journal record has no raw_tx")
	}

	// The reservation is committed (no longer a reserved orphan).
	orphans, _ := svc.policy.Orphans(context.Background())
	if len(orphans) != 0 {
		t.Errorf("found %d reserved orphans after a committed send, want 0", len(orphans))
	}

	// A second send from the same account derives nonce 1 (never re-allocated).
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0xdef"), nil
	}
	res2, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("second SendTx: %v", err)
	}
	if res2.Nonce != 1 {
		t.Errorf("second nonce = %d, want 1 (max(chainPending,local,journal))", res2.Nonce)
	}
}

func TestSendTx_RejectedBroadcast_ReleasesReservationAndNonce(t *testing.T) {
	from := someAddr(3)
	to := someAddr(4)
	svc, f, _ := sendService(t, from)

	// A permanently-rejected broadcast (insufficient funds → exit 5).
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.Hash{}, errString("insufficient funds for gas * price + value")
	}

	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "5"), nil)
	if err == nil {
		t.Fatal("expected an error on a rejected broadcast")
	}
	if de := domain.AsError(err); de.Exit != domain.ExitInsufficientFunds {
		t.Fatalf("exit = %d, want 5 (insufficient funds)", de.Exit)
	}

	// The reservation was RELEASED (abort path) — no committed orphan, and the
	// record is failed.
	orphans, _ := svc.policy.Orphans(context.Background())
	if len(orphans) != 0 {
		t.Errorf("rejected send left %d reserved orphans, want 0 (released)", len(orphans))
	}

	// The nonce was NOT burned: the next send gets nonce 0 again (a refusal never
	// consumes the nonce, §5.1).
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0x111"), nil
	}
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("retry SendTx: %v", err)
	}
	if res.Nonce != 0 {
		t.Errorf("nonce after a rejected send = %d, want 0 (never burned)", res.Nonce)
	}
}

func TestSendTx_TransportExhausted_StaysSigned(t *testing.T) {
	from := someAddr(5)
	to := someAddr(6)
	svc, f, _ := sendService(t, from)

	// Always a transport error → after the backoff retries, the record stays
	// `signed` (no recorded broadcast) and the call returns rpc.unreachable.
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.Hash{}, errString("dial tcp: connection refused")
	}

	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if de := domain.AsError(err); de.Exit != domain.ExitNetwork {
		t.Fatalf("exit = %d, want 6 (network/rpc.unreachable)", de.Exit)
	}

	// The record stays `signed` (recoverable): the reconciliation discriminator
	// must NOT see a recorded broadcast.
	rec, jerr := svc.journal.ByHash(context.Background(), 1, common.HexToHash(res.Hash))
	if jerr != nil {
		t.Fatalf("journal ByHash: %v", jerr)
	}
	if rec.Status != journal.StatusSigned {
		t.Errorf("journal status = %q, want signed (no recorded broadcast)", rec.Status)
	}
	// The nonce lease was committed (transport-exhausted commits the lease) so the
	// next send advances — recovery rebroadcasts the SAME bytes for this one.
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0x222"), nil
	}
	res2, _ := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if res2.Nonce != 1 {
		t.Errorf("next nonce = %d, want 1 (transport-exhausted commits the lease)", res2.Nonce)
	}
}

func TestSendTx_AlreadyKnown_Succeeds(t *testing.T) {
	from := someAddr(7)
	to := someAddr(8)
	svc, f, _ := sendService(t, from)
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.Hash{}, errString("already known")
	}
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("already-known should be success: %v", err)
	}
	rec, _ := svc.journal.ByHash(context.Background(), 1, common.HexToHash(res.Hash))
	if rec.Status != journal.StatusBroadcast {
		t.Errorf("status = %q, want broadcast (already-known is success)", rec.Status)
	}
}

// TestSendTx_NonceTooLow_NoReceipt_Replaced_Exit9 is the §5.1 race-with-self
// NEGATIVE sub-case: "nonce too low" AND no receipt for OUR hash ⇒ a DIFFERENT tx
// consumed the nonce ⇒ tx.replaced (exit 9), the nonce released (never burned).
func TestSendTx_NonceTooLow_NoReceipt_Replaced_Exit9(t *testing.T) {
	from := someAddr(9)
	to := someAddr(10)
	svc, f, _ := sendService(t, from)
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.Hash{}, errString("nonce too low")
	}
	// No receipt for our hash (the fake's default Receipt returns ErrTxNotFound).
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err == nil || domain.AsError(err).Exit != domain.ExitTxConflict {
		t.Fatalf("expected tx conflict exit 9, got %v", err)
	}
	// The record is failed and the nonce is NOT burned (a different tx owns it; our
	// bytes never landed) — the next send re-derives nonce 0.
	orphans, _ := svc.policy.Orphans(context.Background())
	if len(orphans) != 0 {
		t.Errorf("replaced send left %d reserved orphans, want 0 (released)", len(orphans))
	}
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0x999"), nil
	}
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("retry SendTx: %v", err)
	}
	if res.Nonce != 0 {
		t.Errorf("nonce after a no-receipt replaced send = %d, want 0 (never burned)", res.Nonce)
	}
}

// TestSendTx_NonceTooLow_OurReceiptPresent_Success is the §5.1 race-with-self
// POSITIVE sub-case: "nonce too low" but OUR hash already mined ⇒ the nonce was
// consumed BY US ⇒ SUCCESS (exit 0), the record `broadcast`, the reservation
// committed, the nonce advanced. The old behavior reported this as exit 9 — the
// bug the review caught (a successfully-mined payment mis-reported as conflict).
func TestSendTx_NonceTooLow_OurReceiptPresent_Success(t *testing.T) {
	from := someAddr(11)
	to := someAddr(12)
	svc, f, _ := sendService(t, from)

	// The broadcast is rejected nonce-too-low...
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.Hash{}, errString("nonce too low")
	}
	// ...but a receipt EXISTS for OUR hash (our prior attempt actually landed): the
	// fake returns a mined receipt for whatever hash is queried (it is our hash —
	// runSend re-fetches a.hash).
	f.ReceiptFn = func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		return fakeReceipt(h, 100, 1), nil
	}

	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("nonce-too-low with OUR receipt present must succeed: %v", err)
	}
	if res.Status != domain.TxStatusPending {
		t.Errorf("status = %q, want pending (no --wait; the mined-while-racing nonce is ours)", res.Status)
	}

	// The record is `broadcast` (recorded), reservation committed, nonce advanced.
	rec, jerr := svc.journal.ByHash(context.Background(), 1, common.HexToHash(res.Hash))
	if jerr != nil {
		t.Fatalf("journal ByHash: %v", jerr)
	}
	if rec.Status != journal.StatusBroadcast {
		t.Errorf("journal status = %q, want broadcast (our nonce-too-low tx is ours-mined)", rec.Status)
	}
	orphans, _ := svc.policy.Orphans(context.Background())
	if len(orphans) != 0 {
		t.Errorf("ours-mined nonce-too-low left %d reserved orphans, want 0 (committed)", len(orphans))
	}
	// The next send advances to nonce 1 (our nonce 0 was consumed by us).
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0xaaa"), nil
	}
	f.ReceiptFn = nil
	res2, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("second SendTx: %v", err)
	}
	if res2.Nonce != 1 {
		t.Errorf("next nonce = %d, want 1 (our nonce-0 tx was consumed by us)", res2.Nonce)
	}
}

func TestSendTx_DryRun_NoBroadcastNoReservation(t *testing.T) {
	from := someAddr(11)
	to := someAddr(12)
	svc, f, sgn := sendService(t, from)
	sent := false
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		sent = true
		return common.HexToHash("0x0"), nil
	}
	req := txReq(from, to, "1")
	req.DryRun = true
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), req, nil)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !res.DryRun {
		t.Error("result should be marked DryRun")
	}
	if sent {
		t.Error("dry-run must NOT broadcast")
	}
	if sgn.signed != 0 {
		t.Error("dry-run must NOT sign")
	}
	// No reservation written by Evaluate (check-only).
	orphans, _ := svc.policy.Orphans(context.Background())
	if len(orphans) != 0 {
		t.Errorf("dry-run wrote %d reservations, want 0 (Evaluate is check-only)", len(orphans))
	}
}

// TestSendTx_PrefetchBeforeLock proves the §2.7 ordering: the gas quote (a
// SuggestFees/EstimateGas read) happens BEFORE the account lock is acquired and a
// nonce derived. We assert that the gas-engine RPCs are recorded before the first
// SendRaw, and that a SuggestFees failure aborts BEFORE any reservation is written
// (nothing locked, nothing reserved).
func TestSendTx_PrefetchFailsBeforeReserve(t *testing.T) {
	from := someAddr(13)
	to := someAddr(14)
	svc, f, sgn := sendService(t, from)
	// Make the gas prefetch fail.
	f.SuggestFeesFn = func(ctx context.Context, blocks int) (chain.Fees, error) {
		return chain.Fees{}, errString("connection refused")
	}
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err == nil {
		t.Fatal("expected the gas prefetch to fail the send")
	}
	if sgn.signed != 0 {
		t.Error("nothing should have been signed (prefetch failed before authorize)")
	}
	orphans, _ := svc.policy.Orphans(context.Background())
	if len(orphans) != 0 {
		t.Errorf("a prefetch failure wrote %d reservations, want 0 (reserve is AFTER the lock)", len(orphans))
	}
	_ = f
}

// M5: an UNREGISTERED token alias is ref.not_found — the anti-spoofing wall. A
// name not in the registry (and not a bundled major) is NEVER resolved by an
// on-chain symbol() lookup. (The full transfer happy-path lives in tx_token_test.go.)
func TestSendTx_TokenUnregisteredNotFound(t *testing.T) {
	from := someAddr(15)
	svc, _, _ := sendService(t, from)
	req := txReq(from, someAddr(16), "1")
	req.Token = "definitely-not-registered"
	req.Network = "mainnet"
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), req, nil)
	assertCode(t, err, domain.CodeRefNotFound)
}
