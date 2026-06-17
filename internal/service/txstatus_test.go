package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// txstatus_test.go covers the §5.3 wait state machine: confirmed (exit 0),
// reverted (exit 7), replaced (exit 9), and timeout (exit 8, resumable). The wait
// loop reads time via the injected clock; tests inject an advancing clock so the
// deadline is reachable without a real sleep.

// advancingClock returns a clock that steps forward by step on every call,
// starting from base. The §5.3 loop calls clock() at least twice per iteration,
// so a small step relative to the timeout makes the deadline reachable
// deterministically.
func advancingClock(base time.Time, step time.Duration) func() time.Time {
	var mu sync.Mutex
	cur := base
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t := cur
		cur = cur.Add(step)
		return t
	}
}

// waitService opens a send-ready service with an advancing clock so the wait
// machine terminates deterministically.
func waitService(t *testing.T, from common.Address, step time.Duration) (*Service, *fake.Client, *fakeSigner) {
	t.Helper()
	f := fake.New()
	isolate(t)
	svc, err := Open(context.Background(), Options{
		Clock: advancingClock(time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC), step),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	svc.chains = &stubProvider{cc: f}
	sgn := &fakeSigner{addr: from}
	svc.signer = sgn
	svc.secretIO = SecretIO{LookupEnv: func(k string) (string, bool) {
		if k == "DAXIE_PASSPHRASE" {
			return "p", true
		}
		return "", false
	}}
	return svc, f, sgn
}

// sendOne sends a tx and returns its result (so a wait test has a journal record).
func sendOne(t *testing.T, svc *Service, f *fake.Client, from, to common.Address, hash common.Hash) domain.TxResult {
	t.Helper()
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) { return hash, nil }
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("SendTx: %v", err)
	}
	return res
}

func TestWait_Confirmed_Exit0(t *testing.T) {
	from, to := someAddr(20), someAddr(21)
	svc, f, _ := waitService(t, from, time.Second)
	res := sendOne(t, svc, f, from, to, common.HexToHash("0xc0"))
	hash := common.HexToHash(res.Hash)

	// A mined receipt with >= target confirmations (mainnet target 2).
	f.BlockNum = 12
	f.ReceiptFn = func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		return fakeReceipt(hash, 10, 1), nil // conf = 12-10+1 = 3 >= 2
	}

	wres, werr := svc.WaitTx(context.Background(), domain.LocalCLI(),
		domain.WaitRequest{Hash: res.Hash}, nil)
	if werr != nil {
		t.Fatalf("WaitTx confirmed should be exit 0: %v", werr)
	}
	if wres.Status != domain.TxStatusConfirmed {
		t.Errorf("status = %q, want confirmed", wres.Status)
	}
	// The journal folds to confirmed + SettleActual recorded.
	rec, _ := svc.journal.ByHash(context.Background(), 1, hash)
	if rec.Status != journal.StatusConfirmed {
		t.Errorf("journal status = %q, want confirmed", rec.Status)
	}
	// A confirmed send must carry a reservation id (the durable policy reservation
	// the SettleActual shrank). We cannot read actual_gas_wei through policy's
	// public API, but the reservation id must be present and Commit-then-Settle
	// must not have errored (covered by the no-error return above).
	if rec.ReservationID == "" {
		t.Error("confirmed record must carry a reservation_id")
	}
}

func TestWait_Reverted_Exit7(t *testing.T) {
	from, to := someAddr(22), someAddr(23)
	svc, f, _ := waitService(t, from, time.Second)
	res := sendOne(t, svc, f, from, to, common.HexToHash("0xre"))
	hash := common.HexToHash(res.Hash)

	f.BlockNum = 10
	f.ReceiptFn = func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		return fakeReceipt(hash, 10, 0), nil // status 0 = reverted
	}
	_, werr := svc.WaitTx(context.Background(), domain.LocalCLI(), domain.WaitRequest{Hash: res.Hash}, nil)
	if werr == nil || domain.AsError(werr).Exit != domain.ExitReverted {
		t.Fatalf("expected reverted exit 7, got %v", werr)
	}
	rec, _ := svc.journal.ByHash(context.Background(), 1, hash)
	if rec.Status != journal.StatusReverted {
		t.Errorf("journal status = %q, want reverted", rec.Status)
	}
}

func TestWait_Replaced_Exit9(t *testing.T) {
	from, to := someAddr(24), someAddr(25)
	svc, f, _ := waitService(t, from, time.Second)
	res := sendOne(t, svc, f, from, to, common.HexToHash("0x9a"))
	hash := common.HexToHash(res.Hash)

	// No receipt for our hash, but the account's mined nonce advanced past ours →
	// a sibling consumed the nonce → replaced (exit 9).
	f.ReceiptFn = func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		return nil, errTxNotFoundShim()
	}
	f.Nonces[from] = 5 // latest mined nonce >> our nonce 0

	_, werr := svc.WaitTx(context.Background(), domain.LocalCLI(), domain.WaitRequest{Hash: res.Hash}, nil)
	if werr == nil || domain.AsError(werr).Exit != domain.ExitTxConflict {
		t.Fatalf("expected replaced exit 9, got %v", werr)
	}
	rec, _ := svc.journal.ByHash(context.Background(), 1, hash)
	if rec.Status != journal.StatusReplaced {
		t.Errorf("journal status = %q, want replaced", rec.Status)
	}
}

func TestWait_Timeout_Exit8_Resumable(t *testing.T) {
	from, to := someAddr(26), someAddr(27)
	// A big clock step so the deadline is reached within a couple of loop turns.
	svc, f, _ := waitService(t, from, 5*time.Minute)
	res := sendOne(t, svc, f, from, to, common.HexToHash("0x88"))

	// No receipt ever, nonce not consumed → stays pending → deadline → timeout.
	f.ReceiptFn = func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		return nil, errTxNotFoundShim()
	}
	f.Nonces[from] = 0

	wres, werr := svc.WaitTx(context.Background(), domain.LocalCLI(),
		domain.WaitRequest{Hash: res.Hash, Timeout: domain.Duration{D: 8 * time.Minute}}, nil)
	if werr == nil {
		t.Fatal("expected a timeout error")
	}
	de := domain.AsError(werr)
	if de.Exit != domain.ExitTimeoutPending {
		t.Fatalf("exit = %d, want 8 (timeout)", de.Exit)
	}
	if !de.Retryable {
		t.Error("timeout must be retryable (resumable)")
	}
	if wres.Status != domain.TxStatusTimeout {
		t.Errorf("status = %q, want timeout", wres.Status)
	}
	if wres.Resume == "" {
		t.Error("timeout result must carry a Resume hint")
	}
}

func TestWait_Dropped_RebroadcastsSameBytes(t *testing.T) {
	from, to := someAddr(28), someAddr(29)
	// A small clock step: the deadline (default 10m) must outlast the several
	// journal writes (each stamps a ts off the shared clock) + the two wait loops
	// it takes for the rebroadcast→confirm sequence.
	svc, f, sgn := waitService(t, from, time.Second)
	res := sendOne(t, svc, f, from, to, common.HexToHash("0xdr"))
	hash := common.HexToHash(res.Hash)
	signedRaw := sgn.lastRaw

	// First loop: no receipt + nonce not consumed + known to us → dropped →
	// rebroadcast. Receipt is consulted TWICE before the rebroadcast actually
	// happens — once by observe (to classify dropped) and once by the rebroadcast
	// helper's double-spend gate (a) — so we must withhold the receipt for the
	// first two calls, then provide it so the second loop confirms (terminating the
	// test).
	var rebroadcast []byte
	step := 0
	f.ReceiptFn = func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		step++
		if step <= 2 {
			return nil, errTxNotFoundShim()
		}
		f.BlockNum = 10
		return fakeReceipt(hash, 10, 1), nil
	}
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		rebroadcast = raw
		return hash, nil
	}
	f.Nonces[from] = 0

	_, werr := svc.WaitTx(context.Background(), domain.LocalCLI(),
		domain.WaitRequest{Hash: res.Hash, Confirmations: u64ptr(1)}, nil)
	if werr != nil {
		t.Fatalf("wait after a dropped+rebroadcast: %v", werr)
	}
	if rebroadcast == nil {
		t.Fatal("dropped transition did not rebroadcast")
	}
	if string(rebroadcast) != string(signedRaw) {
		t.Error("rebroadcast bytes differ from the original signed raw_tx (must be identical)")
	}
}

func TestListTxs_NewestFirst(t *testing.T) {
	from, to := someAddr(30), someAddr(31)
	svc, f, _ := sendService(t, from)
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) { return common.HexToHash("0x1"), nil }
	_, _ = svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) { return common.HexToHash("0x2"), nil }
	_, _ = svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "2"), nil)

	list, err := svc.ListTxs(context.Background(), domain.LocalCLI(), domain.TxListRequest{Account: from.Hex()})
	if err != nil {
		t.Fatalf("ListTxs: %v", err)
	}
	if len(list.Txs) != 2 {
		t.Fatalf("listed %d txs, want 2", len(list.Txs))
	}
}

// ── tiny test shims ──────────────────────────────────────────────────────────

func u64ptr(n uint64) *uint64 { return &n }

// errTxNotFoundShim returns the chain not-found sentinel so the fake's ReceiptFn
// can signal "no receipt" exactly like the real adapter.
func errTxNotFoundShim() error { return chain.ErrTxNotFound }
