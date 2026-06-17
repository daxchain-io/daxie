package journal

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// newTestNonceMgr opens a journal store + nonce manager over one fresh temp dir.
func newTestNonceMgr(t *testing.T) (*Store, *NonceManager) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	m, err := NewNonceManager(dir, s)
	if err != nil {
		t.Fatalf("NewNonceManager: %v", err)
	}
	return s, m
}

func TestNextNonceEmptyIsChainPending(t *testing.T) {
	t.Parallel()
	_, m := newTestNonceMgr(t)
	ctx := context.Background()

	// No journal records, no cache: NextNonce == chainPending.
	got, err := m.NextNonce(ctx, 1, testAddr, 7)
	if err != nil {
		t.Fatalf("NextNonce: %v", err)
	}
	if got != 7 {
		t.Errorf("NextNonce = %d, want 7 (chainPending)", got)
	}
}

func TestNextNonceFoldsJournalIncludingTerminal(t *testing.T) {
	t.Parallel()
	s, m := newTestNonceMgr(t)
	ctx := context.Background()

	// Journal has a CONFIRMED (terminal) record at nonce 10 and the chain lags (says
	// pending 5, stale RPC). journalNext = 11 must win over chainPending 5.
	r := ethTransfer(1, testAddr, 10, "res-10", "0xaa")
	if err := s.Append(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, 1, r.ID, StateMutation{Status: StatusConfirmed, TxHash: strptr("0xhash10")}); err != nil {
		t.Fatal(err)
	}

	got, err := m.NextNonce(ctx, 1, testAddr, 5)
	if err != nil {
		t.Fatalf("NextNonce: %v", err)
	}
	if got != 11 {
		t.Errorf("NextNonce = %d, want 11 (terminal record at nonce 10 folds to 11 despite stale chain 5)", got)
	}
}

func TestNextNonceFailedRecordDoesNotConsume(t *testing.T) {
	t.Parallel()
	s, m := newTestNonceMgr(t)
	ctx := context.Background()

	// A FAILED (refused-broadcast) record at nonce 3 must NOT advance the nonce: a
	// refused broadcast never burns the nonce. chainPending 3 should still be free.
	r := ethTransfer(1, testAddr, 3, "res-3", "0xaa")
	if err := s.Append(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, 1, r.ID, StateMutation{Status: StatusFailed, Error: strptr("rejected")}); err != nil {
		t.Fatal(err)
	}

	got, err := m.NextNonce(ctx, 1, testAddr, 3)
	if err != nil {
		t.Fatalf("NextNonce: %v", err)
	}
	if got != 3 {
		t.Errorf("NextNonce = %d, want 3 (a failed record must not consume nonce 3)", got)
	}
}

func TestNextNonceStaleCacheLosesToJournalAndChain(t *testing.T) {
	t.Parallel()
	s, m := newTestNonceMgr(t)
	ctx := context.Background()

	// Seed a cache that is BEHIND reality (next=2) via a committed lease, then add a
	// journal record at nonce 8. max(chainPending=0, localNext=2, journalNext=9)=9.
	lease, err := m.AcquireNonce(ctx, 1, testAddr, 1, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// allocated nonce 1 (chainPending) -> Commit writes cache next=2.
	if err := lease.Commit(); err != nil {
		t.Fatal(err)
	}

	r := ethTransfer(1, testAddr, 8, "res-8", "0xaa")
	if err := s.Append(ctx, r); err != nil {
		t.Fatal(err)
	}

	got, err := m.NextNonce(ctx, 1, testAddr, 0)
	if err != nil {
		t.Fatalf("NextNonce: %v", err)
	}
	if got != 9 {
		t.Errorf("NextNonce = %d, want 9 (journalNext beats stale cache 2 and chain 0)", got)
	}
}

func TestAcquireCommitWritesNoncePlusOne(t *testing.T) {
	t.Parallel()
	_, m := newTestNonceMgr(t)
	ctx := context.Background()

	lease, err := m.AcquireNonce(ctx, 1, testAddr, 4, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Nonce() != 4 {
		t.Errorf("lease nonce = %d, want 4", lease.Nonce())
	}
	if err := lease.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Cache now holds next=5; a fresh derivation with a lagging chain sees it.
	next, present, err := m.readCache(1, testAddr)
	if err != nil {
		t.Fatal(err)
	}
	if !present || next != 5 {
		t.Errorf("cache next = %d present=%v, want 5/true", next, present)
	}
}

func TestAcquireReleaseDoesNotBurnNonce(t *testing.T) {
	t.Parallel()
	_, m := newTestNonceMgr(t)
	ctx := context.Background()

	// Acquire nonce 4, then RELEASE (the refused-broadcast / pre-sign-failure path).
	// The cache must be untouched, so the next acquire returns 4 again.
	lease, err := m.AcquireNonce(ctx, 1, testAddr, 4, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, present, err := m.readCache(1, testAddr); err != nil || present {
		t.Errorf("Release must not write the cache; present=%v err=%v", present, err)
	}

	lease2, err := m.AcquireNonce(ctx, 1, testAddr, 4, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease2.Release() }()
	if lease2.Nonce() != 4 {
		t.Errorf("after Release, re-acquire nonce = %d, want 4 (nonce never burned)", lease2.Nonce())
	}
}

func TestForcedNonceBypassesDerivation(t *testing.T) {
	t.Parallel()
	s, m := newTestNonceMgr(t)
	ctx := context.Background()

	// Journal would derive 11, but --nonce 3 must pin 3 (still under the lock).
	r := ethTransfer(1, testAddr, 10, "res-10", "0xaa")
	if err := s.Append(ctx, r); err != nil {
		t.Fatal(err)
	}
	forced := uint64(3)
	lease, err := m.AcquireNonce(ctx, 1, testAddr, 50, &forced, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Release() }()
	if lease.Nonce() != 3 {
		t.Errorf("forced nonce = %d, want 3 (derivation bypassed)", lease.Nonce())
	}
}

func TestSingleWriterViolationWarns(t *testing.T) {
	t.Parallel()
	s, m := newTestNonceMgr(t)
	ctx := context.Background()
	var buf bytes.Buffer
	s.SetWarnSinks(&buf, &buf)

	// No journal records, no cache, but chain reports pending 42 — a foreign writer
	// advanced the account. Warn once and adopt the chain value.
	lease, err := m.AcquireNonce(ctx, 1, testAddr, 42, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Release() }()
	if lease.Nonce() != 42 {
		t.Errorf("adopted nonce = %d, want 42 (chain value)", lease.Nonce())
	}
	if !bytes.Contains(buf.Bytes(), []byte("single-writer")) {
		t.Errorf("expected a single-writer-violation warning; got %q", buf.String())
	}
}

func TestNoViolationWarnWhenInFlight(t *testing.T) {
	t.Parallel()
	s, m := newTestNonceMgr(t)
	ctx := context.Background()
	var buf bytes.Buffer
	s.SetWarnSinks(&buf, &buf)

	// An in-flight (broadcast, non-terminal) record exists; a chain pending ahead of
	// the local view is then expected (our own tx is propagating) and must NOT warn.
	r := ethTransfer(1, testAddr, 0, "res-0", "0xaa")
	if err := s.Append(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, 1, r.ID, StateMutation{Status: StatusBroadcast, TxHash: strptr("0xhash")}); err != nil {
		t.Fatal(err)
	}
	lease, err := m.AcquireNonce(ctx, 1, testAddr, 5, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Release() }()
	if bytes.Contains(buf.Bytes(), []byte("single-writer")) {
		t.Errorf("must NOT warn while a record is in-flight; got %q", buf.String())
	}
}

func TestLeaseSerializesSameAccount(t *testing.T) {
	t.Parallel()
	_, m := newTestNonceMgr(t)
	ctx := context.Background()

	// First lease holds the account lock; a second acquire with a short timeout must
	// time out (state.lock_timeout) — proving same-account serialization.
	lease1, err := m.AcquireNonce(ctx, 1, testAddr, 0, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease1.Release() }()

	_, err = m.AcquireNonce(ctx, 1, testAddr, 0, nil, 100*time.Millisecond)
	if err == nil {
		t.Fatalf("second acquire should have timed out while the first lease is held")
	}
	de := domainErr(err)
	if de == nil || de.Code != CodeStateLockTimeout {
		t.Errorf("second acquire error code = %v, want %s", de, CodeStateLockTimeout)
	}
}

func TestDifferentAccountsDoNotSerialize(t *testing.T) {
	t.Parallel()
	_, m := newTestNonceMgr(t)
	ctx := context.Background()
	other := common.HexToAddress("0x52ae0000000000000000000000000000000000bb")

	lease1, err := m.AcquireNonce(ctx, 1, testAddr, 0, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease1.Release() }()

	// A different account must acquire immediately (per-account lock object).
	lease2, err := m.AcquireNonce(ctx, 1, other, 0, nil, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("different account must not serialize: %v", err)
	}
	_ = lease2.Release()
}
