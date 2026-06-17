package policy

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// counter_test.go pins the §4.4 counter mechanics: rolling-24h sum,
// max-across-candidates, pruning, and per-account flock serialization.

func sCand(value, gasMax string, state string) counterCandidate {
	return counterCandidate{ValueWei: value, GasMaxWei: gasMax, State: state}
}

// TestSumWindowMaxAcrossCandidates confirms the counted wei is the max across an
// entry's candidates (value_wei and gas_max_wei independently), not the sum.
func TestSumWindowMaxAcrossCandidates(t *testing.T) {
	now := now0()
	cf := &counterFile{Entries: []counterEntry{{
		ID: "e1", TS: now.Format(time.RFC3339Nano),
		Candidates: []counterCandidate{
			sCand("100", "10", candReserved),
			sCand("300", "5", candReserved), // RBF candidate: higher value, lower gas
			sCand("200", "20", candReserved),
		},
	}}}
	got := sumWindow(cf, now)
	// max value 300 + max gas 20 = 320 (NOT a per-candidate sum).
	if got.Cmp(big.NewInt(320)) != 0 {
		t.Fatalf("sumWindow = %s, want 320 (max value 300 + max gas 20)", got)
	}
}

// TestSumWindowPrefersActualGas confirms gas_actual_wei is preferred over
// gas_max_wei once a candidate settles (down-only).
func TestSumWindowPrefersActualGas(t *testing.T) {
	now := now0()
	actual := "3"
	cf := &counterFile{Entries: []counterEntry{{
		ID: "e1", TS: now.Format(time.RFC3339Nano),
		Candidates: []counterCandidate{{ValueWei: "0", GasMaxWei: "100", GasActualWei: &actual, State: candCommitted}},
	}}}
	got := sumWindow(cf, now)
	if got.Cmp(big.NewInt(3)) != 0 {
		t.Fatalf("sumWindow = %s, want 3 (gas_actual preferred over gas_max)", got)
	}
}

// TestSumWindowExcludesOldAndReleased confirms entries older than 24h are excluded
// from the sum, and a fully-released entry contributes nothing.
func TestSumWindowExcludesOldAndReleased(t *testing.T) {
	now := now0()
	old := now.Add(-25 * time.Hour)
	cf := &counterFile{Entries: []counterEntry{
		{ID: "old", TS: old.Format(time.RFC3339Nano), Candidates: []counterCandidate{sCand("1000", "0", candCommitted)}},
		{ID: "rel", TS: now.Format(time.RFC3339Nano), Candidates: []counterCandidate{sCand("500", "0", candReleased)}},
		{ID: "live", TS: now.Format(time.RFC3339Nano), Candidates: []counterCandidate{sCand("7", "0", candCommitted)}},
	}}
	got := sumWindow(cf, now)
	if got.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("sumWindow = %s, want 7 (old aged out, released excluded)", got)
	}
}

// TestSumWindowBoundaryExact pins the rolling-24h cutoff at the EXACT boundary
// (an off-by-one — Before vs !After, >= vs > — would otherwise pass every other
// test). sumWindow's cutoff is now−24h with ts.Before(cutoff) ⇒ an entry at
// exactly now−24h MUST still count (it is not strictly before the cutoff); an
// entry 1ns older MUST age out.
func TestSumWindowBoundaryExact(t *testing.T) {
	now := now0()
	atBoundary := now.Add(-24 * time.Hour)               // exactly now−24h ⇒ counts
	justPast := now.Add(-24*time.Hour - time.Nanosecond) // 1ns older ⇒ ages out
	cf := &counterFile{Entries: []counterEntry{
		{ID: "at", TS: atBoundary.Format(time.RFC3339Nano), Candidates: []counterCandidate{sCand("100", "0", candCommitted)}},
		{ID: "past", TS: justPast.Format(time.RFC3339Nano), Candidates: []counterCandidate{sCand("500", "0", candCommitted)}},
	}}
	got := sumWindow(cf, now)
	if got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("sumWindow at the 24h boundary = %s, want 100 (the exact-boundary entry counts, the 1ns-older one ages out)", got)
	}
}

// TestPruneDropsTerminalOldEntries confirms pruning drops entries older than 24h
// whose every candidate is terminal, and keeps in-window or non-terminal entries.
func TestPruneDropsTerminalOldEntries(t *testing.T) {
	now := now0()
	old := now.Add(-25 * time.Hour)
	settled := "1"
	cf := &counterFile{Entries: []counterEntry{
		{ID: "old-terminal", TS: old.Format(time.RFC3339Nano), Candidates: []counterCandidate{{ValueWei: "0", GasMaxWei: "1", GasActualWei: &settled, State: candCommitted}}},
		{ID: "old-reserved", TS: old.Format(time.RFC3339Nano), Candidates: []counterCandidate{sCand("0", "1", candReserved)}}, // non-terminal ⇒ kept
		{ID: "in-window", TS: now.Format(time.RFC3339Nano), Candidates: []counterCandidate{sCand("0", "1", candReleased)}},    // in window ⇒ kept
	}}
	pruneCounter(cf, now)
	ids := map[string]bool{}
	for _, e := range cf.Entries {
		ids[e.ID] = true
	}
	if ids["old-terminal"] {
		t.Fatal("an old, fully-terminal entry must be pruned")
	}
	if !ids["old-reserved"] || !ids["in-window"] {
		t.Fatalf("a non-terminal or in-window entry must be kept; got %+v", ids)
	}
}

// TestPerAccountFlockSerializes confirms the per-account lock serializes concurrent
// debits (the in-process mutex + flock), so the counted total reflects every debit.
func TestPerAccountFlockSerializes(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	acct := selfAcc
	net := "mainnet"

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = e.withNetworkLock(ctx, net, func() error {
				cf, err := e.loadCounter(net, acct)
				if err != nil {
					return err
				}
				cf.Entries = append(cf.Entries, counterEntry{
					ID: ulid(e.now()), TS: e.now().Format(time.RFC3339Nano),
					Candidates: []counterCandidate{sCand("1", "0", candCommitted)},
				})
				return e.writeCounter(net, acct, cf, e.now())
			})
		}()
	}
	wg.Wait()

	var total *big.Int
	_ = e.withNetworkLock(ctx, net, func() error {
		cf, err := e.loadCounter(net, acct)
		if err != nil {
			return err
		}
		total = sumWindow(cf, e.now())
		return nil
	})
	if total.Cmp(big.NewInt(n)) != 0 {
		t.Fatalf("serialized debits lost: total = %s, want %d (no lost updates)", total, n)
	}
}

// TestCounterCorruptIsStateError confirms an unparseable counter file fails closed
// as policy.state_error (counters unreadable, §4.9).
func TestCounterCorruptIsStateError(t *testing.T) {
	e := newEngine(t)
	net := "mainnet"
	acct := common.HexToAddress("0xdeadbeef00000000000000000000000000000000")
	ctx := context.Background()

	// Create the spend dir then write garbage to the counter path.
	if err := os.MkdirAll(filepath.Dir(e.counterPath(net, acct)), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(e.counterPath(net, acct), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}

	var loadErr error
	_ = e.withNetworkLock(ctx, net, func() error {
		_, loadErr = e.loadCounter(net, acct)
		return nil
	})
	if loadErr == nil {
		t.Fatal("a corrupt counter must fail closed")
	}
	assertCode(t, loadErr, "policy.state_error", domain.ExitTimeoutPending)
}
