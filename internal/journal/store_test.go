package journal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// ── shared test helpers ─────────────────────────────────────────────────────────

// fixedClock returns a deterministic monotonically-stepping clock so record `ts`
// values are reproducible in tests (the determinism guard does not cover journal,
// but tests still pin time for stable assertions).
func fixedClock() func() time.Time {
	base := time.Date(2026, 6, 15, 17, 4, 5, 0, time.UTC)
	var n int64
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Millisecond)
		n++
		return t
	}
}

// newTestStore opens a journal store rooted at a fresh temp dir with the fixed clock.
func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, fixedClock())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s, dir
}

// silenceWarnings routes the store's torn/corrupt-line and single-writer warnings
// to a buffer for the duration of the test, returning the buffer so assertions can
// check a warning fired. The sinks are per-Store (no package globals), so parallel
// tests never race on them.
func silenceWarnings(t *testing.T, s *Store) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	s.SetWarnSinks(&buf, &buf)
	return &buf
}

// strptr is a *string helper for the schema's pointer fields.
func strptr(s string) *string { return &s }

// ethTransfer builds a minimal ETH-transfer signed record for chainID/from/nonce.
func ethTransfer(chainID uint64, from common.Address, nonce uint64, resID, rawTx string) *Record {
	return &Record{
		ChainID:         chainID,
		Network:         "test",
		Kind:            KindETHTransfer,
		Status:          StatusSigned,
		Source:          "cli",
		From:            from.Hex(),
		To:              common.HexToAddress("0x1111111111111111111111111111111111111111").Hex(),
		Nonce:           nonce,
		RawTx:           rawTx,
		ValueWei:        "1000000000000000000",
		Asset:           Asset{Kind: "eth", Amount: strptr("1000000000000000000")},
		Fees:            Fees{Type: "eip1559", GasLimit: 21000, MaxFeePerGas: strptr("30000000000"), MaxPriorityPerGas: strptr("1000000000"), Speed: "normal"},
		ReservationID:   resID,
		WorstCaseGasWei: "630000000000000",
		RPC:             "test-rpc",
	}
}

var testAddr = common.HexToAddress("0x52ae0000000000000000000000000000000000aa")

// ── tests ───────────────────────────────────────────────────────────────────────

func TestOpenLazyNoFilesUntilAppend(t *testing.T) {
	t.Parallel()
	s, dir := newTestStore(t)
	ctx := context.Background()

	// A fresh store must read as empty without creating anything.
	recs, err := s.List(ctx, 1, common.Address{})
	if err != nil {
		t.Fatalf("List on empty: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected empty list, got %d", len(recs))
	}
	// List takes the read path which ensureDirs (creates journal/ + locks/) — that is
	// allowed; what must NOT exist is the per-chain journal FILE before any append.
	if _, err := os.Stat(filepath.Join(dir, "journal", "1.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal file should not exist before append; stat err = %v", err)
	}
}

func TestAppendAssignsSeqIDTS(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	r1 := ethTransfer(1, testAddr, 0, "res-1", "0xaa")
	if err := s.Append(ctx, r1); err != nil {
		t.Fatalf("Append r1: %v", err)
	}
	if r1.Seq != 1 {
		t.Errorf("r1.Seq = %d, want 1", r1.Seq)
	}
	if len(r1.ID) != ulidLen {
		t.Errorf("r1.ID = %q (len %d), want a %d-char ULID", r1.ID, len(r1.ID), ulidLen)
	}
	if r1.TS == "" {
		t.Errorf("r1.TS should be stamped")
	}
	if r1.V != recordVersion {
		t.Errorf("r1.V = %d, want %d", r1.V, recordVersion)
	}

	r2 := ethTransfer(1, testAddr, 1, "res-2", "0xbb")
	if err := s.Append(ctx, r2); err != nil {
		t.Fatalf("Append r2: %v", err)
	}
	if r2.Seq != 2 {
		t.Errorf("r2.Seq = %d, want 2", r2.Seq)
	}
	if r1.ID == r2.ID {
		t.Errorf("ULIDs must be unique")
	}
}

func TestSetStateLastWinsPerID(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	r := ethTransfer(1, testAddr, 0, "res-1", "0xaa")
	if err := s.Append(ctx, r); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// signed -> broadcast (sets hash) -> mined (sets receipt) -> confirmed.
	if err := s.SetState(ctx, 1, r.ID, StateMutation{Status: StatusBroadcast, TxHash: strptr("0x9c1f")}); err != nil {
		t.Fatalf("SetState broadcast: %v", err)
	}
	rec := &Receipt{BlockNumber: 100, BlockHash: "0x77aa", GasUsed: 21000, EffectiveGasPrice: "12100000000", Status: 1}
	if err := s.SetState(ctx, 1, r.ID, StateMutation{Status: StatusMined, Receipt: rec}); err != nil {
		t.Fatalf("SetState mined: %v", err)
	}
	if err := s.SetState(ctx, 1, r.ID, StateMutation{Status: StatusConfirmed}); err != nil {
		t.Fatalf("SetState confirmed: %v", err)
	}

	got, err := s.ByReservation(ctx, 1, "res-1")
	if err != nil {
		t.Fatalf("ByReservation: %v", err)
	}
	if got.Status != StatusConfirmed {
		t.Errorf("folded status = %q, want confirmed", got.Status)
	}
	// fields from intermediate transitions must be carried forward (copy-from-prior).
	if got.TxHash != "0x9c1f" {
		t.Errorf("tx_hash lost across transitions: %q", got.TxHash)
	}
	if got.Receipt == nil || got.Receipt.Status != 1 {
		t.Errorf("receipt lost across transitions: %+v", got.Receipt)
	}
	if got.RawTx != "0xaa" {
		t.Errorf("raw_tx lost across transitions: %q", got.RawTx)
	}
}

func TestSetStateUnknownIDIsNotFound(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	err := s.SetState(ctx, 1, "01J9ZD3A6K2Q4XH8YQ0VBM5T2N", StateMutation{Status: StatusBroadcast})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestByReservationChainScoped(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Same reservation id string on two different chains must resolve independently.
	r1 := ethTransfer(1, testAddr, 0, "shared-res", "0xaa")
	r5 := ethTransfer(5, testAddr, 0, "shared-res", "0xbb")
	if err := s.Append(ctx, r1); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, r5); err != nil {
		t.Fatal(err)
	}

	got1, err := s.ByReservation(ctx, 1, "shared-res")
	if err != nil {
		t.Fatalf("chain 1: %v", err)
	}
	if got1.RawTx != "0xaa" || got1.ChainID != 1 {
		t.Errorf("chain 1 resolved wrong record: %+v", got1)
	}
	got5, err := s.ByReservation(ctx, 5, "shared-res")
	if err != nil {
		t.Fatalf("chain 5: %v", err)
	}
	if got5.RawTx != "0xbb" || got5.ChainID != 5 {
		t.Errorf("chain 5 resolved wrong record: %+v", got5)
	}

	// A reservation absent on a chain is ErrNotFound, not a cross-chain bleed.
	if _, err := s.ByReservation(ctx, 999, "shared-res"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound on chain 999, got %v", err)
	}
}

func TestByHash(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	hash := common.HexToHash("0x9c1f000000000000000000000000000000000000000000000000000000000000")

	r := ethTransfer(1, testAddr, 0, "res-1", "0xaa")
	if err := s.Append(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, 1, r.ID, StateMutation{Status: StatusBroadcast, TxHash: strptr(hash.Hex())}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ByHash(ctx, 1, hash)
	if err != nil {
		t.Fatalf("ByHash: %v", err)
	}
	if got.ID != r.ID {
		t.Errorf("ByHash resolved %s, want %s", got.ID, r.ID)
	}
	if _, err := s.ByHash(ctx, 1, common.HexToHash("0xdead")); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for unknown hash, got %v", err)
	}
}

func TestUnresolvedExcludesTerminal(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	// pending (non-terminal), confirmed (terminal), failed (terminal).
	pend := ethTransfer(1, testAddr, 0, "res-pend", "0xaa")
	conf := ethTransfer(1, testAddr, 1, "res-conf", "0xbb")
	fail := ethTransfer(1, testAddr, 2, "res-fail", "0xcc")
	for _, r := range []*Record{pend, conf, fail} {
		if err := s.Append(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetState(ctx, 1, pend.ID, StateMutation{Status: StatusPending, TxHash: strptr("0x01")}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, 1, conf.ID, StateMutation{Status: StatusConfirmed}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, 1, fail.ID, StateMutation{Status: StatusFailed}); err != nil {
		t.Fatal(err)
	}

	un, err := s.Unresolved(ctx, 1)
	if err != nil {
		t.Fatalf("Unresolved: %v", err)
	}
	if len(un) != 1 || un[0].ID != pend.ID {
		t.Fatalf("Unresolved = %d records, want only the pending one; got %+v", len(un), un)
	}
}

func TestListFiltersByFromNewestFirst(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	other := common.HexToAddress("0x52ae0000000000000000000000000000000000bb")

	a0 := ethTransfer(1, testAddr, 0, "res-a0", "0xa0")
	a1 := ethTransfer(1, testAddr, 1, "res-a1", "0xa1")
	b0 := ethTransfer(1, other, 0, "res-b0", "0xb0")
	for _, r := range []*Record{a0, a1, b0} {
		if err := s.Append(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	// from = testAddr: only a0/a1, newest-first (a1 then a0 by seq).
	mine, err := s.List(ctx, 1, testAddr)
	if err != nil {
		t.Fatalf("List(from): %v", err)
	}
	if len(mine) != 2 {
		t.Fatalf("List(from) = %d, want 2", len(mine))
	}
	if mine[0].Seq < mine[1].Seq {
		t.Errorf("List not newest-first: %d then %d", mine[0].Seq, mine[1].Seq)
	}

	// from = zero addr: all three.
	all, err := s.List(ctx, 1, common.Address{})
	if err != nil {
		t.Fatalf("List(all): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("List(all) = %d, want 3", len(all))
	}
}

func TestTornFinalLineTruncatedOnAppendPath(t *testing.T) {
	t.Parallel()
	s, dir := newTestStore(t)
	ctx := context.Background()
	buf := silenceWarnings(t, s)

	// Lay down one complete record, then a torn (no-newline) partial tail by hand.
	r := ethTransfer(1, testAddr, 0, "res-1", "0xaa")
	if err := s.Append(ctx, r); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "journal", "1.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":1,"id":"PARTIAL","seq":2,"sta`); err != nil { // torn, no newline
		t.Fatal(err)
	}
	_ = f.Close()

	// A subsequent append (exclusive lock) must repair the torn tail and assign seq 2
	// (the partial seq-2 line is dropped, not counted).
	r2 := ethTransfer(1, testAddr, 1, "res-2", "0xbb")
	if err := s.Append(ctx, r2); err != nil {
		t.Fatalf("Append after torn tail: %v", err)
	}
	if r2.Seq != 2 {
		t.Errorf("r2.Seq = %d, want 2 (torn partial must not bump the seq)", r2.Seq)
	}
	if !bytes.Contains(buf.Bytes(), []byte("torn final line")) {
		t.Errorf("expected a torn-final-line warning; got %q", buf.String())
	}

	// The PARTIAL id must NOT survive in any query.
	all, err := s.List(ctx, 1, common.Address{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rr := range all {
		if rr.ID == "PARTIAL" {
			t.Errorf("torn PARTIAL record survived: %+v", rr)
		}
	}
	if len(all) != 2 {
		t.Errorf("List = %d, want 2 (r and r2)", len(all))
	}
}

func TestCorruptMidFileLineSkipped(t *testing.T) {
	t.Parallel()
	s, dir := newTestStore(t)
	ctx := context.Background()
	buf := silenceWarnings(t, s)

	r1 := ethTransfer(1, testAddr, 0, "res-1", "0xaa")
	if err := s.Append(ctx, r1); err != nil {
		t.Fatal(err)
	}
	// Inject a corrupt but newline-terminated line in the MIDDLE.
	path := filepath.Join(dir, "journal", "1.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("this is not json\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	r2 := ethTransfer(1, testAddr, 1, "res-2", "0xbb")
	if err := s.Append(ctx, r2); err != nil {
		t.Fatalf("Append after corrupt mid line: %v", err)
	}

	all, err := s.List(ctx, 1, common.Address{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("List = %d, want 2 (corrupt line skipped, r1+r2 kept)", len(all))
	}
	if !bytes.Contains(buf.Bytes(), []byte("skipping corrupt line")) {
		t.Errorf("expected a corrupt-line warning; got %q", buf.String())
	}
}

func TestCompactionPreservesTerminalHistory(t *testing.T) {
	t.Parallel()
	s, dir := newTestStore(t)
	ctx := context.Background()

	// Drive enough superseded transitions to cross the compaction threshold. Each id
	// gets many SetState lines (all but the last are superseded). We use a handful of
	// ids transitioned to terminal states, then force compaction directly and assert
	// the folded snapshot keeps the terminal records.
	ids := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		r := ethTransfer(1, testAddr, uint64(i), "res-"+string(rune('a'+i)), "0x0"+string(rune('a'+i)))
		if err := s.Append(ctx, r); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
		// pending -> confirmed (two superseded transitions per id)
		if err := s.SetState(ctx, 1, r.ID, StateMutation{Status: StatusPending, TxHash: strptr("0x0" + string(rune('a'+i)) + "hash")}); err != nil {
			t.Fatal(err)
		}
		if err := s.SetState(ctx, 1, r.ID, StateMutation{Status: StatusConfirmed}); err != nil {
			t.Fatal(err)
		}
	}

	// Read pre-compaction record count from disk (signed + 2 transitions = 3 lines/id).
	before := countLines(t, filepath.Join(dir, "journal", "1.jsonl"))
	if before < 15 {
		t.Fatalf("expected >=15 lines before compaction, got %d", before)
	}

	// Force a compaction directly under the lock (the threshold-based maybeCompact is
	// exercised via the size/line counts; here we assert compact() itself preserves
	// terminal records and shrinks the file).
	if err := s.withLock(ctx, 1, func() error {
		recs, _, err := s.readAll(1, true)
		if err != nil {
			return err
		}
		return s.compact(1, foldLatest(recs))
	}); err != nil {
		t.Fatalf("compact: %v", err)
	}

	after := countLines(t, filepath.Join(dir, "journal", "1.jsonl"))
	if after != len(ids) {
		t.Errorf("after compaction = %d lines, want %d (one terminal snapshot per id)", after, len(ids))
	}

	// Every terminal record must still resolve to confirmed (history kept).
	for i, id := range ids {
		got, err := s.ByReservation(ctx, 1, "res-"+string(rune('a'+i)))
		if err != nil {
			t.Fatalf("ByReservation after compaction (%s): %v", id, err)
		}
		if got.Status != StatusConfirmed {
			t.Errorf("compacted record %s status = %q, want confirmed", id, got.Status)
		}
	}
}

// countLines counts non-empty lines in a file (helper for compaction assertions).
func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	n := 0
	for _, l := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(l)) > 0 {
			n++
		}
	}
	return n
}

// readerErr is an io.Reader that always errors, used to prove ULID generation
// surfaces an entropy failure rather than emitting a weak id.
type readerErr struct{}

func (readerErr) Read(p []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestAppendFailsOnEntropyError(t *testing.T) {
	// Not parallel: mutates the package randReader.
	s, _ := newTestStore(t)
	ctx := context.Background()
	old := randReader
	randReader = readerErr{}
	t.Cleanup(func() { randReader = old })

	r := ethTransfer(1, testAddr, 0, "res-1", "0xaa")
	if err := s.Append(ctx, r); err == nil {
		t.Fatalf("expected Append to fail when entropy source errors")
	}
}
