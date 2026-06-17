package service

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/ethereum/go-ethereum/common"
)

// fakeClientStrand wraps a fake chain client with a broadcast toggle: while
// failBroadcast is true, SendRawTransaction returns a transport error (stranding a
// `signed` record); flip it false to let the resurrection rebroadcast succeed. It
// records the last rebroadcast bytes so a test can assert the SAME raw_tx was sent.
type fakeClientStrand struct {
	*fake.Client
	failBroadcast    atomic.Bool
	mu               sync.Mutex
	rebroadcastBytes []byte
}

// newStrand builds the strand wrapper over a fresh fake and wires SendRawFn to the
// toggle. The fake's other methods (Receipt default ErrTxNotFound, Nonce 0, etc.)
// are inherited unchanged.
func newStrand() *fakeClientStrand {
	f := fake.New()
	s := &fakeClientStrand{Client: f}
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		if s.failBroadcast.Load() {
			return common.Hash{}, errString("dial tcp: connection refused")
		}
		s.mu.Lock()
		s.rebroadcastBytes = append([]byte(nil), raw...)
		s.mu.Unlock()
		return common.HexToHash("0x0"), nil
	}
	return s
}

// strandService opens a send-ready service whose chain client is the strand
// wrapper. It mirrors sendService but returns the strand so the toggle is reachable.
func strandService(t *testing.T, from common.Address) (*Service, *fakeClientStrand, *fakeSigner) {
	t.Helper()
	strand := newStrand()
	svc := openWithProvider(t, &stubProvider{cc: strand})
	sgn := &fakeSigner{addr: from}
	svc.signer = sgn
	svc.secretIO = SecretIO{LookupEnv: func(k string) (string, bool) {
		if k == "DAXIE_PASSPHRASE" {
			return "test-pass", true
		}
		return "", false
	}}
	return svc, strand, sgn
}

// resurrect_test.go proves the §5.6 AUTOMATIC restart reconciliation: a
// transport-exhausted send leaves a `signed` record (raw_tx persisted, no recorded
// broadcast), and a subsequent `tx status` / `tx list` / next send — with the chain
// reachable again — auto-rebroadcasts the SAME bytes through the shared
// receipt-first helper, flipping the record to `broadcast`. Before the fix this was
// recoverable ONLY via an explicit `tx wait <hash>`; now status/list/send recover it.

// strandSigned drives a transport-exhausted send so a `signed` record is left
// behind (the recovery-rebroadcast source), and returns the stranded record.
func strandSigned(t *testing.T, svc *Service, f *fakeClientStrand, from, to common.Address) *journal.Record {
	t.Helper()
	f.failBroadcast.Store(true)
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err == nil {
		t.Fatal("expected a transport error to strand a signed record")
	}
	rec := recordByNonce(t, svc, from, 0)
	if rec.Status != journal.StatusSigned {
		t.Fatalf("stranded record status = %q, want signed", rec.Status)
	}
	return rec
}

func TestResurrect_TxStatus_RebroadcastsSignedRecord(t *testing.T) {
	from, to := someAddr(30), someAddr(31)
	svc, raw, _ := strandService(t, from)
	rec := strandSigned(t, svc, raw, from, to)

	// Chain reachable again; no receipt for our hash yet (still unknown/pending) →
	// resurrection rebroadcasts the SAME bytes.
	raw.failBroadcast.Store(false)
	_, err := svc.TxStatus(context.Background(), domain.LocalCLI(),
		domain.TxStatusRequest{Hash: rec.TxHash}, nil)
	if err != nil {
		t.Fatalf("TxStatus: %v", err)
	}

	// The record was auto-resurrected to `broadcast`.
	rec2, _ := svc.journal.ByID(context.Background(), 1, rec.ID)
	if rec2.Status != journal.StatusBroadcast {
		t.Errorf("after tx status, record status = %q, want broadcast (auto-resurrected)", rec2.Status)
	}
	if raw.rebroadcastBytes == nil {
		t.Fatal("tx status did not rebroadcast the stranded signed record")
	}
	// The rebroadcast bytes are the SAME persisted raw_tx (idempotent, same hash).
	if want := "0x" + hexBytes(raw.rebroadcastBytes)[2:]; want != rec.RawTx {
		t.Errorf("rebroadcast bytes = %s, want the stored raw_tx %s", want, rec.RawTx)
	}
}

func TestResurrect_ListTxs_RebroadcastsSignedRecord(t *testing.T) {
	from, to := someAddr(32), someAddr(33)
	svc, raw, _ := strandService(t, from)
	rec := strandSigned(t, svc, raw, from, to)

	raw.failBroadcast.Store(false)
	if _, err := svc.ListTxs(context.Background(), domain.LocalCLI(), domain.TxListRequest{}); err != nil {
		t.Fatalf("ListTxs: %v", err)
	}
	rec2, _ := svc.journal.ByID(context.Background(), 1, rec.ID)
	if rec2.Status != journal.StatusBroadcast {
		t.Errorf("after tx list, record status = %q, want broadcast (auto-resurrected)", rec2.Status)
	}
}

func TestResurrect_NextSend_RebroadcastsSignedRecord(t *testing.T) {
	from, to := someAddr(34), someAddr(35)
	svc, raw, _ := strandService(t, from)
	rec := strandSigned(t, svc, raw, from, to)

	// A NEXT send (chain reachable) runs the resurrection at lock acquisition BEFORE
	// deriving its own nonce — the stranded nonce-0 record is rebroadcast and the new
	// send takes nonce 1 (the stranded nonce is durably consumed, never re-allocated).
	raw.failBroadcast.Store(false)
	res2, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("next SendTx: %v", err)
	}
	rec0, _ := svc.journal.ByID(context.Background(), 1, rec.ID)
	if rec0.Status != journal.StatusBroadcast {
		t.Errorf("stranded record status = %q, want broadcast (resurrected at next send's lock)", rec0.Status)
	}
	if res2.Nonce != 1 {
		t.Errorf("next send nonce = %d, want 1 (stranded nonce 0 is consumed, not re-allocated)", res2.Nonce)
	}
}
