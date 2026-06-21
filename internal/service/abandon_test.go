package service

import (
	"context"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
)

// abandon_test.go covers the §5.6 operator escape hatch (service.AbandonTx, now
// reachable via `daxie tx abandon`): voiding a SIGNED-but-never-broadcast record
// marks it failed, releases its reservation, and frees the nonce; a broadcast
// record is refused; an unknown hash is ref.not_found.

func TestAbandonTx_VoidsSignedRecord_FreesNonce(t *testing.T) {
	from, to := someAddr(40), someAddr(41)
	svc, raw, _ := strandService(t, from)
	rec := strandSigned(t, svc, raw, from, to) // signed-never-broadcast, nonce 0, holds a reservation

	res, err := svc.AbandonTx(context.Background(), domain.LocalCLI(),
		domain.AbandonRequest{Hash: rec.TxHash})
	if err != nil {
		t.Fatalf("AbandonTx: %v", err)
	}
	if !res.Abandoned || res.JournalID != rec.ID {
		t.Fatalf("AbandonResult = %+v, want abandoned=true journal=%s", res, rec.ID)
	}

	rec2, _ := svc.journal.ByID(context.Background(), 1, rec.ID)
	if rec2.Status != journal.StatusFailed {
		t.Errorf("record status = %q, want failed", rec2.Status)
	}

	// The nonce is freed: with the chain reachable, the next send reuses nonce 0
	// (NextNonce folds only non-failed records) and the abandoned record is NOT
	// resurrected (resurrection acts only on `signed`).
	raw.failBroadcast.Store(false)
	res2, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("next SendTx: %v", err)
	}
	if res2.Nonce != 0 {
		t.Errorf("next send nonce = %d, want 0 (the abandoned nonce is reused)", res2.Nonce)
	}
}

func TestAbandonTx_RefusesBroadcastRecord(t *testing.T) {
	from, to := someAddr(42), someAddr(43)
	svc, _, _ := strandService(t, from) // failBroadcast defaults false → SendTx broadcasts
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), txReq(from, to, "1"), nil)
	if err != nil {
		t.Fatalf("SendTx: %v", err)
	}
	_, aerr := svc.AbandonTx(context.Background(), domain.LocalCLI(),
		domain.AbandonRequest{Hash: res.Hash})
	if aerr == nil {
		t.Fatal("abandoning a broadcast tx must be refused (it may yet mine)")
	}
	if got := domain.AsError(aerr).Exit; got != domain.ExitUsage {
		t.Errorf("abandon-broadcast exit = %d, want %d (usage)", got, domain.ExitUsage)
	}
}

func TestAbandonTx_UnknownHash(t *testing.T) {
	svc, _, _ := strandService(t, someAddr(44))
	_, err := svc.AbandonTx(context.Background(), domain.LocalCLI(),
		domain.AbandonRequest{Hash: "0x" + strings.Repeat("ab", 32)})
	if err == nil {
		t.Fatal("abandoning an unknown hash must error")
	}
	if got := domain.AsError(err).Code; got != domain.CodeRefNotFound {
		t.Errorf("unknown-hash code = %q, want %q", got, domain.CodeRefNotFound)
	}
}
