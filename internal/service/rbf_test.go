package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// rbf_test.go covers §5.5: the +12.5% bump rule, re-quote-at-fast, the pinned
// nonce + replaces cross-link, the cancel 0-value-self-send shape, the
// already-mined precondition (exit 9), the foreign-hash refusal (exit 10), and
// the underpriced-override floor (exit 9).

// sendLowFee sends a tx with explicit low 1559 fees (maxFee 10gwei / tip 1gwei)
// so the bump rule has a clear floor to clear, returning the result. The
// canonical hash is the SIGNED hash (res.Hash) — the broadcast return value is
// ignored by the pipeline, so tests address records by res.Hash, not by the
// SendRawFn return.
func sendLowFee(t *testing.T, svc *Service, f *fake.Client, from, to common.Address) domain.TxResult {
	t.Helper()
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) { return common.HexToHash("0x0"), nil }
	req := txReq(from, to, "1")
	req.MaxFee = "10gwei"
	req.PriorityFee = "1gwei"
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), req, nil)
	if err != nil {
		t.Fatalf("low-fee SendTx: %v", err)
	}
	return res
}

func TestSpeedup_BumpsFeesAndLinks(t *testing.T) {
	from, to := someAddr(40), someAddr(41)
	svc, f, _ := sendService(t, from)

	res := sendLowFee(t, svc, f, from, to)

	// Re-quote at fast returns a modest tip; the +12.5% floor over the old fees
	// (10gwei/1gwei) should dominate: newTip ≥ ceil(1gwei×1.125)=1.125gwei,
	// newMaxFee ≥ ceil(10gwei×1.125)=11.25gwei.
	f.SuggestFeesFn = func(ctx context.Context, blocks int) (chain.Fees, error) {
		// tip 0.5gwei (all tiers), base 1gwei.
		return chain.Fees{
			BaseFee:        big.NewInt(1_000_000_000),
			PrioritySlow:   big.NewInt(500_000_000),
			PriorityNormal: big.NewInt(500_000_000),
			PriorityFast:   big.NewInt(500_000_000),
			Source:         "fee-history",
		}, nil
	}
	var newRaw []byte
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		newRaw = raw
		return common.HexToHash("0x0"), nil
	}

	sres, err := svc.Speedup(context.Background(), domain.LocalCLI(),
		domain.SpeedupRequest{Hash: res.Hash}, nil)
	if err != nil {
		t.Fatalf("Speedup: %v", err)
	}
	if newRaw == nil {
		t.Fatal("speedup did not broadcast a replacement")
	}
	if sres.Replaced != res.Hash {
		t.Errorf("Replaced = %q, want the original hash %q", sres.Replaced, res.Hash)
	}

	// The new record (addressed by the replacement's signed hash) pins the SAME
	// nonce and links replaces=res.Hash.
	newRec, jerr := svc.journal.ByHash(context.Background(), 1, common.HexToHash(sres.Hash))
	if jerr != nil {
		t.Fatalf("new record: %v", jerr)
	}
	if newRec.Nonce != res.Nonce {
		t.Errorf("replacement nonce = %d, want %d (pinned)", newRec.Nonce, res.Nonce)
	}
	if newRec.Replaces == nil || *newRec.Replaces != res.Hash {
		t.Errorf("replacement.replaces = %v, want %q", newRec.Replaces, res.Hash)
	}
	if newRec.Kind != journal.KindSpeedup {
		t.Errorf("kind = %q, want speedup", newRec.Kind)
	}
	// The bumped maxFee clears the +12.5% floor (≥ 11.25gwei).
	floor := big.NewInt(11_250_000_000)
	if newRec.Fees.MaxFeePerGas == nil || bigOrZero(*newRec.Fees.MaxFeePerGas).Cmp(floor) < 0 {
		t.Errorf("bumped maxFee = %v, want ≥ %s (+12.5%% floor)", newRec.Fees.MaxFeePerGas, floor)
	}

	// The original record is cross-linked (replaced_by → the new signed hash).
	origRec, _ := svc.journal.ByHash(context.Background(), 1, common.HexToHash(res.Hash))
	if origRec.ReplacedBy == nil || *origRec.ReplacedBy != sres.Hash {
		t.Errorf("original.replaced_by = %v, want %q", origRec.ReplacedBy, sres.Hash)
	}
}

func TestCancel_ZeroValueSelfSend(t *testing.T) {
	from, to := someAddr(42), someAddr(43)
	svc, f, _ := sendService(t, from)
	res := sendLowFee(t, svc, f, from, to)

	f.SuggestFeesFn = func(ctx context.Context, blocks int) (chain.Fees, error) {
		return chain.Fees{
			BaseFee:        big.NewInt(1),
			PrioritySlow:   big.NewInt(1),
			PriorityNormal: big.NewInt(1),
			PriorityFast:   big.NewInt(1),
			Source:         "fee-history",
		}, nil
	}
	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) { return common.HexToHash("0x0"), nil }

	cres, err := svc.Cancel(context.Background(), domain.LocalCLI(), domain.CancelRequest{Hash: res.Hash}, nil)
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	rec, _ := svc.journal.ByHash(context.Background(), 1, common.HexToHash(cres.Hash))
	if rec.To != from.Hex() {
		t.Errorf("cancel to = %q, want self %q", rec.To, from.Hex())
	}
	if rec.ValueWei != "0" {
		t.Errorf("cancel value = %q, want 0", rec.ValueWei)
	}
	if rec.Fees.GasLimit != 21000 {
		t.Errorf("cancel gas limit = %d, want 21000", rec.Fees.GasLimit)
	}
	if rec.Kind != journal.KindCancel {
		t.Errorf("kind = %q, want cancel", rec.Kind)
	}
	if rec.Nonce != res.Nonce {
		t.Errorf("cancel nonce = %d, want %d (pinned)", rec.Nonce, res.Nonce)
	}
}

func TestSpeedup_ForeignHash_Exit10(t *testing.T) {
	from := someAddr(44)
	svc, _, _ := sendService(t, from)
	// A well-formed (66-char) but unknown hash → ref.not_found (exit 10).
	foreign := "0x1100000000000000000000000000000000000000000000000000000000000000"
	_, err := svc.Speedup(context.Background(), domain.LocalCLI(), domain.SpeedupRequest{Hash: foreign}, nil)
	if err == nil || domain.AsError(err).Exit != domain.ExitNotFound {
		t.Fatalf("expected foreign-hash exit 10, got %v", err)
	}
}

func TestSpeedup_AlreadyMined_Exit9(t *testing.T) {
	from, to := someAddr(45), someAddr(46)
	svc, f, _ := sendService(t, from)
	res := sendLowFee(t, svc, f, from, to)

	// A receipt now exists for the original → already mined → exit 9.
	f.ReceiptFn = func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		return fakeReceipt(h, 5, 1), nil
	}
	_, err := svc.Speedup(context.Background(), domain.LocalCLI(), domain.SpeedupRequest{Hash: res.Hash}, nil)
	if err == nil || domain.AsError(err).Exit != domain.ExitTxConflict {
		t.Fatalf("expected already-mined exit 9, got %v", err)
	}
}

func TestSpeedup_UnderpricedOverride_Exit9(t *testing.T) {
	from, to := someAddr(47), someAddr(48)
	svc, f, _ := sendService(t, from)
	res := sendLowFee(t, svc, f, from, to) // old maxFee 10gwei

	f.SuggestFeesFn = func(ctx context.Context, blocks int) (chain.Fees, error) {
		return chain.Fees{
			BaseFee:        big.NewInt(1),
			PrioritySlow:   big.NewInt(1),
			PriorityNormal: big.NewInt(1),
			PriorityFast:   big.NewInt(1),
			Source:         "fee-history",
		}, nil
	}
	// No receipt for the original (still pending), so the precondition passes.
	f.ReceiptFn = func(ctx context.Context, h common.Hash) (*types.Receipt, error) {
		return nil, chain.ErrTxNotFound
	}
	// An explicit --max-fee BELOW the +12.5% floor (11.25gwei) → exit 9.
	_, err := svc.Speedup(context.Background(), domain.LocalCLI(),
		domain.SpeedupRequest{Hash: res.Hash, MaxFee: "10gwei", PriorityFee: "5gwei"}, nil)
	if err == nil || domain.AsError(err).Exit != domain.ExitTxConflict {
		t.Fatalf("expected underpriced-override exit 9, got %v", err)
	}
}
