package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// receive_eth_test.go is the PURE balance-delta math (§5.8) — the review-hunted
// own-outbound-fee correctness — exercised without the loop.

func TestBalanceDelta_PlainInbound(t *testing.T) {
	// Baseline 1 ETH; head 1.5 ETH; the 0.5 arrived via an INTERNAL transfer (no
	// direct inbound tx, no own outbound). unattributed = 0.5 − 0 + 0 + 0 = 0.5.
	baseline := eth(1)
	head := wei("1500000000000000000")
	u, clamped, newBaseline := balanceDelta(baseline, head, big.NewInt(0), big.NewInt(0), big.NewInt(0))
	if clamped {
		t.Fatal("a positive residue must not clamp")
	}
	if u.String() != "500000000000000000" {
		t.Fatalf("unattributed = %s, want 0.5 ETH", u)
	}
	if newBaseline.Cmp(head) != 0 {
		t.Fatalf("baseline must carry forward to the head balance (%s), got %s", head, newBaseline)
	}
}

func TestBalanceDelta_DirectInboundIsNotDoubleCounted(t *testing.T) {
	// Baseline 1 ETH; head 1.5; the whole 0.5 was an attributed direct inbound tx
	// (directIn=0.5). unattributed = 0.5 − 0.5 = 0 ⇒ no phantom balance-delta.
	u, clamped, _ := balanceDelta(eth(1), wei("1500000000000000000"), wei("500000000000000000"), big.NewInt(0), big.NewInt(0))
	if clamped {
		t.Fatal("must not clamp")
	}
	if u.Sign() != 0 {
		t.Fatalf("an attributed inbound must not also produce a balance-delta detection; unattributed = %s", u)
	}
}

func TestBalanceDelta_OwnOutboundAddsBackValuePlusActualFee(t *testing.T) {
	// We sent 0.3 ETH out paying a 0.001 ETH ACTUAL fee, and 0.5 ETH arrived
	// internally. Net balance change Δ = +0.5 − 0.3 − 0.001 = +0.199.
	// Baseline 1 ETH; head = 1.199 ETH.
	// unattributed = Δ − directIn + ownOut + ownFees
	//             = 0.199 − 0 + 0.3 + 0.001 = 0.5  ⇒ the internal inflow is recovered.
	delta := wei("199000000000000000")      // +0.199
	head := new(big.Int).Add(eth(1), delta) // 1.199 ETH
	ownOut := wei("300000000000000000")     // 0.3
	ownFees := wei("1000000000000000")      // 0.001 (ACTUAL)
	u, clamped, _ := balanceDelta(eth(1), head, big.NewInt(0), ownOut, ownFees)
	if clamped {
		t.Fatal("must not clamp")
	}
	if u.String() != "500000000000000000" {
		t.Fatalf("unattributed = %s, want 0.5 ETH (the internal inflow recovered via the own-fee correction)", u)
	}
}

func TestBalanceDelta_WorstCaseFeeWouldInflatePhantom(t *testing.T) {
	// SAME scenario as above but using a WORST-CASE fee (0.01 ETH, 10× the actual)
	// instead of the actual 0.001 — the bug the §5.8 non-negotiable forbids. With
	// the inflated fee, unattributed = 0.199 − 0 + 0.3 + 0.01 = 0.509 > the true
	// 0.5 — a PHANTOM extra 0.009 ETH inbound. This test documents WHY actual gas
	// is mandatory: the inflated term over-detects.
	delta := wei("199000000000000000")
	head := new(big.Int).Add(eth(1), delta)
	ownOut := wei("300000000000000000")
	worstCaseFee := wei("10000000000000000") // 0.01 — WRONG (worst-case, not actual)
	u, _, _ := balanceDelta(eth(1), head, big.NewInt(0), ownOut, worstCaseFee)
	if u.String() == "500000000000000000" {
		t.Fatal("worst-case fee should NOT reproduce the correct 0.5; it inflates — confirming actual gas is required")
	}
	if u.String() != "509000000000000000" {
		t.Fatalf("inflated unattributed = %s, want 0.509 (the phantom), confirming the inflation mechanism", u)
	}
}

func TestBalanceDelta_NegativeResidueClampsAndWarns(t *testing.T) {
	// ETH left via a path the scan can't see (an internal CALL outflow we cannot
	// observe). Δ = −0.2; directIn 0; ownOut 0; ownFees 0 ⇒ unattributed = −0.2.
	// Must clamp to zero + warn, never a phantom negative inbound. Baseline still
	// carries forward.
	head := wei("800000000000000000") // 0.8 ETH (down from 1)
	u, clamped, newBaseline := balanceDelta(eth(1), head, big.NewInt(0), big.NewInt(0), big.NewInt(0))
	if !clamped {
		t.Fatal("a negative residue MUST clamp+warn (§5.8)")
	}
	if u.Sign() != 0 {
		t.Fatalf("clamped residue must be zero, got %s (never a phantom negative inbound)", u)
	}
	if newBaseline.Cmp(head) != 0 {
		t.Fatalf("baseline must still carry forward on a clamp, got %s want %s", newBaseline, head)
	}
}

func TestOwnFeesActual_UsesReceiptGasUsedTimesEffectivePrice(t *testing.T) {
	// gasUsed 21000 × effectiveGasPrice 50 gwei = 1_050_000 gwei = 0.00105 ETH.
	h := common.HexToHash("0xfee1")
	f := fake.New()
	f.ReceiptFn = func(_ context.Context, got common.Hash) (*types.Receipt, error) {
		if got != h {
			t.Fatalf("Receipt for %s, want %s", got.Hex(), h.Hex())
		}
		return &types.Receipt{
			GasUsed:           21000,
			EffectiveGasPrice: gwei(50),
			Status:            types.ReceiptStatusSuccessful,
		}, nil
	}
	var svc Service
	total, err := svc.ownFeesActual(context.Background(), f, nil, []common.Hash{h})
	if err != nil {
		t.Fatalf("ownFeesActual: %v", err)
	}
	want := new(big.Int).Mul(big.NewInt(21000), gwei(50))
	if total.Cmp(want) != 0 {
		t.Fatalf("ownFees = %s, want %s (gasUsed×effectiveGasPrice)", total, want)
	}
}

func TestOwnFeesActual_LegacyReceiptFallsBackToTxGasPrice(t *testing.T) {
	// A legacy receipt with no EffectiveGasPrice falls back to the tx's GasPrice
	// (read from the block). gasUsed 21000 × gasPrice 30 gwei.
	from := someAddr(99)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		To:       &from,
		Value:    big.NewInt(0),
		Gas:      21000,
		GasPrice: gwei(30),
	})
	blk := blockWithTxs(7, []*types.Transaction{tx})
	f := fake.New()
	f.ReceiptFn = func(_ context.Context, _ common.Hash) (*types.Receipt, error) {
		return &types.Receipt{GasUsed: 21000, EffectiveGasPrice: nil, Status: 1}, nil
	}
	var svc Service
	total, err := svc.ownFeesActual(context.Background(), f, blk, []common.Hash{tx.Hash()})
	if err != nil {
		t.Fatalf("ownFeesActual: %v", err)
	}
	want := new(big.Int).Mul(big.NewInt(21000), gwei(30))
	if total.Cmp(want) != 0 {
		t.Fatalf("ownFees(legacy) = %s, want %s (gasUsed×tx.GasPrice fallback)", total, want)
	}
}

// ── small numeric + block helpers shared by the receive service tests ──

func eth(n int64) *big.Int  { return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e18)) }
func gwei(n int64) *big.Int { return new(big.Int).Mul(big.NewInt(n), big.NewInt(1e9)) }
func wei(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad wei literal " + s)
	}
	return v
}

// blockWithTxs builds a types.Block at height n carrying txs. The header number is
// set so blk.NumberU64()==n; the hash is derived from the header (stable for a
// given header). Tests use it to drive the ETH block-scan.
func blockWithTxs(n uint64, txs []*types.Transaction) *types.Block {
	h := &types.Header{Number: new(big.Int).SetUint64(n)}
	return types.NewBlockWithHeader(h).WithBody(types.Body{Transactions: txs})
}
