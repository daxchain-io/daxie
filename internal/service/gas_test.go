package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	ethereum "github.com/ethereum/go-ethereum"
)

// gas_test.go covers the §5.4 gas engine: speed presets, the limit multiplier +
// the 21000 EOA exception, the max-fee formula headroom, partial overrides, legacy
// mode, and the bad-flag refusals. It exercises buildGas via an Intent + the
// public Gas use case; both consume chain.SuggestFees from the fake.

// fakeFees programs the fake to return fixed 1559 fees: the same tip for all three
// speed tiers, the given base fee, from one SuggestFees call (maxFee is ignored —
// the gas engine derives it from the formula). It mirrors the new single-call,
// three-tier SuggestFees shape (§5.4).
func fakeFees(f *fake.Client, _maxFee, tip, baseFee int64) {
	f.SuggestFeesFn = func(ctx context.Context, blocks int) (chain.Fees, error) {
		return chain.Fees{
			BaseFee:        big.NewInt(baseFee),
			PrioritySlow:   big.NewInt(tip),
			PriorityNormal: big.NewInt(tip),
			PriorityFast:   big.NewInt(tip),
			Source:         "fee-history",
		}, nil
	}
}

func TestGas_ThreeSpeeds1559(t *testing.T) {
	f := fake.New()
	// Different tip per speed tier so the rows differ — ONE SuggestFees call
	// returns all three (slow=1/normal=5/fast=9).
	f.SuggestFeesFn = func(ctx context.Context, blocks int) (chain.Fees, error) {
		return chain.Fees{
			BaseFee:        big.NewInt(100),
			PrioritySlow:   big.NewInt(1),
			PriorityNormal: big.NewInt(5),
			PriorityFast:   big.NewInt(9),
			Source:         "fee-history",
		}, nil
	}
	svc := openWithProvider(t, &stubProvider{cc: f})
	// Disable the min-priority-fee floor for this test so the small per-speed tips
	// (1/5/9) pass through the formula unchanged; the floor itself is covered by
	// TestGas_MinPriorityFloor.
	svc.cfg.Gas.MinPriorityFee = "0"

	res, err := svc.Gas(context.Background(), domain.LocalCLI(), domain.GasRequest{}, nil)
	if err != nil {
		t.Fatalf("Gas: %v", err)
	}
	// max-fee = 2.0 × baseFee(100) + tip.
	if res.Slow.MaxFeePerGas != "201" { // 200 + 1
		t.Errorf("slow maxFee = %q, want 201", res.Slow.MaxFeePerGas)
	}
	if res.Normal.MaxFeePerGas != "205" {
		t.Errorf("normal maxFee = %q, want 205", res.Normal.MaxFeePerGas)
	}
	if res.Fast.MaxFeePerGas != "209" {
		t.Errorf("fast maxFee = %q, want 209", res.Fast.MaxFeePerGas)
	}
	if res.BaseFee != "100" {
		t.Errorf("baseFee = %q, want 100", res.BaseFee)
	}
	// §5.4: `daxie gas` prints all three speed quotes from ONE feeHistory call.
	if calls := f.CallsFor("SuggestFees"); len(calls) != 1 {
		t.Errorf("daxie gas made %d SuggestFees calls, want 1 (one feeHistory call serves all three speeds)", len(calls))
	}
}

// TestGas_FeeHistoryBlocksFromConfig asserts the configured gas.fee-history-blocks
// window is plumbed into the single SuggestFees call (not a hardcoded const).
func TestGas_FeeHistoryBlocksFromConfig(t *testing.T) {
	f := fake.New()
	var gotBlocks int
	f.SuggestFeesFn = func(ctx context.Context, blocks int) (chain.Fees, error) {
		gotBlocks = blocks
		return chain.Fees{
			BaseFee:        big.NewInt(100),
			PrioritySlow:   big.NewInt(1),
			PriorityNormal: big.NewInt(5),
			PriorityFast:   big.NewInt(9),
			Source:         "fee-history",
		}, nil
	}
	svc := openWithProvider(t, &stubProvider{cc: f})
	// The built-in default is 20.
	if _, err := svc.Gas(context.Background(), domain.LocalCLI(), domain.GasRequest{}, nil); err != nil {
		t.Fatalf("Gas: %v", err)
	}
	if gotBlocks != 20 {
		t.Errorf("SuggestFees window = %d, want 20 (the gas.fee-history-blocks default)", gotBlocks)
	}
}

func TestGas_MinPriorityFloor(t *testing.T) {
	f := fake.New()
	// A tip of 0 must be floored to the config min-priority-fee (0.01gwei =
	// 10_000_000 wei).
	fakeFees(f, 0, 0, 100)
	svc := openWithProvider(t, &stubProvider{cc: f})
	res, err := svc.Gas(context.Background(), domain.LocalCLI(), domain.GasRequest{}, nil)
	if err != nil {
		t.Fatalf("Gas: %v", err)
	}
	if res.Normal.PriorityFee != "10000000" {
		t.Errorf("priority fee floor = %q, want 10000000 (0.01gwei)", res.Normal.PriorityFee)
	}
}

func TestBuildGas_21000Exception(t *testing.T) {
	f := fake.New()
	f.EstimateGasFn = func(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
		return 21000, nil
	}
	fakeFees(f, 0, 5, 100)
	svc := openWithProvider(t, &stubProvider{cc: f})

	in := &Intent{network: "mainnet", to: someAddr(1), value: big.NewInt(0)}
	q, err := svc.buildGas(context.Background(), f, in, domain.TxRequest{})
	if err != nil {
		t.Fatalf("buildGas: %v", err)
	}
	// The 21000 estimate is used AS-IS (no ×1.2 headroom) for a plain EOA transfer.
	if q.GasLimit != 21000 {
		t.Errorf("gas limit = %d, want 21000 (EOA exception, no multiplier)", q.GasLimit)
	}
}

func TestBuildGas_LimitMultiplierRoundsUp(t *testing.T) {
	f := fake.New()
	f.EstimateGasFn = func(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
		return 50000, nil // a contract-ish estimate → ×1.2 = 60000
	}
	fakeFees(f, 0, 5, 100)
	svc := openWithProvider(t, &stubProvider{cc: f})

	// Non-empty data so the 21000 exception does NOT apply (and the estimate isn't
	// 21000 anyway).
	in := &Intent{network: "mainnet", to: someAddr(1), value: big.NewInt(0), data: []byte{0x01}}
	q, err := svc.buildGas(context.Background(), f, in, domain.TxRequest{})
	if err != nil {
		t.Fatalf("buildGas: %v", err)
	}
	if q.GasLimit != 60000 { // 50000 × 1.2
		t.Errorf("gas limit = %d, want 60000 (×1.2)", q.GasLimit)
	}
}

func TestBuildGas_MaxFeeFormula(t *testing.T) {
	f := fake.New()
	f.EstimateGasFn = func(ctx context.Context, msg ethereum.CallMsg) (uint64, error) { return 21000, nil }
	fakeFees(f, 0, 2_000_000_000, 30_000_000_000) // tip 2gwei, base 30gwei
	svc := openWithProvider(t, &stubProvider{cc: f})

	in := &Intent{network: "mainnet", to: someAddr(1), value: big.NewInt(0)}
	q, err := svc.buildGas(context.Background(), f, in, domain.TxRequest{})
	if err != nil {
		t.Fatalf("buildGas: %v", err)
	}
	// maxFee = 2.0 × 30gwei + 2gwei = 62gwei.
	if q.MaxFeePerGas.String() != "62000000000" {
		t.Errorf("maxFee = %s, want 62000000000 (2×base + tip)", q.MaxFeePerGas)
	}
	// worst-case = limit × maxFee.
	want := new(big.Int).Mul(big.NewInt(21000), big.NewInt(62_000_000_000))
	if q.WorstCaseGasWei.Cmp(want) != 0 {
		t.Errorf("worst-case gas = %s, want %s", q.WorstCaseGasWei, want)
	}
}

func TestBuildGas_PartialOverride_PriorityAlone(t *testing.T) {
	f := fake.New()
	f.EstimateGasFn = func(ctx context.Context, msg ethereum.CallMsg) (uint64, error) { return 21000, nil }
	fakeFees(f, 0, 1_000_000_000, 30_000_000_000)
	svc := openWithProvider(t, &stubProvider{cc: f})

	in := &Intent{network: "mainnet", to: someAddr(1), value: big.NewInt(0)}
	q, err := svc.buildGas(context.Background(), f, in, domain.TxRequest{PriorityFee: "3gwei"})
	if err != nil {
		t.Fatalf("buildGas: %v", err)
	}
	if q.PriorityFee.String() != "3000000000" {
		t.Errorf("tip = %s, want 3000000000 (explicit)", q.PriorityFee)
	}
	// maxFee recomputed from the formula with the explicit tip: 2×30 + 3 = 63gwei.
	if q.MaxFeePerGas.String() != "63000000000" {
		t.Errorf("maxFee = %s, want 63000000000 (formula with explicit tip)", q.MaxFeePerGas)
	}
}

func TestBuildGas_PartialOverride_MaxFeeAlone(t *testing.T) {
	f := fake.New()
	f.EstimateGasFn = func(ctx context.Context, msg ethereum.CallMsg) (uint64, error) { return 21000, nil }
	// estimate tip 50gwei so min(tip, maxFee) clamps to the maxFee.
	fakeFees(f, 0, 50_000_000_000, 30_000_000_000)
	svc := openWithProvider(t, &stubProvider{cc: f})

	in := &Intent{network: "mainnet", to: someAddr(1), value: big.NewInt(0)}
	q, err := svc.buildGas(context.Background(), f, in, domain.TxRequest{MaxFee: "10gwei"})
	if err != nil {
		t.Fatalf("buildGas: %v", err)
	}
	// tip = min(50gwei, 10gwei) = 10gwei.
	if q.PriorityFee.String() != "10000000000" {
		t.Errorf("tip = %s, want 10000000000 (clamped to maxFee)", q.PriorityFee)
	}
	if q.MaxFeePerGas.String() != "10000000000" {
		t.Errorf("maxFee = %s, want 10000000000", q.MaxFeePerGas)
	}
}

func TestBuildGas_TipExceedsMaxFee_Exit2(t *testing.T) {
	f := fake.New()
	f.EstimateGasFn = func(ctx context.Context, msg ethereum.CallMsg) (uint64, error) { return 21000, nil }
	fakeFees(f, 0, 1, 100)
	svc := openWithProvider(t, &stubProvider{cc: f})

	in := &Intent{network: "mainnet", to: someAddr(1), value: big.NewInt(0)}
	_, err := svc.buildGas(context.Background(), f, in, domain.TxRequest{MaxFee: "1gwei", PriorityFee: "2gwei"})
	if err == nil {
		t.Fatal("expected a usage error when tip > maxFee")
	}
	if de := domain.AsError(err); de.Exit != domain.ExitUsage {
		t.Errorf("exit = %d, want 2 (usage)", de.Exit)
	}
}

func TestBuildGas_LegacyMode(t *testing.T) {
	f := fake.New()
	f.EstimateGasFn = func(ctx context.Context, msg ethereum.CallMsg) (uint64, error) { return 21000, nil }
	f.SuggestGasPriceFn = func(ctx context.Context) (*big.Int, error) { return big.NewInt(20_000_000_000), nil }
	svc := openWithProvider(t, &stubProvider{cc: f})

	in := &Intent{network: "mainnet", to: someAddr(1), value: big.NewInt(0)}
	q, err := svc.buildGas(context.Background(), f, in, domain.TxRequest{Legacy: true})
	if err != nil {
		t.Fatalf("buildGas legacy: %v", err)
	}
	if !q.Legacy {
		t.Error("expected a legacy quote")
	}
	// normal speed ×1.2: 20gwei × 1.2 = 24gwei.
	if q.GasPrice.String() != "24000000000" {
		t.Errorf("gas price = %s, want 24000000000 (20gwei × 1.2)", q.GasPrice)
	}
}

func TestBuildGas_GasPriceOnNon1559_Exit2(t *testing.T) {
	f := fake.New()
	f.EstimateGasFn = func(ctx context.Context, msg ethereum.CallMsg) (uint64, error) { return 21000, nil }
	fakeFees(f, 0, 1, 100)
	svc := openWithProvider(t, &stubProvider{cc: f})
	in := &Intent{network: "mainnet", to: someAddr(1), value: big.NewInt(0)}
	_, err := svc.buildGas(context.Background(), f, in, domain.TxRequest{GasPrice: "20gwei"})
	if err == nil || domain.AsError(err).Exit != domain.ExitUsage {
		t.Fatalf("expected usage exit 2 for --gas-price on a 1559 network, got %v", err)
	}
}

func TestBuildGas_EstimateRevert_Exit7(t *testing.T) {
	f := fake.New()
	f.EstimateGasFn = func(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
		return 0, errString("execution reverted: bad")
	}
	fakeFees(f, 0, 1, 100)
	svc := openWithProvider(t, &stubProvider{cc: f})
	in := &Intent{network: "mainnet", to: someAddr(1), value: big.NewInt(0)}
	_, err := svc.buildGas(context.Background(), f, in, domain.TxRequest{})
	if err == nil || domain.AsError(err).Exit != domain.ExitReverted {
		t.Fatalf("expected reverted exit 7, got %v", err)
	}
}
