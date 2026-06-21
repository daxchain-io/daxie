package service

import (
	"context"
	"testing"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/daxchain-io/daxie/internal/domain"
)

// eventABIJSON is a minimal ABI with one event, so contract logs can PackEvent.
const eventABIJSON = `[{"type":"event","name":"Transfer","inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":true},{"name":"value","type":"uint256","indexed":false}]}]`

// TestContractLogs_RejectsTooWideSpan proves a from_block:0..head query past the
// span cap is refused BEFORE any eth_getLogs call — the fan-out DoS is prevented at
// the source, with a usage error.
func TestContractLogs_RejectsTooWideSpan(t *testing.T) {
	from := someAddr(0x01)
	contract := someAddr(0x42)
	svc, f, _ := sendService(t, from)
	f.BlockNum = maxLogSpan + 50 // head well past the cap when from-block is 0
	filtered := false
	f.FilterLogsFn = func(_ context.Context, _ ethereum.FilterQuery) ([]types.Log, error) {
		filtered = true
		return nil, nil
	}
	addContract(t, svc, "tok", contract, eventABIJSON)

	_, err := svc.ContractLogs(context.Background(), domain.LocalCLI(), domain.ContractLogsRequest{
		Contract:  "tok",
		Event:     "Transfer",
		FromBlock: "0",
		Network:   "mainnet",
	})
	if err == nil {
		t.Fatal("a from_block:0..head span past the cap must be rejected")
	}
	if got := domain.AsError(err).Code; got != domain.CodeUsage+".log_range_too_wide" {
		t.Errorf("error code = %q, want usage.log_range_too_wide", got)
	}
	if filtered {
		t.Error("FilterLogs was called despite the span cap — the fan-out was not prevented")
	}
}

// TestContractLogs_WithinSpanScans proves a range within the cap still scans.
func TestContractLogs_WithinSpanScans(t *testing.T) {
	from := someAddr(0x01)
	contract := someAddr(0x42)
	svc, f, _ := sendService(t, from)
	f.BlockNum = 500
	calls := 0
	f.FilterLogsFn = func(_ context.Context, _ ethereum.FilterQuery) ([]types.Log, error) {
		calls++
		return nil, nil
	}
	addContract(t, svc, "tok", contract, eventABIJSON)

	if _, err := svc.ContractLogs(context.Background(), domain.LocalCLI(), domain.ContractLogsRequest{
		Contract:  "tok",
		Event:     "Transfer",
		FromBlock: "0",
		Network:   "mainnet",
	}); err != nil {
		t.Fatalf("ContractLogs within cap: %v", err)
	}
	if calls == 0 {
		t.Error("expected FilterLogs to be called for an in-range query")
	}
}
