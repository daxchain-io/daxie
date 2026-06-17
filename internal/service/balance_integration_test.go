//go:build integration

// balance_integration_test.go drives the M2 read paths end-to-end through the REAL
// ChainProvider against a local anvil: `daxie balance` of a funded dev account
// returns the expected nonzero wei, and `rpc test` verifies the chain-id (and
// refuses a deliberate mismatch). It is gated by //go:build integration so it
// compiles only under `go test -tags integration`.
package service

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/testchain"
)

// openAtAnvil writes a config fixture with a `localanvil` network (chain-id 31337)
// and a `localanvil-rpc` endpoint pointing at the given URL, isolates every state
// class to temp dirs, and Opens the service against it. mismatchID, when nonzero,
// declares a WRONG chain-id so the dial guard can be exercised.
func openAtAnvil(t *testing.T, url string, declaredChainID uint64) *Service {
	t.Helper()
	dir := t.TempDir()
	cfg := "schema = 1\n\n" +
		"[networks.localanvil]\n" +
		"chain-id = " + itoaU(declaredChainID) + "\n" +
		"confirmations = 1\n" +
		"default-rpc = \"localanvil-rpc\"\n\n" +
		"[rpc.localanvil-rpc]\n" +
		"network = \"localanvil\"\n" +
		"url = \"" + url + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("seed config.toml: %v", err)
	}
	t.Setenv("DAXIE_CONFIG", dir)
	t.Setenv("DAXIE_KEYSTORE", t.TempDir())
	t.Setenv("DAXIE_STATE_DIR", t.TempDir())
	t.Setenv("DAXIE_CACHE_DIR", t.TempDir())

	svc, err := Open(context.Background(), Options{
		Network: "localanvil",
		Clock:   time.Now,
	})
	if err != nil {
		t.Fatalf("Open at anvil: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// TestBalance_FundedAnvil reads the funded dev account's ETH balance through the
// real ChainProvider and asserts it is the nonzero amount anvil funds (10000 ETH).
func TestBalance_FundedAnvil(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc := openAtAnvil(t, anvil.URL(), testchain.AnvilChainID)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, err := svc.Balance(ctx, domain.LocalCLI(), domain.BalanceRequest{
		Account: anvil.FundedAddress().Hex(),
		Network: "localanvil",
	}, nil)
	if err != nil {
		t.Fatalf("Balance(funded): %v", err)
	}
	wei, ok := new(big.Int).SetString(res.Wei, 10)
	if !ok {
		t.Fatalf("Balance wei %q is not a decimal string", res.Wei)
	}
	// Assert the EXACT amount anvil funds (10000 ETH = 1e22 wei), not merely >0: a
	// wrong-but-positive number or a wei/eth mis-scaling in the read path must fail.
	if wei.Cmp(testchain.FundedWei) != 0 {
		t.Fatalf("Balance(funded) = %s wei, want exactly %s (10000 ETH)", res.Wei, testchain.FundedWei)
	}
	if res.Eth != "10000" {
		t.Errorf("Eth = %q, want 10000 (the human-scaled funded amount)", res.Eth)
	}
	if res.Symbol != "ETH" {
		t.Errorf("Symbol = %q, want ETH", res.Symbol)
	}
	if res.Address != anvil.FundedAddress().Hex() {
		t.Errorf("Address = %q, want %q", res.Address, anvil.FundedAddress().Hex())
	}
}

// TestBalance_EmptyAnvil reads an unfunded address: a zero balance, no error.
func TestBalance_EmptyAnvil(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc := openAtAnvil(t, anvil.URL(), testchain.AnvilChainID)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, err := svc.Balance(ctx, domain.LocalCLI(), domain.BalanceRequest{
		Account: anvil.EmptyAddress().Hex(),
		Network: "localanvil",
	}, nil)
	if err != nil {
		t.Fatalf("Balance(empty): %v", err)
	}
	if res.Wei != "0" {
		t.Errorf("Balance(empty) = %q wei, want 0", res.Wei)
	}
}

// TestRPCTest_ChainIDMatch verifies `rpc test` against a correctly-declared
// endpoint reports OK + the verified chain-id.
func TestRPCTest_ChainIDMatch(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc := openAtAnvil(t, anvil.URL(), testchain.AnvilChainID)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, err := svc.RPCTest(ctx, domain.LocalCLI(), domain.RPCTestRequest{Name: "localanvil-rpc"})
	if err != nil {
		t.Fatalf("RPCTest(match): %v", err)
	}
	if !res.OK {
		t.Error("RPCTest OK = false, want true")
	}
	if res.ChainID != testchain.AnvilChainID {
		t.Errorf("RPCTest ChainID = %d, want %d", res.ChainID, testchain.AnvilChainID)
	}
}

// TestRPCTest_Mismatch_Refuses is the end-to-end malicious-endpoint guard: a
// fixture endpoint whose network DECLARES the wrong chain-id (mainnet's 1) while
// the endpoint actually reaches anvil (31337) MUST refuse with
// rpc.chain_id_mismatch (exit 12).
func TestRPCTest_Mismatch_Refuses(t *testing.T) {
	anvil := testchain.Spawn(t)
	// Declare chain-id 1 (wrong) for the localanvil network; the endpoint still
	// points at anvil, which reports 31337.
	svc := openAtAnvil(t, anvil.URL(), 1)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := svc.RPCTest(ctx, domain.LocalCLI(), domain.RPCTestRequest{Name: "localanvil-rpc"})
	if err == nil {
		t.Fatal("RPCTest(mismatch): expected refusal, got nil error")
	}
	de := domain.AsError(err)
	if de.Code != domain.CodeRPCChainIDMismatch {
		t.Fatalf("error code = %q, want %q", de.Code, domain.CodeRPCChainIDMismatch)
	}
	if de.Exit != domain.ExitIntegrity {
		t.Fatalf("exit = %d, want %d (INTEGRITY)", de.Exit, domain.ExitIntegrity)
	}
}

// TestRPCAdd_VerifiesAtAnvil proves add-time chain-ID verification against a REAL
// node: adding an endpoint whose declared network matches anvil's chain-id
// succeeds (the guard ran and passed), with no add-time warning.
func TestRPCAdd_VerifiesAtAnvil(t *testing.T) {
	anvil := testchain.Spawn(t)
	// Declare the CORRECT chain-id (31337) so the add-time guard passes.
	svc := openAtAnvil(t, anvil.URL(), testchain.AnvilChainID)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, err := svc.RPCAdd(ctx, domain.LocalCLI(), domain.RPCAddRequest{
		Name:    "anvil-extra",
		Network: "localanvil",
		URL:     anvil.URL(),
	})
	if err != nil {
		t.Fatalf("RPCAdd(correct chain): %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("RPCAdd(correct, reachable) emitted warnings, want none: %v", res.Warnings)
	}
}

// TestRPCAdd_WrongChain_RefusedAtAnvil is the add-time malicious-endpoint guard:
// declaring the WRONG chain-id (mainnet's 1) for an endpoint that actually reaches
// anvil (31337) MUST refuse at add time with rpc.chain_id_mismatch (exit 12).
func TestRPCAdd_WrongChain_RefusedAtAnvil(t *testing.T) {
	anvil := testchain.Spawn(t)
	// Declare chain-id 1 (WRONG) for localanvil; the endpoint reaches anvil (31337).
	svc := openAtAnvil(t, anvil.URL(), 1)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := svc.RPCAdd(ctx, domain.LocalCLI(), domain.RPCAddRequest{
		Name:    "anvil-wrong",
		Network: "localanvil",
		URL:     anvil.URL(),
	})
	if err == nil {
		t.Fatal("RPCAdd(wrong chain): expected refusal, got nil error")
	}
	de := domain.AsError(err)
	if de.Code != domain.CodeRPCChainIDMismatch {
		t.Fatalf("error code = %q, want %q", de.Code, domain.CodeRPCChainIDMismatch)
	}
	if de.Exit != domain.ExitIntegrity {
		t.Fatalf("exit = %d, want %d (INTEGRITY)", de.Exit, domain.ExitIntegrity)
	}
}

// itoaU formats a uint64 for the TOML fixture without importing strconv at the top
// (keeps the test's import set tight; the value is small).
func itoaU(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
