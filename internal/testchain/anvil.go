//go:build integration

// Package testchain (integration build) spawns a local anvil devnet for the
// real-EVM contract + balance integration tests (§2.9). It is compiled only
// under `go test -tags integration`.
package testchain

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/ethereum/go-ethereum/common"
)

// AnvilChainID is the chain-id anvil is started with. 31337 is anvil/hardhat's
// conventional local devnet id.
const AnvilChainID = 31337

// testMnemonic is anvil/hardhat's well-known deterministic dev mnemonic. Starting
// anvil with it yields the canonical funded dev accounts below, so the harness can
// hard-code FundedAddress without parsing anvil's stdout.
const testMnemonic = "test test test test test test test test test test test junk"

// fundedAddr0 is account index 0 derived from testMnemonic (m/44'/60'/0'/0/0).
// anvil funds it with 10000 ETH by default. It is the canonical hardhat account 0.
var fundedAddr0 = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")

// FundedWei is anvil's deterministic default balance for each dev account: exactly
// 10000 ETH (1e22 wei). The contract suite + the balance integration test assert
// this EXACT amount (not merely >0) so a wrong-but-positive read or a wei/eth
// mis-scaling in the read path is caught.
var FundedWei, _ = new(big.Int).SetString("10000000000000000000000", 10)

// emptyAddr is an address anvil does NOT fund (not in the dev set), so its balance
// is exactly zero — the EmptyAddress the contract suite checks.
var emptyAddr = common.HexToAddress("0x00000000000000000000000000000000DEADBEEF")

// Anvil is a running local anvil process plus the facts the tests need. It
// implements chaintest.Harness.
type Anvil struct {
	url string
	cmd *exec.Cmd
}

// Spawn starts anvil on a free port with the deterministic dev mnemonic + chain-id
// and waits until it answers eth_chainId, registering a t.Cleanup to kill it. It
// uses anvil's default instant auto-mining (every tx mines immediately). If anvil
// is not on PATH it t.Skip()s — UNLESS DAXIE_IT_REQUIRE_ANVIL=1 (CI sets it), in
// which case a missing anvil is a hard failure (the integration job must actually
// run, not silently skip).
func Spawn(t *testing.T) *Anvil {
	return spawn(t, false)
}

// SpawnManualMining starts anvil with --no-mining, so a submitted tx LINGERS in
// the mempool until Mine() is called. This gives the RBF (speedup/cancel) and the
// revert integration tests a real, controllable mempool: the test sends a tx,
// replaces/cancels it while pending, then mines exactly one block to observe the
// on-chain outcome — never racing anvil's auto-miner.
func SpawnManualMining(t *testing.T) *Anvil {
	return spawn(t, true)
}

// spawn is the shared launcher. noMining selects --no-mining (manual block
// production via Mine) vs the default instant auto-mining.
func spawn(t *testing.T, noMining bool) *Anvil {
	t.Helper()

	anvilBin, err := exec.LookPath("anvil")
	if err != nil {
		if requireAnvil(t) {
			t.Fatalf("anvil not found on PATH but DAXIE_IT_REQUIRE_ANVIL is set: %v", err)
		}
		t.Skip("anvil not found on PATH; skipping integration test (set DAXIE_IT_REQUIRE_ANVIL=1 to require it)")
	}

	port := freePort(t)
	url := "http://127.0.0.1:" + strconv.Itoa(port)

	// --silent keeps anvil's banner off the test log; a fixed mnemonic + chain-id
	// makes the funded accounts deterministic.
	args := []string{
		"--host", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--chain-id", strconv.Itoa(AnvilChainID),
		"--mnemonic", testMnemonic,
		"--silent",
	}
	if noMining {
		// --no-mining: anvil holds submitted txs in the mempool until evm_mine.
		args = append(args, "--no-mining")
	}
	// #nosec G204 -- test-only harness: anvilBin is the `anvil` binary located via
	// exec.LookPath on PATH; all args are constant/test-controlled (no user input).
	cmd := exec.Command(anvilBin, args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting anvil: %v", err)
	}

	a := &Anvil{url: url, cmd: cmd}
	t.Cleanup(a.stop)

	a.waitReady(t)
	return a
}

// Mine produces exactly one block via anvil's evm_mine cheatcode, sealing whatever
// is currently in the mempool. Used by the manual-mining tests to advance the chain
// on demand after a send/replace/cancel.
func (a *Anvil) Mine(t *testing.T) {
	t.Helper()
	a.rpc(t, "evm_mine", []any{})
}

// alwaysRevertCode is minimal EVM bytecode that REVERTs on every call/value
// transfer: PUSH1 0x00, PUSH1 0x00, REVERT. Planting it at an address via
// SetRevertContract makes a plain ETH send to that address revert on-chain — the
// fixture for the deliberate-revert (exit 7) integration test (M3 tx send is
// ETH-only with no deploy path, so the reverting target is planted, not deployed).
const alwaysRevertCode = "0x60006000fd"

// SetRevertContract plants always-reverting bytecode at addr via anvil's
// anvil_setCode cheatcode, so any subsequent ETH send to addr reverts on
// execution. Returns addr for convenience.
func (a *Anvil) SetRevertContract(t *testing.T, addr common.Address) common.Address {
	t.Helper()
	a.rpc(t, "anvil_setCode", []any{addr.Hex(), alwaysRevertCode})
	return addr
}

// rpc posts a single JSON-RPC call to anvil and fails the test on a transport or
// JSON-RPC error. It is a tiny test-only client (the production adapter does not
// expose anvil cheatcodes like evm_mine).
func (a *Anvil) rpc(t *testing.T, method string, params []any) json.RawMessage {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		t.Fatalf("rpc %s marshal: %v", method, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("rpc %s request: %v", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("rpc %s do: %v", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("rpc %s decode: %v", method, err)
	}
	if out.Error != nil {
		t.Fatalf("rpc %s: %s", method, out.Error.Message)
	}
	return out.Result
}

// URL returns the JSON-RPC HTTP endpoint URL.
func (a *Anvil) URL() string { return a.url }

// ── chaintest.Harness ─────────────────────────────────────────────────────────

// ExpectChainID is anvil's configured chain-id (31337).
func (a *Anvil) ExpectChainID() *big.Int { return big.NewInt(AnvilChainID) }

// FundedAddress is anvil dev account 0 (10000 ETH).
func (a *Anvil) FundedAddress() common.Address { return fundedAddr0 }

// ExpectFundedWei is anvil's deterministic default funding: exactly 10000 ETH.
func (a *Anvil) ExpectFundedWei() *big.Int { return new(big.Int).Set(FundedWei) }

// EmptyAddress is an address anvil never funds (zero balance).
func (a *Anvil) EmptyAddress() common.Address { return emptyAddr }

// SupportsSubscribe is false: the harness dials the HTTP endpoint, on which
// Subscribe* must return chain.ErrNotSupported.
func (a *Anvil) SupportsSubscribe() bool { return false }

// ── lifecycle ─────────────────────────────────────────────────────────────────

// waitReady polls eth_chainId until anvil answers (or a deadline). It dials the
// real adapter with the expected chain-id so a healthy start also exercises the
// chain-id guard once.
func (a *Anvil) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		cc, err := chain.Dial(ctx, chain.Options{
			URL:           a.url,
			Network:       "localanvil",
			ExpectChainID: big.NewInt(AnvilChainID),
		})
		cancel()
		if err == nil {
			cc.Close()
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("anvil did not become ready at %s: %v", a.url, lastErr)
}

// stop kills the anvil process (best effort).
func (a *Anvil) stop() {
	if a.cmd != nil && a.cmd.Process != nil {
		_ = a.cmd.Process.Kill()
		_, _ = a.cmd.Process.Wait()
	}
}

// freePort grabs an OS-assigned free TCP port and releases it immediately, so
// anvil can bind it (a tiny race window, acceptable for a local test harness).
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// requireAnvil reports whether DAXIE_IT_REQUIRE_ANVIL is set to a truthy value
// (CI sets it so a missing anvil hard-fails rather than silently skips).
func requireAnvil(t *testing.T) bool {
	t.Helper()
	v, ok := os.LookupEnv("DAXIE_IT_REQUIRE_ANVIL")
	return ok && v != "" && v != "0"
}
