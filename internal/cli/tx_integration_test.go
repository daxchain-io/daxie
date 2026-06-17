//go:build integration

// tx_integration_test.go drives the M3 tx pipeline END-TO-END through the real
// cli funnel against a local anvil: it builds the cobra tree, signs with a key
// imported into a real keystore, broadcasts via the real ChainProvider, and
// asserts BOTH the on-chain effect (recipient balance, receipt status, nonce
// sequencing) AND the §5.7 exit code the command surface returns. It is the
// frontend-level complement to internal/service/tx_integration_test.go (the
// service-level scenarios): this one proves the WHOLE `daxie tx …` command works,
// flags → request → kernel → chain → render → exit code.
//
// Compiled only under `go test -tags integration`. anvil must be on PATH (CI's
// foundry-toolchain provides it; DAXIE_IT_REQUIRE_ANVIL=1 turns a missing anvil
// into a hard failure rather than a silent skip).
package cli

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/testchain"
	"github.com/ethereum/go-ethereum/common"
)

// anvilAcct0Key is the well-known anvil/hardhat dev account 0 private key (hex, no
// 0x prefix needed by the import path — we write it with 0x). It derives the
// funded address testchain.FundedAddress (0xf39F…2266, 10000 ETH). Test-only
// constant; it controls only the throwaway local anvil dev chain.
const anvilAcct0Key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

// freshRecipient is a deterministic address anvil does NOT fund, used as a send
// target so its post-send balance is exactly the sent amount.
var freshRecipient = common.HexToAddress("0x000000000000000000000000000000000000C0DE")

// setupAnvilCLI spawns anvil, isolates every state class to temp dirs, writes a
// config with a `localanvil` network (chain-id 31337, confirmations 1) pointing at
// anvil, wires the non-interactive keystore passphrase + light KDF, imports the
// funded dev key as the `funded` standalone account, and returns the anvil handle.
// Every subsequent execCLI call signs from `funded` against `localanvil`.
func setupAnvilCLI(t *testing.T) *testchain.Anvil {
	t.Helper()
	anvil := testchain.Spawn(t)

	cfgDir := t.TempDir()
	cfg := "schema = 1\n\n" +
		"[defaults]\n" +
		"network = \"localanvil\"\n\n" +
		"[networks.localanvil]\n" +
		"chain-id = 31337\n" +
		"confirmations = 1\n" +
		"default-rpc = \"localanvil-rpc\"\n\n" +
		"[rpc.localanvil-rpc]\n" +
		"network = \"localanvil\"\n" +
		"url = \"" + anvil.URL() + "\"\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	passFile := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(passFile, []byte("integration passphrase\n"), 0o600); err != nil {
		t.Fatalf("seed pass: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(anvilAcct0Key+"\n"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	t.Setenv("DAXIE_CONFIG", cfgDir)
	t.Setenv("DAXIE_KEYSTORE", t.TempDir())
	t.Setenv("DAXIE_STATE_DIR", t.TempDir())
	t.Setenv("DAXIE_CACHE_DIR", t.TempDir())
	t.Setenv("DAXIE_PASSPHRASE_FILE", passFile)
	t.Setenv("DAXIE_PASSPHRASE_CONFIRM_FILE", passFile)
	t.Setenv("DAXIE_KDF_LIGHT", "1")

	// Import the funded dev key as a standalone account named "funded". --yes
	// covers the first-init keystore-confirm on a fresh keystore (the confirm
	// env channel is also wired above, belt-and-suspenders).
	if _, stderr, code := execCLI(t, "account", "import", "funded", "--key-file", keyFile, "--yes"); code != 0 {
		t.Fatalf("account import funded: exit %d, stderr=%s", code, stderr)
	}
	return anvil
}

// balanceWei reads an address's balance through the cli (`balance <addr> --json`)
// and returns it as a big.Int.
func balanceWei(t *testing.T, addr common.Address) *big.Int {
	t.Helper()
	out, stderr, code := execCLI(t, "balance", addr.Hex(), "--json")
	if code != 0 {
		t.Fatalf("balance %s: exit %d, stderr=%s", addr.Hex(), code, stderr)
	}
	var br domain.BalanceResult
	if err := json.Unmarshal([]byte(out), &br); err != nil {
		t.Fatalf("balance --json invalid: %v (%q)", err, out)
	}
	wei, ok := new(big.Int).SetString(br.Wei, 10)
	if !ok {
		t.Fatalf("balance wei %q not decimal", br.Wei)
	}
	return wei
}

// sendOK runs `tx send` with --json --yes --wait from `funded` and returns the
// parsed TxResult, failing on a nonzero exit.
func sendOK(t *testing.T, to common.Address, amount string, extra ...string) domain.TxResult {
	t.Helper()
	args := append([]string{"tx", "send", "--from", "funded", "--to", to.Hex(),
		"--amount", amount, "--wait", "--yes", "--json"}, extra...)
	out, stderr, code := execCLI(t, args...)
	if code != 0 {
		t.Fatalf("tx send: exit %d, stderr=%s", code, stderr)
	}
	var res domain.TxResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("tx send --json invalid: %v (%q)", err, out)
	}
	return res
}

// NOTE on the revert scenario (§7 item 2, exit 7): a deliberate on-chain revert
// requires SENDING ETH to a contract whose fallback reverts, which in turn needs a
// DEPLOYED reverting contract. M3's `tx send` is ETH-only (no --data / no deploy
// path until M10 `contract`), so a reverting target cannot be created through the
// cli command surface alone. The revert→exit-7 assertion therefore lives in the
// SERVICE-level integration test (internal/service/tx_integration_test.go), which
// deploys the revert fixture via the chain client directly (plan §7). These
// cli-level tests cover the full ETH-only command surface end to end.

// Scenario 1: tx send → confirmed (exact). Send 1 ETH to a fresh address with
// --wait; assert the recipient balance is EXACTLY 1e18 wei, the result is
// confirmed, exit 0, and stderr (progress) carried no stdout leak under --json.
func TestTxSend_ConfirmedExact(t *testing.T) {
	anvil := setupAnvilCLI(t)
	_ = anvil

	before := balanceWei(t, freshRecipient)
	res := sendOK(t, freshRecipient, "1eth")

	if res.Status != domain.TxStatusConfirmed {
		t.Fatalf("status = %q, want confirmed", res.Status)
	}
	if res.Hash == "" {
		t.Fatal("confirmed send has no hash")
	}
	after := balanceWei(t, freshRecipient)
	delta := new(big.Int).Sub(after, before)
	oneEth, _ := new(big.Int).SetString("1000000000000000000", 10)
	if delta.Cmp(oneEth) != 0 {
		t.Fatalf("recipient delta = %s wei, want exactly 1e18", delta)
	}
}

// tx send --dry-run builds + estimates + previews but signs/broadcasts nothing:
// the result is marked DryRun and the recipient balance is unchanged.
func TestTxSend_DryRunNoBroadcast(t *testing.T) {
	setupAnvilCLI(t)

	before := balanceWei(t, freshRecipient)
	out, stderr, code := execCLI(t, "tx", "send", "--from", "funded",
		"--to", freshRecipient.Hex(), "--amount", "1eth", "--dry-run", "--yes", "--json")
	if code != 0 {
		t.Fatalf("dry-run send: exit %d, stderr=%s", code, stderr)
	}
	var res domain.TxResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("dry-run --json invalid: %v (%q)", err, out)
	}
	if !res.DryRun {
		t.Errorf("dry-run result not marked DryRun: %+v", res)
	}
	after := balanceWei(t, freshRecipient)
	if before.Cmp(after) != 0 {
		t.Errorf("dry-run moved funds: before=%s after=%s", before, after)
	}
}

// Scenario 3: nonce sequencing across two back-to-back sends. The first without
// --wait (returns the hash immediately), the second with --wait. Assert the two
// nonces are N and N+1 (never double-allocated) and both confirm.
func TestTxSend_NonceSequencing(t *testing.T) {
	setupAnvilCLI(t)

	// First send (no --wait): returns the hash + the allocated nonce.
	out, stderr, code := execCLI(t, "tx", "send", "--from", "funded",
		"--to", freshRecipient.Hex(), "--amount", "0.1eth", "--yes", "--json")
	if code != 0 {
		t.Fatalf("first send: exit %d, stderr=%s", code, stderr)
	}
	var first domain.TxResult
	if err := json.Unmarshal([]byte(out), &first); err != nil {
		t.Fatalf("first send --json invalid: %v (%q)", err, out)
	}

	// Second send (with --wait): its nonce must be exactly first.Nonce+1.
	second := sendOK(t, freshRecipient, "0.1eth")
	if second.Nonce != first.Nonce+1 {
		t.Fatalf("second nonce = %d, want %d (= first %d + 1) — nonce double-allocated or gapped",
			second.Nonce, first.Nonce+1, first.Nonce)
	}

	// The first should now also be confirmed; tx status folds it.
	st, stderr2, code := execCLI(t, "tx", "status", first.Hash, "--json")
	if code != 0 {
		t.Fatalf("tx status: exit %d, stderr=%s", code, stderr2)
	}
	var fs domain.TxResult
	if err := json.Unmarshal([]byte(st), &fs); err != nil {
		t.Fatalf("tx status --json invalid: %v (%q)", err, st)
	}
	if fs.Status != domain.TxStatusConfirmed {
		t.Fatalf("first tx status = %q, want confirmed", fs.Status)
	}
}

// tx list folds the journal and shows the sends just made (newest-first).
func TestTxList_AfterSends(t *testing.T) {
	setupAnvilCLI(t)
	_ = sendOK(t, freshRecipient, "0.2eth")

	out, stderr, code := execCLI(t, "tx", "list", "--account", "funded", "--json")
	if code != 0 {
		t.Fatalf("tx list: exit %d, stderr=%s", code, stderr)
	}
	var lr domain.TxListResult
	if err := json.Unmarshal([]byte(out), &lr); err != nil {
		t.Fatalf("tx list --json invalid: %v (%q)", err, out)
	}
	if len(lr.Txs) == 0 {
		t.Fatal("tx list returned no rows after a send")
	}
	if lr.Txs[0].Status != "confirmed" {
		t.Errorf("newest tx status = %q, want confirmed", lr.Txs[0].Status)
	}
}

// gas returns a live three-speed quote with a base fee against anvil.
func TestGas_LiveQuote(t *testing.T) {
	setupAnvilCLI(t)
	out, stderr, code := execCLI(t, "gas", "--json")
	if code != 0 {
		t.Fatalf("gas: exit %d, stderr=%s", code, stderr)
	}
	var gr domain.GasQuotesResult
	if err := json.Unmarshal([]byte(out), &gr); err != nil {
		t.Fatalf("gas --json invalid: %v (%q)", err, out)
	}
	// Each speed quote must carry a non-empty 1559 max-fee (anvil is post-1559).
	for name, q := range map[string]domain.GasResult{"slow": gr.Slow, "normal": gr.Normal, "fast": gr.Fast} {
		if q.MaxFeePerGas == "" {
			t.Errorf("%s quote has no max-fee-per-gas", name)
		}
	}
}

// Scenario 4 + 5 (speedup + cancel) need a tx that stays pending in the mempool.
// anvil mines instantly by default, so a tx confirms before a replacement can
// race it. We drive the speedup/cancel SURFACE here (exit + cross-link wiring)
// against an instant-mine chain by sending with --no-wait, then asserting the
// commands return a sane §5.7 code: on an already-mined hash that is exit 9
// (tx.already_mined). The real mempool-race replacement is exercised in the
// service-level integration test with anvil --no-mining.
func TestTxSpeedup_AlreadyMined(t *testing.T) {
	setupAnvilCLI(t)
	res := sendOK(t, freshRecipient, "0.05eth") // confirmed (instant mine)

	// speedup on a hash that already has a receipt → tx.already_mined (exit 9).
	_, _, code := execCLI(t, "tx", "speedup", res.Hash, "--yes")
	if code != int(domain.ExitTxConflict) {
		t.Fatalf("speedup of a mined tx: exit %d, want %d (tx.already_mined)", code, domain.ExitTxConflict)
	}
}

// A foreign / unknown hash to speedup is ref.not_found (exit 10) — the journal has
// no Daxie-originated record for it.
func TestTxSpeedup_UnknownHash(t *testing.T) {
	setupAnvilCLI(t)
	bogus := common.HexToHash("0xdeadbeef").Hex()
	_, _, code := execCLI(t, "tx", "speedup", bogus, "--yes")
	if code != int(domain.ExitNotFound) {
		t.Fatalf("speedup of an unknown hash: exit %d, want %d (ref.not_found)", code, domain.ExitNotFound)
	}
}

// A bounded --wait that the deadline hits is timeout (exit 8), NOT a failure — it
// is resumable. We provoke it by waiting on a never-broadcast (fabricated) hash
// with a tiny timeout; the wait state machine returns timeout, not an error code.
func TestTxWait_TimeoutResumable(t *testing.T) {
	setupAnvilCLI(t)
	// A syntactically valid but unknown hash: wait polls and times out.
	unknown := common.HexToHash("0xabc123").Hex()
	_, _, code := execCLI(t, "tx", "wait", unknown, "--timeout", "2s")
	// timeout (8) for a pending/unknown hash that never resolves; a known-not-ours
	// hash with no journal record may instead be ref.not_found (10). Either is a
	// non-failure §5.7 code — assert it is one of the two and never a generic 1.
	if code != int(domain.ExitTimeoutPending) && code != int(domain.ExitNotFound) {
		t.Fatalf("wait on an unknown hash: exit %d, want %d (timeout) or %d (not_found)",
			code, domain.ExitTimeoutPending, domain.ExitNotFound)
	}
}
