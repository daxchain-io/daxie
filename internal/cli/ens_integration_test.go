//go:build integration

// ens_integration_test.go is the FRONTEND-PARITY complement to the service-level
// ENS integration suite (§2.9): it drives the whole `daxie ens …` + `daxie tx send
// --to name.eth` command surface through the real cobra funnel against a local anvil
// with a DEPLOYED mock ENS, asserting flags → request → kernel → chain → render →
// exit code. Compiled only under `go test -tags integration`.
package cli

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ens"
	"github.com/daxchain-io/daxie/internal/testchain"
	"github.com/ethereum/go-ethereum/common"
)

// setupENSCLI spawns anvil, sets up the cli env (via setupAnvilCLI), deploys the mock
// ENS, and installs it as the chain-31337 registry via the integration-only
// ens.SetTestRegistry hook (process-wide, so every subsequent execCLI sees it). It
// returns the anvil handle + the deployed registry address.
func setupENSCLI(t *testing.T) (*testchain.Anvil, common.Address) {
	t.Helper()
	anvil := setupAnvilCLI(t)
	reg := testchain.DeployENS(t, anvil)
	ens.SetTestRegistry(big.NewInt(testchain.AnvilChainID), reg)
	t.Cleanup(func() { ens.SetTestRegistry(big.NewInt(testchain.AnvilChainID), common.Address{}) })
	return anvil, reg
}

// TestCLI_ENSResolve: `daxie ens resolve daxchain.eth --json` returns the registered
// address (exit 0).
func TestCLI_ENSResolve(t *testing.T) {
	anvil, reg := setupENSCLI(t)
	addrA := common.HexToAddress("0x00000000000000000000000000000000000000f1")
	anvil.ENSSetAddr(t, reg, ens.Namehash("daxchain.eth"), addrA)

	out, stderr, code := execCLI(t, "ens", "resolve", "daxchain.eth", "--json")
	if code != 0 {
		t.Fatalf("ens resolve: exit %d, stderr=%s", code, stderr)
	}
	var rr domain.EnsResolveResult
	if err := json.Unmarshal([]byte(out), &rr); err != nil {
		t.Fatalf("ens resolve --json invalid: %v (%q)", err, out)
	}
	if !strings.EqualFold(rr.Address, addrA.Hex()) {
		t.Fatalf("ens resolve address = %s, want %s", rr.Address, addrA.Hex())
	}
}

// TestCLI_ENSUnresolvedExit10: an unregistered name resolves to nothing → exit 10
// (ref.not_found), never an all-zero address echoed as success.
func TestCLI_ENSUnresolvedExit10(t *testing.T) {
	setupENSCLI(t)
	_, _, code := execCLI(t, "ens", "resolve", "nope.eth", "--json")
	if code != int(domain.ExitNotFound) {
		t.Fatalf("ens resolve <unregistered> exit = %d, want 10 (ref.not_found)", code)
	}
}

// TestCLI_TxSendToENS: `daxie tx send --to name.eth` resolves + sends; the transfer
// lands at the resolved address (the resolved address is echoed in the --json
// result's To block before signing).
func TestCLI_TxSendToENS(t *testing.T) {
	anvil, reg := setupENSCLI(t)
	addrA := common.HexToAddress("0x00000000000000000000000000000000000000f2")
	anvil.ENSSetAddr(t, reg, ens.Namehash("payee.eth"), addrA)

	before := balanceWei(t, addrA)
	out, stderr, code := execCLI(t, "tx", "send", "--from", "funded", "--to", "payee.eth",
		"--amount", "1eth", "--wait", "--yes", "--json")
	if code != 0 {
		t.Fatalf("tx send --to payee.eth: exit %d, stderr=%s", code, stderr)
	}
	var res domain.TxResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("tx send --json invalid: %v (%q)", err, out)
	}
	if res.To.Address != addrA || res.To.ENSName != "payee.eth" {
		t.Fatalf("echoed dest = %+v, want addr=%s ens=payee.eth", res.To, addrA.Hex())
	}
	after := balanceWei(t, addrA)
	delta := new(big.Int).Sub(after, before)
	oneEth, _ := new(big.Int).SetString("1000000000000000000", 10)
	if delta.Cmp(oneEth) != 0 {
		t.Fatalf("resolved recipient delta = %s wei, want exactly 1e18", delta)
	}
}
