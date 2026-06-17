//go:build integration

// tx_integration_test.go drives the full §5.1 send pipeline end-to-end through the
// REAL ChainProvider + the REAL keystore signer + the REAL journal/policy against a
// local anvil: send→wait→confirmed (exact balances), a deliberate revert (exit 7),
// nonce sequencing across two sends (never double-allocated), and RBF speedup/cancel
// on a pending tx. Gated by //go:build integration so it compiles only under
// `go test -tags integration` with anvil on PATH.
package service

import (
	"bytes"
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/testchain"
	"github.com/ethereum/go-ethereum/common"
)

// anvilAcct0Key is anvil/hardhat dev account 0's well-known private key (the
// funded 10000-ETH account, m/44'/60'/0'/0/0 of the test mnemonic). Importing it
// lets the REAL keystore signer sign from the funded address.
const anvilAcct0Key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

// openSendAnvil opens a service against anvil with a keystore holding the funded
// account (imported as a standalone account named "funded"), a real clock, and the
// passphrase wired non-interactively. It returns the service + the funded address.
func openSendAnvil(t *testing.T, url string) (*Service, common.Address) {
	t.Helper()
	dir := t.TempDir()
	cfg := "schema = 1\n\n" +
		"[networks.localanvil]\n" +
		"chain-id = 31337\n" +
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
	t.Setenv("DAXIE_KDF_LIGHT", "1")

	env := map[string]string{
		"DAXIE_PASSPHRASE":         "anvil-pass",
		"DAXIE_PASSPHRASE_CONFIRM": "anvil-pass",
		"DAXIE_KDF_LIGHT":          "1",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	svc, err := Open(context.Background(), Options{
		Network: "localanvil",
		Clock:   time.Now,
		Sleep:   func(ctx context.Context, d time.Duration) error { time.Sleep(d); return nil },
		Secret: SecretIO{
			Stdin:     bytes.NewReader([]byte(anvilAcct0Key + "\n")),
			LookupEnv: lookup,
			IsTTY:     func() bool { return false },
		},
	})
	if err != nil {
		t.Fatalf("Open at anvil: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })

	// Import the funded key as a standalone account (key on stdin, passphrase env).
	res, err := svc.AccountImport(context.Background(), domain.LocalCLI(),
		domain.AccountImportRequest{Name: "funded"},
		AccountImportInput{KeyStdin: true}, nil)
	if err != nil {
		t.Fatalf("AccountImport funded key: %v", err)
	}
	return svc, common.HexToAddress(res.Address)
}

func TestIntegration_SendConfirmedExact(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())
	if from != anvil.FundedAddress() {
		t.Fatalf("imported address %s != anvil funded %s", from.Hex(), anvil.FundedAddress().Hex())
	}
	to := common.HexToAddress("0x00000000000000000000000000000000000000a1")

	req := domain.TxRequest{
		From: "funded", To: to.Hex(), Amount: "1",
		Yes:  true,
		Wait: domain.WaitOpts{Enabled: true},
	}
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), req, nil)
	if err != nil {
		t.Fatalf("SendTx --wait: %v", err)
	}
	if res.Status != domain.TxStatusConfirmed {
		t.Fatalf("status = %q, want confirmed", res.Status)
	}

	// The recipient holds EXACTLY 1 ETH.
	cc, err := svc.chains.ClientFor(context.Background(), ChainRequest{Network: "localanvil"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()
	bal, err := cc.Balance(context.Background(), to, nil)
	if err != nil {
		t.Fatalf("balance: %v", err)
	}
	if bal.Cmp(big.NewInt(1_000_000_000_000_000_000)) != 0 {
		t.Errorf("recipient balance = %s wei, want exactly 1e18", bal)
	}

	// The journal folds to confirmed with a status-1 receipt.
	rec, jerr := svc.journal.ByHash(context.Background(), 31337, common.HexToHash(res.Hash))
	if jerr != nil {
		t.Fatalf("journal ByHash: %v", jerr)
	}
	if rec.Status != journal.StatusConfirmed {
		t.Errorf("journal status = %q, want confirmed", rec.Status)
	}
	if rec.Receipt == nil || rec.Receipt.Status != 1 {
		t.Errorf("journal receipt = %+v, want status 1", rec.Receipt)
	}
}

func TestIntegration_NonceSequencing(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, _ := openSendAnvil(t, anvil.URL())
	to := common.HexToAddress("0x00000000000000000000000000000000000000b2")

	r1, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: to.Hex(), Amount: "1", Yes: true}, nil)
	if err != nil {
		t.Fatalf("send 1: %v", err)
	}
	r2, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: to.Hex(), Amount: "1", Yes: true}, nil)
	if err != nil {
		t.Fatalf("send 2: %v", err)
	}
	if r1.Nonce != 0 || r2.Nonce != 1 {
		t.Fatalf("nonces = %d, %d, want 0, 1 (never double-allocated)", r1.Nonce, r2.Nonce)
	}
}

// TestIntegration_RevertExit7 sends ETH to a contract whose bytecode always
// reverts. With an explicit --gas-limit the send bypasses eth_estimateGas (which
// would itself revert), so the tx is REALLY broadcast, mined under manual control,
// and produces a status-0 receipt on-chain. `tx wait` must then map the reverted
// receipt to exit 7 and fold the journal to reverted.
func TestIntegration_RevertExit7(t *testing.T) {
	anvil := testchain.SpawnManualMining(t)
	svc, _ := openSendAnvil(t, anvil.URL())

	// Plant always-reverting bytecode at the recipient.
	target := anvil.SetRevertContract(t, common.HexToAddress("0x000000000000000000000000000000000000dead"))

	// Send with an explicit gas limit so estimateGas (which reverts) is skipped and
	// the tx actually reaches the mempool. No --wait: anvil is manual-mining.
	r, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: target.Hex(), Amount: "1", GasLimit: "100000", Yes: true}, nil)
	if err != nil {
		t.Fatalf("send to reverting contract: %v", err)
	}

	// Seal the block: the tx mines with a status-0 (reverted) receipt.
	anvil.Mine(t)

	_, werr := svc.WaitTx(context.Background(), domain.LocalCLI(),
		domain.WaitRequest{Hash: r.Hash}, nil)
	if werr == nil {
		t.Fatal("wait on a reverted tx must error (exit 7)")
	}
	if got := domain.AsError(werr).Exit; got != domain.ExitReverted {
		t.Fatalf("revert exit = %d, want %d (tx.reverted)", got, domain.ExitReverted)
	}

	// The journal must fold to reverted with a status-0 receipt.
	rec, jerr := svc.journal.ByHash(context.Background(), 31337, common.HexToHash(r.Hash))
	if jerr != nil {
		t.Fatalf("journal ByHash: %v", jerr)
	}
	if rec.Status != journal.StatusReverted {
		t.Errorf("journal status = %q, want reverted", rec.Status)
	}
	if rec.Receipt == nil || rec.Receipt.Status != 0 {
		t.Errorf("journal receipt = %+v, want on-chain status 0", rec.Receipt)
	}
}

// TestIntegration_SpeedupReplacesPending exercises a REAL RBF replacement in
// anvil's mempool. With manual mining the original low-fee tx LINGERS pending; the
// speedup broadcasts a higher-fee replacement at the same nonce, then a single
// mined block seals the replacement (the original is evicted). The replacement's
// receipt must mine and the journal must cross-link replaces/replaced_by.
func TestIntegration_SpeedupReplacesPending(t *testing.T) {
	anvil := testchain.SpawnManualMining(t)
	svc, _ := openSendAnvil(t, anvil.URL())
	to := common.HexToAddress("0x00000000000000000000000000000000000000c3")

	// Low-fee send: with --no-mining it stays in the mempool (never auto-mined).
	r, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: to.Hex(), Amount: "1", MaxFee: "2gwei", PriorityFee: "1gwei", Yes: true}, nil)
	if err != nil {
		t.Fatalf("low-fee send: %v", err)
	}

	// Speed it up: a higher-fee replacement at the SAME nonce enters the mempool.
	sres, serr := svc.Speedup(context.Background(), domain.LocalCLI(),
		domain.SpeedupRequest{Hash: r.Hash}, nil)
	if serr != nil {
		t.Fatalf("Speedup against a pending mempool: %v", serr)
	}
	if sres.Replaced != r.Hash {
		t.Errorf("Replaced = %q, want %q", sres.Replaced, r.Hash)
	}
	if sres.Nonce != r.Nonce {
		t.Errorf("speedup nonce = %d, want %d (same nonce pinned)", sres.Nonce, r.Nonce)
	}

	// Seal the block: the higher-fee replacement mines, the original is dropped.
	anvil.Mine(t)

	wres, werr := svc.WaitTx(context.Background(), domain.LocalCLI(),
		domain.WaitRequest{Hash: sres.Hash, Confirmations: u64ptrIT(1)}, nil)
	if werr != nil {
		t.Fatalf("wait on the replacement: %v", werr)
	}
	if wres.Status != domain.TxStatusConfirmed {
		t.Fatalf("replacement status = %q, want confirmed", wres.Status)
	}

	// The journal links the replacement back to the original.
	repRec, jerr := svc.journal.ByHash(context.Background(), 31337, common.HexToHash(sres.Hash))
	if jerr != nil {
		t.Fatalf("journal ByHash replacement: %v", jerr)
	}
	if repRec.Replaces == nil || *repRec.Replaces == "" {
		t.Errorf("replacement record must carry a replaces link")
	}
}

// TestIntegration_CancelReplacesPending cancels a pending tx: a 0-value self-send
// at the same nonce evicts the original from the mempool. After mining, the cancel
// (self-send) confirms and the original never lands.
func TestIntegration_CancelReplacesPending(t *testing.T) {
	anvil := testchain.SpawnManualMining(t)
	svc, from := openSendAnvil(t, anvil.URL())
	to := common.HexToAddress("0x00000000000000000000000000000000000000d4")

	r, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: to.Hex(), Amount: "1", MaxFee: "2gwei", PriorityFee: "1gwei", Yes: true}, nil)
	if err != nil {
		t.Fatalf("low-fee send: %v", err)
	}

	cres, cerr := svc.Cancel(context.Background(), domain.LocalCLI(),
		domain.CancelRequest{Hash: r.Hash}, nil)
	if cerr != nil {
		t.Fatalf("Cancel against a pending mempool: %v", cerr)
	}
	if cres.Nonce != r.Nonce {
		t.Errorf("cancel nonce = %d, want %d (same nonce pinned)", cres.Nonce, r.Nonce)
	}

	anvil.Mine(t)

	wres, werr := svc.WaitTx(context.Background(), domain.LocalCLI(),
		domain.WaitRequest{Hash: cres.Hash, Confirmations: u64ptrIT(1)}, nil)
	if werr != nil {
		t.Fatalf("wait on the cancel: %v", werr)
	}
	if wres.Status != domain.TxStatusConfirmed {
		t.Fatalf("cancel status = %q, want confirmed", wres.Status)
	}

	// The original recipient never received the 1 ETH (cancel is a self-send).
	cc, err := svc.chains.ClientFor(context.Background(), ChainRequest{Network: "localanvil"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()
	bal, err := cc.Balance(context.Background(), to, nil)
	if err != nil {
		t.Fatalf("balance: %v", err)
	}
	if bal.Sign() != 0 {
		t.Errorf("cancelled recipient balance = %s, want 0 (original never landed)", bal)
	}
	_ = from
}

// u64ptrIT is a *uint64 helper local to the integration tests.
func u64ptrIT(n uint64) *uint64 { return &n }
