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
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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
		// The ADMIN passphrase (M4) is a DISTINCT secret from the keystore passphrase
		// (§3.7) — distinct env name, distinct value — so the M4 policy tests can set a
		// sealed policy through the same service without the keystore secret deriving
		// the seal key.
		"DAXIE_ADMIN_PASSPHRASE": "anvil-admin-pass",
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

// ── M4 policy enforcement (anvil end-to-end) ─────────────────────────────────
//
// These drive a REAL sealed policy (set under the admin passphrase via the same
// service) and assert the §4.9 denial codes on real sends: over the per-tx limit
// (nothing signed), an allowlisted dest (mines), a non-allowlisted dest, and the
// gas-cap refusal. They are the M4 keystone's end-to-end proof.

const itAdminEnv = "anvil-admin-pass" // matches DAXIE_ADMIN_PASSPHRASE in openSendAnvil

// strPtrIT is a *string helper for the policy set request.
func strPtrIT(s string) *string { return &s }

// setPolicyIT bootstraps/updates the sealed policy under the admin passphrase
// (acquired from DAXIE_ADMIN_PASSPHRASE, wired in openSendAnvil). The same engine
// instance updates its in-memory anchor, so subsequent sends through svc are gated.
func setPolicyIT(t *testing.T, svc *Service, req PolicySetRequest) {
	t.Helper()
	if _, err := svc.PolicySet(context.Background(), domain.LocalCLI(), req, AdminInput{}); err != nil {
		t.Fatalf("PolicySet: %v", err)
	}
}

// allowIT pins an allowlist address under the admin passphrase.
func allowIT(t *testing.T, svc *Service, addr common.Address) {
	t.Helper()
	if _, err := svc.PolicyAllow(context.Background(), domain.LocalCLI(),
		PolicyAllowRequest{Source: "address", Address: addr.Hex()}, AdminInput{}); err != nil {
		t.Fatalf("PolicyAllow: %v", err)
	}
}

// wantDenied asserts err is a *domain.Error carrying the expected policy.denied.*
// code at exit 3.
func wantDenied(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a policy denial %q, got nil", code)
	}
	de := domain.AsError(err)
	if de.Code != code {
		t.Fatalf("denial code = %q, want %q (msg %q)", de.Code, code, de.Msg)
	}
	if de.Exit != domain.ExitPolicyDenied {
		t.Errorf("denial exit = %d, want 3 (POLICY_DENIED)", de.Exit)
	}
}

// TestIntegration_PolicyTxLimitDenied: a send over max_tx is denied tx_limit and
// NOTHING is signed/journaled (Reserve denied before sign).
func TestIntegration_PolicyTxLimitDenied(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())
	to := common.HexToAddress("0x00000000000000000000000000000000000000d1")

	// max_tx 0.1 ETH, allowlist OFF (so the ETH limit is what bites, not the gate).
	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:     strPtrIT("0.1eth"),
		Allowlist: strPtrIT("off"),
	})

	_, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: to.Hex(), Amount: "1", Yes: true}, nil)
	wantDenied(t, err, "policy.denied.tx_limit")

	// Nothing was journaled as broadcast/confirmed (the spend was refused before sign).
	recs, lerr := svc.journal.List(context.Background(), 31337, from)
	if lerr != nil {
		t.Fatalf("journal List: %v", lerr)
	}
	for _, r := range recs {
		if r.Status == journal.StatusBroadcast || r.Status == journal.StatusConfirmed {
			t.Fatalf("a denied send left a %s journal record — nothing should have been signed", r.Status)
		}
	}
}

// TestIntegration_PolicyAllowlist: within limits, an allowlisted dest mines (exit 0,
// exact balance); a NON-allowlisted dest is denied allowlist.
func TestIntegration_PolicyAllowlist(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, _ := openSendAnvil(t, anvil.URL())
	allowed := common.HexToAddress("0x00000000000000000000000000000000000000d2")
	denied := common.HexToAddress("0x00000000000000000000000000000000000000d3")

	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:       strPtrIT("1eth"),
		MaxDay:      strPtrIT("10eth"),
		Allowlist:   strPtrIT("on"),
		IncludeSelf: strPtrIT("on"),
	})
	allowIT(t, svc, allowed)

	// Allowlisted dest, within limits ⇒ confirmed, exact 0.5 ETH.
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: allowed.Hex(), Amount: "0.5", Yes: true,
			Wait: domain.WaitOpts{Enabled: true}}, nil)
	if err != nil {
		t.Fatalf("allowlisted send: %v", err)
	}
	if res.Status != domain.TxStatusConfirmed {
		t.Fatalf("allowlisted send status = %q, want confirmed", res.Status)
	}
	cc, _ := svc.chains.ClientFor(context.Background(), ChainRequest{Network: "localanvil"})
	defer cc.Close()
	bal, _ := cc.Balance(context.Background(), allowed, nil)
	if bal.Cmp(big.NewInt(500_000_000_000_000_000)) != 0 {
		t.Errorf("allowlisted recipient balance = %s, want 5e17", bal)
	}

	// Non-allowlisted dest ⇒ denied allowlist.
	_, derr := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: denied.Hex(), Amount: "0.01", Yes: true}, nil)
	wantDenied(t, derr, "policy.denied.allowlist")
}

// TestIntegration_PolicyGasCap: a max_gas_price below the chain base fee refuses the
// send with gas_cap, and the payload carries current_base_fee.
func TestIntegration_PolicyGasCap(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, _ := openSendAnvil(t, anvil.URL())
	to := common.HexToAddress("0x00000000000000000000000000000000000000d4")

	// Allowlist off; an absurdly low gas cap (1 wei) is below any real base fee.
	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:       strPtrIT("1eth"),
		MaxGasPrice: strPtrIT("1wei"),
		Allowlist:   strPtrIT("off"),
	})

	_, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: to.Hex(), Amount: "0.01", Yes: true}, nil)
	wantDenied(t, err, "policy.denied.gas_cap")
	de := domain.AsError(err)
	if de.Data == nil || de.Data["current_base_fee"] == nil {
		t.Errorf("gas_cap denial payload missing current_base_fee: %+v", de.Data)
	}
	if !de.Retryable {
		t.Errorf("gas_cap denial should be retryable (the fee market moves)")
	}
}

// TestIntegration_PolicyVerifyRoundTrip: after a `set`, the seal verifies (exit 0);
// tamper the policy.json on disk and Verify fails closed (exit 8) — passphrase-free.
func TestIntegration_PolicyVerifyRoundTrip(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, _ := openSendAnvil(t, anvil.URL())

	setPolicyIT(t, svc, PolicySetRequest{MaxTx: strPtrIT("1eth"), Allowlist: strPtrIT("on")})

	if _, err := svc.PolicyVerify(context.Background(), domain.LocalCLI()); err != nil {
		t.Fatalf("verify after set: %v (want exit 0)", err)
	}

	// Tamper the sealed policy.json (flip a byte in the body) ⇒ verify fails closed.
	pf := filepath.Join(svc.paths.State, "policy.json")
	b, rerr := os.ReadFile(pf)
	if rerr != nil {
		t.Fatalf("read policy.json: %v", rerr)
	}
	b[len(b)/2] ^= 0x40
	if werr := os.WriteFile(pf, b, 0o600); werr != nil {
		t.Fatalf("write tampered policy.json: %v", werr)
	}
	if _, err := svc.PolicyVerify(context.Background(), domain.LocalCLI()); err == nil {
		t.Fatal("verify of a tampered policy returned nil, want exit 8 (seal_violation)")
	} else if de := domain.AsError(err); de.Exit != domain.ExitTimeoutPending {
		t.Errorf("tampered verify exit = %d, want 8 (seal_violation)", de.Exit)
	}
}

// counterEntryIT is the minimal on-disk counter shape the RBF test inspects.
type counterEntryIT struct {
	AccountNonce *uint64 `json:"account_nonce"`
	Candidates   []struct {
		ValueWei string `json:"value_wei"`
		State    string `json:"state"`
	} `json:"candidates"`
}
type counterFileIT struct {
	Entries []counterEntryIT `json:"entries"`
}

// TestIntegration_RBFSupersedesWindow proves the §4.4/§5.5 RBF supersession on a
// REAL sealed policy + real send pipeline: a speedup folds a candidate into the
// EXISTING (network,from,account_nonce) counter entry (max-across-candidates), it
// does NOT create a second entry, and a speedup of a tx that consumed most of the
// daily budget is NOT falsely denied day_limit (value is not re-counted). This is
// the end-to-end regression for the dropped Check.AccountNonce.
func TestIntegration_RBFSupersedesWindow(t *testing.T) {
	anvil := testchain.SpawnManualMining(t)
	svc, from := openSendAnvil(t, anvil.URL())
	to := common.HexToAddress("0x00000000000000000000000000000000000000e7")

	// A TIGHT daily budget: max_day 1.2 ETH. A 1 ETH send consumes most of it; the
	// pre-fix gate would re-count the original 1 ETH on speedup and deny day_limit.
	// Allowlist off so the ETH limits govern directly.
	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:     strPtrIT("2eth"),
		MaxDay:    strPtrIT("1.2eth"),
		Allowlist: strPtrIT("off"),
	})

	// Low-fee 1 ETH send: stays pending in the mempool (no auto-mining).
	r, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: to.Hex(), Amount: "1", MaxFee: "2gwei", PriorityFee: "1gwei", Yes: true}, nil)
	if err != nil {
		t.Fatalf("low-fee 1 ETH send: %v", err)
	}

	// Speed it up. The replacement re-counts ONLY the positive gas delta (value not
	// re-counted), so it must NOT be denied day_limit even though the original
	// already consumed ~1 ETH of the 1.2 ETH budget.
	sres, serr := svc.Speedup(context.Background(), domain.LocalCLI(),
		domain.SpeedupRequest{Hash: r.Hash}, nil)
	if serr != nil {
		t.Fatalf("speedup of a near-budget tx must not be denied (value is not re-counted); got %v", serr)
	}
	if sres.Nonce != r.Nonce {
		t.Errorf("speedup nonce = %d, want %d (same nonce pinned)", sres.Nonce, r.Nonce)
	}

	// Inspect the on-disk counter: exactly ONE entry for the pinned nonce, with TWO
	// candidates (the original + the RBF candidate folded in) — NOT two entries.
	cf := filepath.Join(svc.paths.State, "spend", "localanvil", strings.ToLower(from.Hex())+".json")
	b, rerr := os.ReadFile(cf)
	if rerr != nil {
		t.Fatalf("read counter file %s: %v", cf, rerr)
	}
	var doc counterFileIT
	if jerr := json.Unmarshal(b, &doc); jerr != nil {
		t.Fatalf("counter file is not valid JSON: %v", jerr)
	}
	matching := 0
	for _, e := range doc.Entries {
		if e.AccountNonce != nil && *e.AccountNonce == r.Nonce {
			matching++
			if len(e.Candidates) < 2 {
				t.Errorf("RBF entry has %d candidate(s), want ≥2 (the speedup must fold into the entry, not create a new one)", len(e.Candidates))
			}
		}
	}
	if matching != 1 {
		t.Fatalf("counter has %d entries for nonce %d, want exactly 1 (RBF supersedes, not adds)", matching, r.Nonce)
	}
}
