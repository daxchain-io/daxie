//go:build integration

// token_integration_test.go drives the M5 token surface END-TO-END through the real
// cli funnel against a local anvil with a freshly-deployed test ERC-20: token add →
// balance --token → tx send --token → token approve → token allowance → token revoke,
// asserting BOTH the on-chain effect (via the testchain raw-RPC readers, independent
// of Daxie's erc package) AND the §5.7 exit codes the command surface returns,
// including the #19 broadcasting outcomes and the fail-closed deny (exit 3).
//
// Compiled only under `go test -tags integration`. anvil must be on PATH.
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

// setupTokenCLI spawns anvil, isolates state, writes a localanvil config, wires the
// keystore + ADMIN passphrases non-interactively, imports the funded dev key, and
// deploys + registers the test ERC-20 (alias "tst"). It returns the anvil handle +
// the token contract address. The admin passphrase is wired so the fail-closed test
// can seal a policy through the same cli.
func setupTokenCLI(t *testing.T) (*testchain.Anvil, common.Address) {
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
	adminFile := filepath.Join(t.TempDir(), "admin")
	if err := os.WriteFile(adminFile, []byte("integration admin\n"), 0o600); err != nil {
		t.Fatalf("seed admin pass: %v", err)
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
	t.Setenv("DAXIE_ADMIN_PASSPHRASE_FILE", adminFile)
	t.Setenv("DAXIE_KDF_LIGHT", "1")

	if _, stderr, code := execCLI(t, "account", "import", "funded", "--key-file", keyFile, "--yes"); code != 0 {
		t.Fatalf("account import funded: exit %d, stderr=%s", code, stderr)
	}

	token := testchain.DeployERC20(t, anvil) // deployer = funded acct 0 holds the supply
	if _, stderr, code := execCLI(t, "token", "add", token.Hex(), "--name", "tst"); code != 0 {
		t.Fatalf("token add: exit %d, stderr=%s", code, stderr)
	}
	return anvil, token
}

func TestTokenCLI_AddBalanceTransfer(t *testing.T) {
	anvil, token := setupTokenCLI(t)
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000A1")

	// balance --token tst --json equals the on-chain balanceOf.
	out, stderr, code := execCLI(t, "balance", anvil.FundedAddress().Hex(), "--token", "tst", "--json")
	if code != 0 {
		t.Fatalf("balance --token: exit %d, stderr=%s", code, stderr)
	}
	var br domain.BalanceResult
	if err := json.Unmarshal([]byte(out), &br); err != nil {
		t.Fatalf("balance --token --json invalid: %v (%q)", err, out)
	}
	if br.Token == nil {
		t.Fatal("balance --token result has no Token block")
	}
	onChain := anvil.ERC20BalanceOf(t, token, anvil.FundedAddress())
	if br.Token.Base != onChain.String() {
		t.Errorf("balance --token base = %s, want on-chain %s", br.Token.Base, onChain)
	}

	// tx send --token tst → recipient receives it.
	if _, stderr, code := execCLI(t, "tx", "send", "--from", "funded", "--to", recipient.Hex(),
		"--amount", "42", "--token", "tst", "--wait", "--yes", "--json"); code != 0 {
		t.Fatalf("tx send --token: exit %d, stderr=%s", code, stderr)
	}
	want := new(big.Int).Mul(big.NewInt(42), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	if got := anvil.ERC20BalanceOf(t, token, recipient); got.Cmp(want) != 0 {
		t.Errorf("recipient on-chain balance = %s, want %s", got, want)
	}
}

func TestTokenCLI_ApproveAllowanceRevoke(t *testing.T) {
	anvil, token := setupTokenCLI(t)
	spender := common.HexToAddress("0x00000000000000000000000000000000000000B2")

	// approve --wait → exit 0; on-chain allowance == approved.
	if _, stderr, code := execCLI(t, "token", "approve", "tst", "--from", "funded", "--spender", spender.Hex(),
		"--amount", "175", "--wait", "--yes", "--json"); code != 0 {
		t.Fatalf("token approve: exit %d, stderr=%s", code, stderr)
	}
	want := new(big.Int).Mul(big.NewInt(175), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	if got := anvil.ERC20Allowance(t, token, anvil.FundedAddress(), spender); got.Cmp(want) != 0 {
		t.Errorf("on-chain allowance = %s, want %s", got, want)
	}

	// token allowance --json agrees.
	out, stderr, code := execCLI(t, "token", "allowance", "tst",
		"--owner", anvil.FundedAddress().Hex(), "--spender", spender.Hex(), "--json")
	if code != 0 {
		t.Fatalf("token allowance: exit %d, stderr=%s", code, stderr)
	}
	var al domain.AllowanceResult
	if err := json.Unmarshal([]byte(out), &al); err != nil {
		t.Fatalf("token allowance --json invalid: %v (%q)", err, out)
	}
	if al.Allowance != want.String() {
		t.Errorf("token allowance = %s, want %s", al.Allowance, want)
	}

	// revoke --wait → allowance 0.
	if _, stderr, code := execCLI(t, "token", "revoke", "tst", "--from", "funded", "--spender", spender.Hex(),
		"--wait", "--yes", "--json"); code != 0 {
		t.Fatalf("token revoke: exit %d, stderr=%s", code, stderr)
	}
	if got := anvil.ERC20Allowance(t, token, anvil.FundedAddress(), spender); got.Sign() != 0 {
		t.Errorf("on-chain allowance after revoke = %s, want 0", got)
	}
}

// An --unlimited approve WITHOUT --yes is refused at the cli (exit 2), and the
// on-chain allowance is unchanged (nothing signed).
func TestTokenCLI_UnlimitedWithoutYesDenied(t *testing.T) {
	anvil, token := setupTokenCLI(t)
	spender := common.HexToAddress("0x00000000000000000000000000000000000000C3")

	_, _, code := execCLI(t, "token", "approve", "tst", "--spender", spender.Hex(), "--unlimited")
	if code != int(domain.ExitUsage) {
		t.Fatalf("--unlimited without --yes: exit %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if got := anvil.ERC20Allowance(t, token, anvil.FundedAddress(), spender); got.Sign() != 0 {
		t.Errorf("an unacked --unlimited must not change the allowance, got %s", got)
	}
}

// A sentinel --amount (the exact 2^256-1 base-unit value, expressed as the human
// decimal for the token's 18 decimals) WITHOUT --yes must be refused as an unlimited
// approval (exit 3, policy.denied.unlimited_unacked) — NOT silently signed as a
// "bounded" approve. This is the §4.2 bypass the adversarial review found: the
// infinite-allowance sentinel arriving via --amount instead of the --unlimited flag.
// The spender is on the allowlist so the only gate that can bite is the unlimited
// ceremony, and the on-chain allowance stays 0 (nothing was signed).
func TestTokenCLI_SentinelAmountUnlimitedDeniedExit3(t *testing.T) {
	anvil, token := setupTokenCLI(t)
	spender := common.HexToAddress("0x00000000000000000000000000000000000000E5")

	// Seal a policy with an allowlist that includes the spender, so the fail-closed
	// no-allowlist rule does NOT fire and the unlimited gate is the operative one.
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}
	if _, stderr, code := execCLI(t, "policy", "allow", spender.Hex()); code != 0 {
		t.Fatalf("policy allow spender: exit %d, stderr=%s", code, stderr)
	}

	// 2^256-1 as the human decimal for an 18-decimal token (parses to the exact
	// infinite-allowance base-unit word). Note: NO --unlimited flag, NO --yes.
	max256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	s := max256.String()
	sentinelHuman := s[:len(s)-18] + "." + s[len(s)-18:]

	_, _, code := execCLI(t, "token", "approve", "tst", "--from", "funded",
		"--spender", spender.Hex(), "--amount", sentinelHuman, "--json")
	if code != int(domain.ExitPolicyDenied) {
		t.Fatalf("sentinel --amount without --yes: exit %d, want %d (POLICY_DENIED)", code, domain.ExitPolicyDenied)
	}
	if got := anvil.ERC20Allowance(t, token, anvil.FundedAddress(), spender); got.Sign() != 0 {
		t.Errorf("a denied unlimited-via-amount approval set an allowance: %s, want 0", got)
	}

	// And with --yes the SAME sentinel --amount IS allowed (the ceremony is
	// satisfiable, not over-blocking): the on-chain allowance becomes 2^256-1.
	if _, stderr, code := execCLI(t, "token", "approve", "tst", "--from", "funded",
		"--spender", spender.Hex(), "--amount", sentinelHuman, "--wait", "--yes", "--json"); code != 0 {
		t.Fatalf("acked sentinel --amount approve: exit %d, stderr=%s", code, stderr)
	}
	if got := anvil.ERC20Allowance(t, token, anvil.FundedAddress(), spender); got.Cmp(max256) != 0 {
		t.Errorf("acked sentinel approve allowance = %s, want 2^256-1", got)
	}
}

// A token transfer with limits set + no allowlist is refused fail-closed (exit 3),
// and the recipient never receives the token.
func TestTokenCLI_FailClosedDeniedExit3(t *testing.T) {
	anvil, token := setupTokenCLI(t)
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000D4")

	// Seal a policy (admin pass wired): limits set, allowlist OFF.
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "off"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}

	_, _, code := execCLI(t, "tx", "send", "--from", "funded", "--to", recipient.Hex(),
		"--amount", "1", "--token", "tst", "--yes", "--json")
	if code != int(domain.ExitPolicyDenied) {
		t.Fatalf("fail-closed token transfer: exit %d, want %d (POLICY_DENIED)", code, domain.ExitPolicyDenied)
	}
	if got := anvil.ERC20BalanceOf(t, token, recipient); got.Sign() != 0 {
		t.Errorf("a denied transfer moved tokens: recipient balance %s, want 0", got)
	}
}
