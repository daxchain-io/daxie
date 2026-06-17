//go:build integration

// sign_integration_test.go drives the M9 sign/verify surface END-TO-END through the
// real cli funnel against a local anvil with a freshly-deployed EIP-2612 permit
// token. The load-bearing scenario is the REAL permit roundtrip: `daxie sign typed`
// produces a signature over an EIP-2612 Permit, the harness submits it to the token's
// on-chain permit() (via testchain.SubmitPermit, independent of Daxie), and asserts
// allowance(owner,spender) == value — the executable proof that a Daxie-signed permit
// is a valid, fund-moving authorization, which is WHY it is policy-checked at
// signature time like an on-chain approval. The companion scenarios assert the
// permit-safety gates: a non-allowlisted spender is DENIED (exit 3, nothing signed);
// an unknown typed message is DENIED (typed_data.unknown) until `policy typed allow`
// opens it; a wrong-chainId permit is DENIED (chain_mismatch). Plus the EIP-191
// sign+verify roundtrip and the mismatch case.
//
// Compiled only under `go test -tags integration`. anvil must be on PATH.
package cli

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/testchain"
	"github.com/ethereum/go-ethereum/common"
)

// setupSignCLI spawns anvil, isolates state, writes a localanvil config, wires the
// keystore + ADMIN passphrases non-interactively, imports the funded dev key as the
// signer "owner", and deploys the EIP-2612 permit token. It returns the anvil handle
// + the token contract address. The owner holds the full supply (the constructor
// minted to the deployer == anvil dev account 0 == the imported key), so a permit
// from owner is a real, fund-backed authorization.
func setupSignCLI(t *testing.T) (*testchain.Anvil, common.Address) {
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

	if _, stderr, code := execCLI(t, "account", "import", "owner", "--key-file", keyFile, "--yes"); code != 0 {
		t.Fatalf("account import owner: exit %d, stderr=%s", code, stderr)
	}

	token := testchain.DeployERC2612(t, anvil) // deployer = owner holds the supply
	return anvil, token
}

// sigFromHex splits a 0x 65-byte signature into (v, r, s) for an on-chain permit()
// submission. Daxie emits V in {27,28}; the on-chain ecrecover wants exactly that, so
// no normalization here.
func sigFromHex(t *testing.T, sigHex string) (uint8, [32]byte, [32]byte) {
	t.Helper()
	b := common.FromHex(sigHex)
	if len(b) != 65 {
		t.Fatalf("signature is %d bytes, want 65 (%q)", len(b), sigHex)
	}
	var r, s [32]byte
	copy(r[:], b[0:32])
	copy(s[:], b[32:64])
	return b[64], r, s
}

// signTypedDoc writes the typed-data document to a temp file and runs
// `daxie sign typed --data <file> --account owner --json`, returning the parsed
// SigResult (and the raw exit code/stderr for the deny cases). A temp file (rather
// than --data-stdin) keeps the test on the existing execCLI funnel, which does not
// wire stdin — the --data path is the equivalent surface (cli-spec offers both).
func signTypedDoc(t *testing.T, doc []byte, args ...string) (domain.SigResult, string, int) {
	t.Helper()
	docFile := filepath.Join(t.TempDir(), "typed.json")
	if err := os.WriteFile(docFile, doc, 0o600); err != nil {
		t.Fatalf("write typed doc: %v", err)
	}
	full := append([]string{"sign", "typed", "--data", docFile, "--account", "owner", "--json"}, args...)
	stdout, stderr, code := execCLI(t, full...)
	var res domain.SigResult
	if code == 0 {
		if err := json.Unmarshal([]byte(stdout), &res); err != nil {
			t.Fatalf("sign typed --json invalid: %v (%q)", err, stdout)
		}
	}
	return res, stderr, code
}

// ── Scenario 1: the REAL EIP-2612 permit roundtrip (the load-bearing one) ──────

func TestSignCLI_PermitRoundtrip(t *testing.T) {
	anvil, token := setupSignCLI(t)
	owner := anvil.FundedAddress()
	spender := common.HexToAddress("0x00000000000000000000000000000000000005A1")

	// Seal a policy that ALLOWLISTS the spender so the permit (a spend-equivalent) is
	// permitted at signature time exactly like an on-chain approval.
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}
	if _, stderr, code := execCLI(t, "policy", "allow", spender.Hex()); code != 0 {
		t.Fatalf("policy allow spender: exit %d, stderr=%s", code, stderr)
	}

	value := new(big.Int).Mul(big.NewInt(7), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)) // 7 PTST
	deadline := big.NewInt(9_999_999_999)
	nonce := anvil.PermitNonce(t, token, owner)

	doc := testchain.Permit712(testchain.AnvilChainID, token, owner, spender, value, nonce, deadline)
	res, stderr, code := signTypedDoc(t, doc)
	if code != 0 {
		t.Fatalf("sign typed (allowlisted permit) exit %d, stderr=%s", code, stderr)
	}
	if len(common.FromHex(res.Signature)) != 65 {
		t.Fatalf("signature is not 65 bytes: %q", res.Signature)
	}
	if res.Scheme != "eip712" {
		t.Errorf("scheme = %q, want eip712", res.Scheme)
	}

	// Submit the permit on-chain and assert the allowance is set to value — the proof
	// the Daxie signature is a valid, fund-moving authorization.
	v, r, s := sigFromHex(t, res.Signature)
	testchain.SubmitPermit(t, anvil, token, owner, spender, value, deadline, v, r, s)
	if got := anvil.ERC2612Allowance(t, token, owner, spender); got.Cmp(value) != 0 {
		t.Fatalf("on-chain allowance after permit = %s, want %s", got, value)
	}
}

// ── Scenario 2: sign message + verify round-trip ──────────────────────────────

func TestSignCLI_MessageVerifyRoundtrip(t *testing.T) {
	anvil, _ := setupSignCLI(t)
	owner := anvil.FundedAddress()

	// sign message → capture the signature.
	out, stderr, code := execCLI(t, "sign", "message", "hello daxie", "--account", "owner", "--json")
	if code != 0 {
		t.Fatalf("sign message: exit %d, stderr=%s", code, stderr)
	}
	var sig domain.SigResult
	if err := json.Unmarshal([]byte(out), &sig); err != nil {
		t.Fatalf("sign message --json invalid: %v (%q)", err, out)
	}
	if sig.Scheme != "eip191" {
		t.Errorf("scheme = %q, want eip191", sig.Scheme)
	}

	// verify against the correct signer ⇒ valid (exit 0).
	vout, vstderr, vcode := execCLI(t, "verify", "--message", "hello daxie",
		"--signature", sig.Signature, "--address", owner.Hex(), "--json")
	if vcode != 0 {
		t.Fatalf("verify (correct signer): exit %d, stderr=%s", vcode, vstderr)
	}
	var vr domain.VerifyResult
	if err := json.Unmarshal([]byte(vout), &vr); err != nil {
		t.Fatalf("verify --json invalid: %v (%q)", err, vout)
	}
	if !vr.Valid {
		t.Errorf("verify against the real signer reports invalid: %+v", vr)
	}
	if !strings.EqualFold(vr.Recovered, owner.Hex()) {
		t.Errorf("recovered = %s, want %s", vr.Recovered, owner.Hex())
	}

	// verify against a DIFFERENT address ⇒ mismatch (exit 2, valid:false), and the
	// recovered address is surfaced.
	other := common.HexToAddress("0x000000000000000000000000000000000000bEEF")
	mout, _, mcode := execCLI(t, "verify", "--message", "hello daxie",
		"--signature", sig.Signature, "--address", other.Hex(), "--json")
	if mcode != int(domain.ExitUsage) {
		t.Fatalf("verify (wrong signer) exit %d, want %d (USAGE/mismatch)", mcode, domain.ExitUsage)
	}
	var mr domain.VerifyResult
	if err := json.Unmarshal([]byte(mout), &mr); err != nil {
		t.Fatalf("verify mismatch still emits a result object; got %q (%v)", mout, err)
	}
	if mr.Valid {
		t.Error("verify against a wrong address reports valid:true")
	}
	if !strings.EqualFold(mr.Recovered, owner.Hex()) {
		t.Errorf("mismatch recovered = %s, want the real signer %s", mr.Recovered, owner.Hex())
	}

	// --no-hash over a 32-byte 0x digest still signs (the EIP-191 prefix wraps the
	// 32 bytes) and verifies against the same digest input.
	digest := "0x" + strings.Repeat("ab", 32)
	dout, dstderr, dcode := execCLI(t, "sign", "message", digest, "--no-hash", "--account", "owner", "--json")
	if dcode != 0 {
		t.Fatalf("sign message --no-hash: exit %d, stderr=%s", dcode, dstderr)
	}
	var dsig domain.SigResult
	if err := json.Unmarshal([]byte(dout), &dsig); err != nil {
		t.Fatalf("sign --no-hash --json invalid: %v (%q)", err, dout)
	}
	if _, _, vc := execCLI(t, "verify", "--message", digest, "--no-hash",
		"--signature", dsig.Signature, "--address", owner.Hex(), "--json"); vc != 0 {
		t.Fatalf("verify --no-hash roundtrip exit %d, want 0", vc)
	}
}

// ── Scenario 3: permit to a NON-allowlisted spender DENIED at signature time ────

func TestSignCLI_PermitNonAllowlistedDeniedExit3(t *testing.T) {
	anvil, token := setupSignCLI(t)
	owner := anvil.FundedAddress()
	allowed := common.HexToAddress("0x00000000000000000000000000000000000005B2")
	rogue := common.HexToAddress("0x00000000000000000000000000000000000005B3")

	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}
	if _, stderr, code := execCLI(t, "policy", "allow", allowed.Hex()); code != 0 {
		t.Fatalf("policy allow: exit %d, stderr=%s", code, stderr)
	}

	value := new(big.Int).Mul(big.NewInt(3), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	deadline := big.NewInt(9_999_999_999)
	nonce := anvil.PermitNonce(t, token, owner)
	doc := testchain.Permit712(testchain.AnvilChainID, token, owner, rogue, value, nonce, deadline)

	_, stderr, code := signTypedDoc(t, doc)
	if code != int(domain.ExitPolicyDenied) {
		t.Fatalf("permit to non-allowlisted spender exit %d, want %d (POLICY_DENIED); stderr=%s", code, domain.ExitPolicyDenied, stderr)
	}
	if !strings.Contains(stderr, "policy.denied") {
		t.Errorf("deny envelope should carry policy.denied.*:\n%s", stderr)
	}
	// The key was NEVER touched — the on-chain allowance is unchanged (no permit was
	// even produced to submit).
	if got := anvil.ERC2612Allowance(t, token, owner, rogue); got.Sign() != 0 {
		t.Errorf("a denied permit set an allowance: %s, want 0", got)
	}
}

// ── Scenario 4: unknown typed message DENIED, then allowed via policy typed allow ─

func TestSignCLI_UnknownTypedDenyThenAllow(t *testing.T) {
	anvil, _ := setupSignCLI(t)
	verifying := common.HexToAddress("0x00000000000000000000000000000000005EA907")
	offerer := anvil.FundedAddress()

	// A policy must be ACTIVE for the deny-by-default gate to engage.
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}

	doc := testchain.UnknownTyped712(testchain.AnvilChainID, verifying, offerer)

	// Unknown typed ⇒ deny-by-default (exit 3, typed_data.unknown).
	_, stderr, code := signTypedDoc(t, doc)
	if code != int(domain.ExitPolicyDenied) {
		t.Fatalf("unknown typed exit %d, want %d (POLICY_DENIED); stderr=%s", code, domain.ExitPolicyDenied, stderr)
	}
	if !strings.Contains(stderr, "typed_data") {
		t.Errorf("deny envelope should mention typed_data:\n%s", stderr)
	}

	// Open the specific (chain-id, contract, primary-type) triple via the M9 admin
	// surface, then the SAME document signs (exit 0).
	if _, astderr, acode := execCLI(t, "policy", "typed", "allow",
		"--chain-id", "31337", "--contract", verifying.Hex(), "--primary-type", "OrderComponents"); acode != 0 {
		t.Fatalf("policy typed allow: exit %d, stderr=%s", acode, astderr)
	}
	res, stderr2, code2 := signTypedDoc(t, doc)
	if code2 != 0 {
		t.Fatalf("sign typed after allow exit %d, want 0; stderr=%s", code2, stderr2)
	}
	if len(common.FromHex(res.Signature)) != 65 {
		t.Fatalf("post-allow signature is not 65 bytes: %q", res.Signature)
	}

	// Remove it again ⇒ denied once more (round-trips the admin surface end-to-end).
	if _, rstderr, rcode := execCLI(t, "policy", "typed", "remove",
		"--chain-id", "31337", "--contract", verifying.Hex(), "--primary-type", "OrderComponents"); rcode != 0 {
		t.Fatalf("policy typed remove: exit %d, stderr=%s", rcode, rstderr)
	}
	if _, _, code3 := signTypedDoc(t, doc); code3 != int(domain.ExitPolicyDenied) {
		t.Fatalf("unknown typed after remove exit %d, want %d (POLICY_DENIED)", code3, domain.ExitPolicyDenied)
	}
}

// ── Scenario 5: wrong-chainId permit DENIED (chain_mismatch) ───────────────────

func TestSignCLI_WrongChainIdPermitDeniedExit3(t *testing.T) {
	anvil, token := setupSignCLI(t)
	owner := anvil.FundedAddress()
	spender := common.HexToAddress("0x00000000000000000000000000000000000005C4")

	// Allowlist the spender so the ONLY gate that can bite is the chain mismatch.
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}
	if _, stderr, code := execCLI(t, "policy", "allow", spender.Hex()); code != 0 {
		t.Fatalf("policy allow: exit %d, stderr=%s", code, stderr)
	}

	value := new(big.Int).Mul(big.NewInt(2), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	deadline := big.NewInt(9_999_999_999)
	nonce := anvil.PermitNonce(t, token, owner)
	// domain.chainId = 1 (mainnet) while signing on anvil (31337) — the classic
	// exfiltration trick.
	doc := testchain.Permit712(1, token, owner, spender, value, nonce, deadline)

	_, stderr, code := signTypedDoc(t, doc)
	if code != int(domain.ExitPolicyDenied) {
		t.Fatalf("wrong-chainId permit exit %d, want %d (POLICY_DENIED); stderr=%s", code, domain.ExitPolicyDenied, stderr)
	}
	if !strings.Contains(stderr, "chain_mismatch") && !strings.Contains(stderr, "typed_data") {
		t.Errorf("deny envelope should signal a chain mismatch:\n%s", stderr)
	}
	if got := anvil.ERC2612Allowance(t, token, owner, spender); got.Sign() != 0 {
		t.Errorf("a chain-mismatch permit set an allowance: %s, want 0", got)
	}
}
