//go:build integration

// contract_integration_test.go drives the M10 `daxie contract` surface END-TO-END
// through the real cli funnel against a local anvil with a freshly-deployed Staking
// fixture + ERC-20. The LOAD-BEARING scenarios are the calldata-bypass security crux
// (the whole point of M10):
//
//   - a `contract send` to the ERC-20 carrying approve(attacker, 2^256-1) is CLASSIFIED
//     KindApprove (NOT an opaque call): with a NON-allowlisted spender it is denied
//     allowlist (exit 3, asserted on error.data.address = the DECODED attacker, never the
//     ERC-20 contract); with the spender allowlisted but WITHOUT the deliberate --unlimited
//     ack it is denied unlimited_unacked (exit 3, asserted on error.code — the bare --yes
//     does NOT ack the unlimited approval, so the generic path cannot defeat the typed
//     ceremony); an ALLOWED --dry-run surfaces the classification verdict (approve /
//     attacker / unlimited) on a populated TxResult before signing; and only the deliberate
//     two-flag ceremony (--unlimited --yes) on the allowlisted spender signs (exit 0). The
//     typed path (`token approve --unlimited --yes`) and the generic path produce the SAME
//     verdict for the same (spender, amount).
//   - an UNRECOGNIZED selector (stake) to a non-allowlisted contract while a policy is
//     active routes to stage-5b policy.denied.contract_call (exit 3); `policy contract
//     allow <staking> --selector 0x<stake>` opens that EXACT triple (exit 0); a
//     different selector to the same contract still denies (the ack is per-triple).
//   - encode/decode NEVER touch policy: run under a deny-all policy and assert exit 0.
//
// Plus the read/write happy paths: add/list/show/remove, call earned (view), send stake
// (state change + journal), logs (event decode + indexed filter + non-indexed reject),
// encode/decode round-trip, and the --dry-run classification verdict.
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

// maxUint256Dec is 2^256-1 as a decimal string — the unlimited-approval sentinel the
// classifier + the ceremony match.
const maxUint256Dec = "115792089237316195423570985008687907853269984665640564039457584007913129639935"

// setupContractCLI spawns anvil, isolates state, writes a localanvil config, wires the
// keystore + ADMIN passphrases non-interactively, imports the funded dev key as the
// signer "owner", and deploys the Staking fixture + an ERC-20. It returns the anvil
// handle + the staking address + the erc20 address. Mirrors setupSignCLI.
func setupContractCLI(t *testing.T) (*testchain.Anvil, common.Address, common.Address) {
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
	t.Setenv("DAXIE_ACCOUNT", "owner")

	staking := testchain.DeployStaking(t, anvil)
	erc20 := testchain.DeployERC20(t, anvil) // deployer = owner holds the supply
	return anvil, staking, erc20
}

// addStaking registers the staking alias with its inline ABI via --abi-stdin. execCLI
// does not wire stdin, so the test writes the ABI to a file and uses --abi.
func addStaking(t *testing.T, alias string, addr common.Address) {
	t.Helper()
	abiFile := filepath.Join(t.TempDir(), "staking.abi.json")
	if err := os.WriteFile(abiFile, []byte(testchain.StakingABI), 0o600); err != nil {
		t.Fatalf("write staking abi: %v", err)
	}
	if _, stderr, code := execCLI(t, "contract", "add", alias, addr.Hex(), "--abi", abiFile); code != 0 {
		t.Fatalf("contract add %s: exit %d, stderr=%s", alias, code, stderr)
	}
}

// erc20ABIFile writes a minimal ERC-20 approve/transfer ABI to a temp file and returns
// the path (for the security-crux scenarios that drive the ERC-20 ad hoc).
func erc20ABIFile(t *testing.T) string {
	t.Helper()
	const erc20ABI = `[{"type":"function","name":"approve","inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"},{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"}]`
	f := filepath.Join(t.TempDir(), "erc20.abi.json")
	if err := os.WriteFile(f, []byte(erc20ABI), 0o600); err != nil {
		t.Fatalf("write erc20 abi: %v", err)
	}
	return f
}

// ── Scenario 1: add / list / show / remove (+ invalid-ABI reject) ──────────────

func TestContractCLI_RegistryCRUD(t *testing.T) {
	_, staking, _ := setupContractCLI(t)

	addStaking(t, "stk", staking)

	// list shows it.
	out, stderr, code := execCLI(t, "contract", "list", "--json")
	if code != 0 {
		t.Fatalf("contract list: exit %d, stderr=%s", code, stderr)
	}
	var lst domain.ContractListResult
	if err := json.Unmarshal([]byte(out), &lst); err != nil {
		t.Fatalf("contract list --json invalid: %v (%q)", err, out)
	}
	if len(lst.Contracts) != 1 || lst.Contracts[0].Alias != "stk" {
		t.Fatalf("contract list = %+v, want one alias stk", lst.Contracts)
	}
	if !strings.EqualFold(lst.Contracts[0].Address, staking.Hex()) {
		t.Errorf("listed address = %s, want %s", lst.Contracts[0].Address, staking.Hex())
	}

	// show prints the fn/event summary.
	sout, sstderr, scode := execCLI(t, "contract", "show", "stk", "--json")
	if scode != 0 {
		t.Fatalf("contract show: exit %d, stderr=%s", scode, sstderr)
	}
	var row domain.ContractRow
	if err := json.Unmarshal([]byte(sout), &row); err != nil {
		t.Fatalf("contract show --json invalid: %v (%q)", err, sout)
	}
	if row.FuncCount == 0 || row.EvtCount == 0 {
		t.Errorf("contract show fn=%d evt=%d, want both nonzero", row.FuncCount, row.EvtCount)
	}

	// An INVALID ABI at add → usage exit 2, NOT stored.
	badFile := filepath.Join(t.TempDir(), "bad.abi.json")
	if err := os.WriteFile(badFile, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write bad abi: %v", err)
	}
	if _, _, c := execCLI(t, "contract", "add", "bad", staking.Hex(), "--abi", badFile); c != 2 {
		t.Fatalf("contract add (bad abi) exit %d, want 2 (usage)", c)
	}
	if _, _, c := execCLI(t, "contract", "show", "bad", "--json"); c != 10 {
		t.Fatalf("contract show bad exit %d, want 10 (not stored ⇒ ref.not_found)", c)
	}

	// remove drops it.
	if _, rstderr, rcode := execCLI(t, "contract", "remove", "stk", "--yes"); rcode != 0 {
		t.Fatalf("contract remove: exit %d, stderr=%s", rcode, rstderr)
	}
	if _, _, c := execCLI(t, "contract", "show", "stk", "--json"); c != 10 {
		t.Fatalf("contract show after remove exit %d, want 10 (ref.not_found)", c)
	}
}

// ── Scenario 2: contract call earned (view; no signing, no policy) ─────────────

func TestContractCLI_CallEarnedView(t *testing.T) {
	anvil, staking, _ := setupContractCLI(t)
	addStaking(t, "stk", staking)
	owner := anvil.FundedAddress()

	// Stake first so earned() is nonzero (stake(amount) accrues amount/10).
	if _, stderr, code := execCLI(t, "contract", "send", "stk", "stake", "1000", "--yes"); code != 0 {
		t.Fatalf("contract send stake: exit %d, stderr=%s", code, stderr)
	}

	out, stderr, code := execCLI(t, "contract", "call", "stk", "earned", owner.Hex(), "--json")
	if code != 0 {
		t.Fatalf("contract call earned: exit %d, stderr=%s", code, stderr)
	}
	var res domain.ContractCallResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("contract call --json invalid: %v (%q)", err, out)
	}
	if len(res.Returns) != 1 || res.Returns[0].Value != "100" {
		t.Fatalf("earned returns = %+v, want one uint256 100 (1000/10)", res.Returns)
	}
	// Cross-check against the raw on-chain reader (independent of Daxie's abi).
	if got := anvil.StakingEarned(t, staking, owner); got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("raw on-chain earned = %s, want 100", got)
	}
}

// ── Scenario 3: contract send stake (state change + journal) ───────────────────

func TestContractCLI_SendStakeStateChange(t *testing.T) {
	anvil, staking, _ := setupContractCLI(t)
	addStaking(t, "stk", staking)
	owner := anvil.FundedAddress()

	out, stderr, code := execCLI(t, "contract", "send", "stk", "stake", "5000", "--wait", "--json")
	if code != 0 {
		t.Fatalf("contract send stake --wait: exit %d, stderr=%s", code, stderr)
	}
	var res domain.TxResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("contract send --json invalid: %v (%q)", err, out)
	}
	if res.Hash == "" {
		t.Fatal("contract send produced no tx hash")
	}

	// earned() reflects the stake (5000/10 = 500).
	if got := anvil.StakingEarned(t, staking, owner); got.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("earned after stake = %s, want 500", got)
	}

	// The journal records a contract-call kind tx.
	lout, _, lcode := execCLI(t, "tx", "list", "--json")
	if lcode != 0 {
		t.Fatalf("tx list: exit %d", lcode)
	}
	if !strings.Contains(lout, "contract-call") {
		t.Errorf("tx list does not show a contract-call kind: %s", lout)
	}
}

// ── Scenario 4: contract logs (event decode + indexed filter + non-indexed reject) ──

func TestContractCLI_LogsEventDecode(t *testing.T) {
	anvil, staking, _ := setupContractCLI(t)
	addStaking(t, "stk", staking)
	owner := anvil.FundedAddress()

	if _, stderr, code := execCLI(t, "contract", "send", "stk", "stake", "4200", "--wait"); code != 0 {
		t.Fatalf("contract send stake: exit %d, stderr=%s", code, stderr)
	}

	out, stderr, code := execCLI(t, "contract", "logs", "stk", "Staked", "--from-block", "0", "--json")
	if code != 0 {
		t.Fatalf("contract logs Staked: exit %d, stderr=%s", code, stderr)
	}
	var res domain.ContractLogsResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("contract logs --json invalid: %v (%q)", err, out)
	}
	if len(res.Logs) != 1 {
		t.Fatalf("Staked logs = %d, want 1", len(res.Logs))
	}
	// The decoded log carries labeled user + amount.
	var sawUser, sawAmount bool
	for _, a := range res.Logs[0].Args {
		if a.Name == "user" && strings.EqualFold(a.Value, owner.Hex()) {
			sawUser = true
		}
		if a.Name == "amount" && a.Value == "4200" {
			sawAmount = true
		}
	}
	if !sawUser || !sawAmount {
		t.Fatalf("decoded Staked log = %+v, want user=%s amount=4200", res.Logs[0].Args, owner.Hex())
	}

	// An --arg user=<owner> indexed filter narrows it (still one log).
	fout, _, fcode := execCLI(t, "contract", "logs", "stk", "Staked", "--from-block", "0", "--arg", "user="+owner.Hex(), "--json")
	if fcode != 0 {
		t.Fatalf("contract logs --arg user: exit %d", fcode)
	}
	var fres domain.ContractLogsResult
	if err := json.Unmarshal([]byte(fout), &fres); err != nil {
		t.Fatalf("filtered logs --json invalid: %v", err)
	}
	if len(fres.Logs) != 1 {
		t.Errorf("filtered Staked logs = %d, want 1", len(fres.Logs))
	}

	// A filter on the NON-indexed amount → usage exit 2.
	if _, _, c := execCLI(t, "contract", "logs", "stk", "Staked", "--from-block", "0", "--arg", "amount=4200", "--json"); c != 2 {
		t.Fatalf("contract logs --arg amount (non-indexed) exit %d, want 2 (usage)", c)
	}
}

// ── Scenario 5: THE SECURITY CRUX — approve(spender, MAX) via contract send ────

func TestContractCLI_ApproveClassifiedLikeTypedPath(t *testing.T) {
	anvil, _, erc20 := setupContractCLI(t)
	attacker := common.HexToAddress("0x000000000000000000000000000000000000A77a")
	abiFile := erc20ABIFile(t)

	// Seal a policy with limits + allowlist ON (the typed approve path's gates).
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}

	// (a) The spender NOT allowlisted: the calldata is classified KindApprove → the deny
	//     is exit 3 (allowlist rank-1 wins), and the allowlist subject in the denial is the
	//     DECODED attacker (arg0), NEVER the ERC-20 contract. Asserted POSITIVELY on the
	//     structured envelope: error.data.address == lower(attacker) AND != lower(erc20).
	_, stderr, code := execCLI(t, "contract", "send", erc20.Hex(), "approve", attacker.Hex(), maxUint256Dec, "--abi", abiFile, "--json")
	if code != 3 {
		t.Fatalf("contract send approve(attacker,MAX) non-allowlisted: exit %d, want 3 (policy denied)", code)
	}
	gotAddr := errEnvelopeDataString(t, stderr, "address")
	if !strings.EqualFold(gotAddr, attacker.Hex()) {
		t.Errorf("denial error.data.address = %q, want the DECODED attacker spender %s (the spender-as-subject invariant)", gotAddr, strings.ToLower(attacker.Hex()))
	}
	if strings.EqualFold(gotAddr, erc20.Hex()) {
		t.Errorf("denial names the ERC-20 contract %s as the allowlist subject — the bypass invariant is BROKEN", erc20.Hex())
	}

	// (b) An ALLOWED --dry-run --json returns a POPULATED TxResult whose Classification is
	//     asserted UNCONDITIONALLY: classified_as=approve, spender=decoded attacker,
	//     unlimited=true, exit 0 — the headline "proves the classification verdict before
	//     signing" claim. Allowlisting the spender (so stage-3b passes) + the deliberate
	//     --unlimited --yes ack (so the stage-6 unlimited gate passes) makes the dry-run
	//     ALLOWED; --dry-run still never signs.
	if _, astderr, ac := execCLI(t, "policy", "allow", attacker.Hex()); ac != 0 {
		t.Fatalf("policy allow attacker: exit %d, stderr=%s", ac, astderr)
	}
	dout, dstderr, dcode := execCLI(t, "contract", "send", erc20.Hex(), "approve", attacker.Hex(), maxUint256Dec, "--abi", abiFile, "--dry-run", "--unlimited", "--yes", "--json")
	if dcode != 0 {
		t.Fatalf("allowed contract send --dry-run: exit %d, want 0, stderr=%s", dcode, dstderr)
	}
	var dres domain.TxResult
	if err := json.Unmarshal([]byte(dout), &dres); err != nil {
		t.Fatalf("contract send --dry-run --json invalid: %v (%q)", err, dout)
	}
	if dres.Classification == nil {
		t.Fatal("dry-run TxResult carries no Classification — the pre-flight verdict is missing")
	}
	if dres.Classification.ClassifiedAs != "approve" {
		t.Errorf("dry-run classified_as = %q, want approve", dres.Classification.ClassifiedAs)
	}
	if !strings.EqualFold(dres.Classification.Spender, attacker.Hex()) {
		t.Errorf("dry-run spender = %q, want decoded attacker %s", dres.Classification.Spender, strings.ToLower(attacker.Hex()))
	}
	if !dres.Classification.Unlimited {
		t.Error("dry-run unlimited = false, want true (MAX is the sentinel)")
	}
	if dres.Hash != "" {
		t.Errorf("--dry-run produced a tx hash %q — it must never sign", dres.Hash)
	}

	// (c) END-TO-END unlimited_unacked: the spender is NOW allowlisted (stage-3b passes),
	//     so the ONLY gate that fires for an unlimited approve sent WITHOUT --unlimited is
	//     the stage-6 unlimited ceremony. This isolates unlimited_unacked from the allowlist
	//     deny and validates the header's claim through the real CLI/anvil funnel: --yes
	//     alone (confirm-skip) does NOT carry the ack — the generic path cannot defeat the
	//     typed ceremony.
	_, ustderr, ucode := execCLI(t, "contract", "send", erc20.Hex(), "approve", attacker.Hex(), maxUint256Dec, "--abi", abiFile, "--yes", "--json")
	if ucode != 3 {
		t.Fatalf("contract send approve(allowlisted,MAX) --yes WITHOUT --unlimited: exit %d, want 3 (unlimited_unacked)", ucode)
	}
	if gotCode := errEnvelopeCode(t, ustderr); gotCode != "policy.denied.unlimited_unacked" {
		t.Errorf("unacked-unlimited deny code = %q, want policy.denied.unlimited_unacked (the bare --yes must NOT ack the unlimited approval)", gotCode)
	}

	// (d) The DELIBERATE two-flag ceremony (--unlimited --yes) on an allowlisted spender ⇒
	//     signs (exit 0). This proves the generic path and the typed path (`token approve
	//     --unlimited --yes`) reach the SAME verdict for the same (spender, amount):
	//     allowlisted + acked unlimited ⇒ allowed.
	out, stderr, c := execCLI(t, "contract", "send", erc20.Hex(), "approve", attacker.Hex(), maxUint256Dec, "--abi", abiFile, "--wait", "--unlimited", "--yes", "--json")
	if c != 0 {
		t.Fatalf("contract send approve(allowlisted,MAX) --unlimited --yes: exit %d, stderr=%s", c, stderr)
	}
	var res domain.TxResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("contract send --json invalid: %v (%q)", err, out)
	}
	if res.Hash == "" {
		t.Fatal("allowlisted+acked approve produced no tx hash")
	}
	// The on-chain allowance is now MAX — the bypass would have set it silently; the gate
	// fired identically to the typed path and the operator deliberately acked it.
	want, _ := new(big.Int).SetString(maxUint256Dec, 10)
	if got := anvil.ERC20Allowance(t, erc20, anvil.FundedAddress(), attacker); got.Cmp(want) != 0 {
		t.Fatalf("on-chain allowance = %s, want MAX", got)
	}
}

// errEnvelopeDataString parses the §5.7 JSON error envelope on stderr and returns the
// string value of error.data[key] (failing the test if the envelope, the data block, or
// the key is missing/non-string). It turns a denial's structured payload into a real
// positive assertion target (the spender-as-subject invariant rides error.data.address).
func errEnvelopeDataString(t *testing.T, stderr, key string) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string         `json:"code"`
			Data map[string]any `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &env); err != nil {
		t.Fatalf("error envelope is not valid JSON: %v (%q)", err, stderr)
	}
	v, ok := env.Error.Data[key]
	if !ok {
		t.Fatalf("error.data[%q] absent in envelope %q", key, stderr)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("error.data[%q] = %v (%T), want a string", key, v, v)
	}
	return s
}

// errEnvelopeCode parses the §5.7 JSON error envelope on stderr and returns error.code
// (the canonical dotted deny code), failing the test on a malformed envelope.
func errEnvelopeCode(t *testing.T, stderr string) string {
	t.Helper()
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &env); err != nil {
		t.Fatalf("error envelope is not valid JSON: %v (%q)", err, stderr)
	}
	return env.Error.Code
}

// ── Scenario 6: stage-5b unknown-selector deny + per-triple allow ──────────────

func TestContractCLI_UnknownSelectorStage5b(t *testing.T) {
	anvil, staking, _ := setupContractCLI(t)
	addStaking(t, "stk", staking)

	// A policy is active with limits set + allowlist ON (the design-faithful posture). The
	// staking contract is NOT in the address allowlist, so the only way a stake() (an
	// UNRECOGNIZED selector) opens is the stage-5b per-triple opt-in (§4.3 stage 5b: refused
	// "unless the contract address is allowlisted OR the (network, contract, selector) triple
	// is in contracts_allowed[]"). Stage-3b does NOT gate the contract-as-destination on an
	// unknown-calldata send — stage-5b governs that destination — so the triple-allow below
	// can open the send with the allowlist on. The ETH per-tx/daily/gas gates still cap
	// --value/gas a fortiori. deny-by-default holds for any non-opted-in selector.
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}

	_, stderr, code := execCLI(t, "contract", "send", "stk", "stake", "100")
	if code != 3 {
		t.Fatalf("contract send stake (unknown, non-opted-in) exit %d, want 3 (policy denied)", code)
	}
	if !strings.Contains(stderr, "contract_call") {
		t.Errorf("stage-5b deny code missing contract_call: %s", stderr)
	}

	// Allow the EXACT (network, contract, selector) triple → the SAME send now passes.
	if _, astderr, acode := execCLI(t, "policy", "contract", "allow", staking.Hex(),
		"--selector", "0xa694fc3a", "--network", "localanvil"); acode != 0 {
		t.Fatalf("policy contract allow: exit %d, stderr=%s", acode, astderr)
	}
	if _, sstderr, scode := execCLI(t, "contract", "send", "stk", "stake", "100", "--wait"); scode != 0 {
		t.Fatalf("contract send stake after allow: exit %d, stderr=%s", scode, sstderr)
	}

	// A DIFFERENT selector to the same contract still denies (the ack is per-triple).
	// withdraw(uint256) = 0x2e1a7d4d — not allowed.
	if _, _, c := execCLI(t, "contract", "send", "stk", "withdraw", "100"); c != 3 {
		t.Fatalf("contract send withdraw (different selector) exit %d, want 3 (per-triple ack)", c)
	}
	_ = anvil
}

// ── Scenario 7: encode / decode round-trip (pure; bypass-irrelevant) ───────────

func TestContractCLI_EncodeDecodePure(t *testing.T) {
	_, staking, _ := setupContractCLI(t)
	addStaking(t, "stk", staking)

	// A deny-all policy is active: encode/decode MUST still succeed (exit 0) — they
	// never touch policy. (max-tx 0 denies every value-moving send.)
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "0", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set deny-all: exit %d, stderr=%s", code, stderr)
	}

	out, stderr, code := execCLI(t, "contract", "encode", "stk", "stake", "777", "--json")
	if code != 0 {
		t.Fatalf("contract encode under deny-all: exit %d, stderr=%s", code, stderr)
	}
	var enc domain.EncodeResult
	if err := json.Unmarshal([]byte(out), &enc); err != nil {
		t.Fatalf("contract encode --json invalid: %v (%q)", err, out)
	}
	if !strings.HasPrefix(enc.Calldata, "0xa694fc3a") {
		t.Fatalf("encoded calldata = %q, want stake selector 0xa694fc3a prefix", enc.Calldata)
	}

	dout, dstderr, dcode := execCLI(t, "contract", "decode", enc.Calldata, "--sig", "stake(uint256)", "--json")
	if dcode != 0 {
		t.Fatalf("contract decode under deny-all: exit %d, stderr=%s", dcode, dstderr)
	}
	var dec domain.DecodeResult
	if err := json.Unmarshal([]byte(dout), &dec); err != nil {
		t.Fatalf("contract decode --json invalid: %v (%q)", err, dout)
	}
	if len(dec.Args) != 1 || dec.Args[0].Value != "777" {
		t.Fatalf("decoded args = %+v, want one uint256 777 (round-trip)", dec.Args)
	}
	if dec.Selector != "0xa694fc3a" {
		t.Errorf("decoded selector = %q, want 0xa694fc3a", dec.Selector)
	}
}
