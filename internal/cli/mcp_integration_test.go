//go:build integration

// mcp_integration_test.go is the §2.9 MCP ANVIL SMOKE — the executable proof of
// one-core/two-frontends. It drives the SAME on-chain scenarios through the OTHER
// frontend (the MCP server, over an in-memory MCP pipe the way `daxie mcp serve` serves
// over stdio) against a real local anvil, and asserts the IDENTICAL on-chain effect the
// CLI produces (internal/cli/tx_integration_test.go is the CLI-path control): a `send`
// tool moves ETH, the recipient balance increases by exactly the amount, the result is
// confirmed, and the journal record carries Source:"mcp". It then proves guardrails bind
// MCP IDENTICALLY (§6.4): a `send`/`token_approve` over MCP that violates a sealed policy
// returns the SAME policy.denied.* tool-error the CLI gets, with NOTHING signed — a
// prompt-injected agent cannot skip the check because mcpserver cannot import policy/keys.
//
// Compiled only under `go test -tags integration`. anvil must be on PATH (CI's
// foundry-toolchain provides it; DAXIE_IT_REQUIRE_ANVIL=1 turns a missing anvil into a
// hard failure rather than a silent skip — honored by testchain.Spawn / setupAnvilCLI).
package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/mcpserver"
	"github.com/daxchain-io/daxie/internal/testchain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcpClient opens a real service against the env configured by setupAnvilCLI, builds the
// transport-agnostic MCP server over it (mcpserver.New — the SAME assembly `daxie mcp
// serve` uses), and connects an in-memory MCP client. The returned session drives real
// tools/call requests through the real server with no OS process. Cleanup closes both.
func mcpClient(t *testing.T) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	svc, closeFn, err := openService(ctx, &rootState{})
	if err != nil {
		t.Fatalf("openService: %v", err)
	}
	t.Cleanup(closeFn)

	srv := mcpserver.New(svc)
	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("mcp server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-integration-test", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("mcp client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// callTool issues a tools/call and returns the result. A transport/protocol fault —
// including any tool-output schema-validation failure — is a FATAL test error: the
// value-returning tools (send, tx_status, …) carry common.Address/Hash/domain.Duration,
// which mcpserver/tools/schema.go types as JSON strings (matching their encoding/json
// wire form) so the SDK validates a real result rather than rejecting it. A tool-level
// outcome (IsError + content, e.g. a policy denial) is returned for inspection. There is
// NO skip here: the smoke is a REAL stdio-equivalent MCP session that must produce the
// real on-chain effect, so a recurrence of the value-type schema bug fails the gate.
func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: protocol error: %v", name, err)
	}
	return res
}

// structResult decodes a successful tool result's structured content into out. The SDK
// fills StructuredContent from the typed Out on the success (and dual-signal) paths.
func structResult(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("decode structured content into %T: %v (%s)", out, err, b)
	}
}

// toolErrorText concatenates a result's text content (where the SDK packs a tool error's
// domain.Error JSON envelope — byte-identical to the CLI --json error, §6.6).
func toolErrorText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// Scenario 1: a `send` (ETH) over the MCP frontend produces the IDENTICAL on-chain
// effect as the CLI `tx send` — recipient balance += exactly the amount, status
// confirmed — AND the journal record carries Source:"mcp" (the ONE sanctioned
// difference from the CLI path, §6.4).
func TestMCP_SendETH_IdenticalOnChainEffect(t *testing.T) {
	setupAnvilCLI(t)
	cs := mcpClient(t)

	before := balanceWei(t, freshRecipient)

	res := callTool(t, cs, "send", map[string]any{
		"from":   "funded",
		"to":     freshRecipient.Hex(),
		"amount": "0.5",
		// NO confirm field: the confirmation is invisible over MCP (json:"-", wired
		// constant-true server-side by sendCeremony). The schema is additionalProperties:
		// false, so passing it would be rejected.
		"wait": map[string]any{},
	})
	if res.IsError {
		t.Fatalf("send tool errored: %s", toolErrorText(res))
	}

	var out domain.TxResult
	structResult(t, res, &out)
	if out.Status != domain.TxStatusConfirmed {
		t.Fatalf("status = %q, want confirmed", out.Status)
	}
	if out.Hash == "" {
		t.Fatal("confirmed send carries no hash")
	}

	after := balanceWei(t, freshRecipient)
	delta := new(big.Int).Sub(after, before)
	half, _ := new(big.Int).SetString("500000000000000000", 10) // 0.5 ETH
	if delta.Cmp(half) != 0 {
		t.Fatalf("recipient delta = %s wei, want exactly 5e17 (0.5 ETH) — same as the CLI path", delta)
	}

	// The journal record exists with Source:"mcp" (chain-id 31337 ⇒ journal/31337.jsonl).
	journal := readJournal(t)
	if !strings.Contains(journal, `"source":"mcp"`) && !strings.Contains(journal, `"source": "mcp"`) {
		t.Errorf("journal has no Source:\"mcp\" record after an MCP send:\n%s", journal)
	}
}

// Scenario 2 (guardrail identity): with a sealed policy that DENIES the send (a per-tx
// limit below the amount, allowlist on with the recipient not allowlisted), the SAME
// `send` over MCP returns the SAME policy.denied.* tool-error the CLI gets (exit-3
// family), and NOTHING is signed (the recipient balance is unchanged). The policy is
// sealed BEFORE the service opens, so the running server loads it on the authorize path
// it shares with the CLI — mcpserver cannot import policy, so it cannot skip the check.
func TestMCP_PolicyDeniesSend_NothingSigned(t *testing.T) {
	setupAnvilCLI(t)

	// Seal a restrictive policy via the CLI admin path (the agent never holds this).
	adminFile := filepath.Join(t.TempDir(), "admin")
	if err := os.WriteFile(adminFile, []byte("mcp integration admin\n"), 0o600); err != nil {
		t.Fatalf("seed admin pass: %v", err)
	}
	t.Setenv("DAXIE_ADMIN_PASSPHRASE_FILE", adminFile)
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "0.001eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}

	before := balanceWei(t, freshRecipient)

	cs := mcpClient(t)
	res := callTool(t, cs, "send", map[string]any{
		"from":   "funded",
		"to":     freshRecipient.Hex(), // not allowlisted, and amount > max-tx
		"amount": "0.5",
		"wait":   map[string]any{},
	})
	if !res.IsError {
		t.Fatalf("send over MCP was NOT denied by a sealed policy (guardrails must bind MCP identically, §6.4)")
	}
	env := toolErrorText(res)
	if !strings.Contains(env, "policy.denied") {
		t.Errorf("MCP send denial code is not policy.denied.*: %s", env)
	}

	after := balanceWei(t, freshRecipient)
	if before.Cmp(after) != 0 {
		t.Fatalf("a policy-denied MCP send MOVED funds: before=%s after=%s — nothing must be signed", before, after)
	}
}

// Scenario 2b (the unlimited ceremony over MCP): an unlimited token_approve that does NOT
// acknowledge the unlimited grant is denied policy.denied.unlimited_unacked, with nothing
// signed. The acknowledgement is the dedicated `acknowledge_unlimited` schema field —
// the ONE named ack field across token_approve/sign_typed_data/contract_send (§6.3/§6.4) —
// mapped to Check.Acked. The write ceremony wires the TTY-skip (Yes) server-side but
// DELIBERATELY never touches acknowledge_unlimited, so an `unlimited: true` approve that
// omits `acknowledge_unlimited` is the genuine "the agent did not say the dangerous thing
// out loud" case: the core's unlimited gate must deny it exactly as the CLI denies an
// unacked `--unlimited`, proving the §6.4 gate binds MCP identically.
func TestMCP_UnlimitedApproveUnacked_Denied(t *testing.T) {
	anvil := setupAnvilCLI(t)

	// Deploy a REAL ERC-20 (deployer = funded acct0 holds the supply) and register it, so
	// the approve path's metadata read (decimals/symbol) succeeds and the operative gate is
	// the §4.2 unlimited-ack ceremony — not a "not an ERC-20" usage error. The MCP tool
	// executes the same approve pipeline the CLI does, so the token must really exist.
	token := testchain.DeployERC20(t, anvil)
	if _, stderr, code := execCLI(t, "token", "add", token.Hex(), "--name", "tst"); code != 0 {
		t.Fatalf("token add: exit %d, stderr=%s", code, stderr)
	}

	adminFile := filepath.Join(t.TempDir(), "admin")
	if err := os.WriteFile(adminFile, []byte("mcp integration admin\n"), 0o600); err != nil {
		t.Fatalf("seed admin pass: %v", err)
	}
	t.Setenv("DAXIE_ADMIN_PASSPHRASE_FILE", adminFile)
	// A policy with an allowlist on; allow the spender so the ONLY remaining gate is the
	// unlimited-ack ceremony (isolate it from the allowlist gate).
	spender := "0x000000000000000000000000000000000000A77a"
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}
	if _, stderr, code := execCLI(t, "policy", "allow", spender); code != 0 {
		t.Fatalf("policy allow spender: exit %d, stderr=%s", code, stderr)
	}

	allowanceBefore := anvil.ERC20Allowance(t, token, anvil.FundedAddress(), common.HexToAddress(spender))

	cs := mcpClient(t)
	res := callTool(t, cs, "token_approve", map[string]any{
		"from":      "funded",
		"token":     token.Hex(),
		"spender":   spender,
		"unlimited": true,
		// acknowledge_unlimited OMITTED — the agent did NOT say the dangerous thing out
		// loud. The ceremony wires Yes (TTY-skip) but never the ack, so this reaches the
		// core's unlimited gate unacknowledged and must be denied (§6.4).
		"wait": map[string]any{},
	})
	if !res.IsError {
		t.Fatalf("an UNLIMITED approve without acknowledge_unlimited was NOT denied over MCP (the §6.4 ceremony must bind identically)")
	}
	env := toolErrorText(res)
	if !strings.Contains(env, "unlimited_unacked") && !strings.Contains(env, "policy.denied") {
		t.Errorf("unacked unlimited approve denial code unexpected: %s", env)
	}
	// Nothing signed: the on-chain allowance is unchanged (the deny happened before the tx).
	allowanceAfter := anvil.ERC20Allowance(t, token, anvil.FundedAddress(), common.HexToAddress(spender))
	if allowanceBefore.Cmp(allowanceAfter) != 0 {
		t.Fatalf("a denied unlimited approve over MCP changed the on-chain allowance: before=%s after=%s — nothing must be signed", allowanceBefore, allowanceAfter)
	}
}

// Scenario 2c (the BOUNDED-approve success branch over MCP): a bounded token_approve
// SUCCEEDS on-chain — the allowance is set to exactly the approved amount, and the journal
// records Source:"mcp". This exercises approveCeremony's success path (Yes wired
// server-side; NO acknowledge_unlimited needed for a bounded grant) end-to-end against a
// real ERC-20 — the happy-path approve branch the deny-only scenarios never reached.
func TestMCP_BoundedApprove_OnChainAllowance(t *testing.T) {
	anvil := setupAnvilCLI(t)

	token := testchain.DeployERC20(t, anvil)
	if _, stderr, code := execCLI(t, "token", "add", token.Hex(), "--name", "tst"); code != 0 {
		t.Fatalf("token add: exit %d, stderr=%s", code, stderr)
	}
	spender := common.HexToAddress("0x000000000000000000000000000000000000A77a")

	cs := mcpClient(t)
	res := callTool(t, cs, "token_approve", map[string]any{
		"from":    "funded",
		"token":   token.Hex(),
		"spender": spender.Hex(),
		"amount":  "250", // a bounded allowance; no acknowledge_unlimited needed
		"wait":    map[string]any{},
	})
	if res.IsError {
		t.Fatalf("bounded token_approve over MCP errored: %s", toolErrorText(res))
	}
	var out domain.TxResult
	structResult(t, res, &out)
	if out.Status != domain.TxStatusConfirmed {
		t.Fatalf("bounded approve status = %q, want confirmed", out.Status)
	}

	// The on-chain allowance equals the approved amount (250 × 10^decimals). DeployERC20
	// uses 18 decimals; assert the base-unit allowance matches.
	want := new(big.Int).Mul(big.NewInt(250), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	got := anvil.ERC20Allowance(t, token, anvil.FundedAddress(), spender)
	if got.Cmp(want) != 0 {
		t.Fatalf("on-chain allowance after MCP bounded approve = %s, want %s", got, want)
	}

	// The journal records the MCP origin (the ONE sanctioned CLI/MCP difference, §6.4).
	journal := readJournal(t)
	if !strings.Contains(journal, `"source":"mcp"`) && !strings.Contains(journal, `"source": "mcp"`) {
		t.Errorf("journal has no Source:\"mcp\" record after an MCP approve:\n%s", journal)
	}
}

// Scenario 2d (contract_send SUCCESS over MCP): a `contract_send` to the staking fixture
// produces a REAL on-chain state change identical to the CLI contract send (the M10
// headline wired onto MCP in M11). It exercises contractSendCeremony + the stage-2
// ClassifyCalldata path (a benign stake selector classifies as unknown-but-allowed when no
// sealed policy gates it) end-to-end against a real chain, with journal Source:"mcp".
func TestMCP_ContractSend_OnChainStateChange(t *testing.T) {
	anvil := setupAnvilCLI(t)
	staking := testchain.DeployStaking(t, anvil)

	// Register the staking alias with its inline ABI (operator CLI act; the agent then
	// transacts by alias). --abi-stdin is not wired through execCLI, so use --abi <file>.
	abiFile := filepath.Join(t.TempDir(), "staking.abi.json")
	if err := os.WriteFile(abiFile, []byte(testchain.StakingABI), 0o600); err != nil {
		t.Fatalf("write staking abi: %v", err)
	}
	if _, stderr, code := execCLI(t, "contract", "add", "stk", staking.Hex(), "--abi", abiFile); code != 0 {
		t.Fatalf("contract add stk: exit %d, stderr=%s", code, stderr)
	}

	before := anvil.StakingEarned(t, staking, anvil.FundedAddress())

	cs := mcpClient(t)
	res := callTool(t, cs, "contract_send", map[string]any{
		"from":     "funded",
		"contract": "stk",
		"method":   "stake",
		"args":     []any{"5000"},
		"wait":     map[string]any{},
	})
	if res.IsError {
		t.Fatalf("contract_send stake over MCP errored: %s", toolErrorText(res))
	}
	var out domain.TxResult
	structResult(t, res, &out)
	if out.Status != domain.TxStatusConfirmed {
		t.Fatalf("contract_send status = %q, want confirmed", out.Status)
	}
	if out.Hash == "" {
		t.Fatal("confirmed contract_send carries no hash")
	}

	// The staking fixture accrues amount/10 in rewards; earned() must increase by 500.
	after := anvil.StakingEarned(t, staking, anvil.FundedAddress())
	delta := new(big.Int).Sub(after, before)
	if delta.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("staking earned delta = %s, want 500 (5000/10) — the on-chain state changed identically to the CLI path", delta)
	}
	journal := readJournal(t)
	if !strings.Contains(journal, `"source":"mcp"`) && !strings.Contains(journal, `"source": "mcp"`) {
		t.Errorf("journal has no Source:\"mcp\" record after an MCP contract_send:\n%s", journal)
	}
}

// Scenario 2e (contract_send classifier binds MCP — the CRUX): a `contract_send` whose
// raw calldata encodes approve(spender, MAX) is CLASSIFIED at stage 5b inside authorize
// EXACTLY like token_approve, so without acknowledge_unlimited it is denied
// policy.denied.unlimited_unacked with NOTHING signed — proving raw calldata is not a
// policy bypass over MCP and the §6.4 unlimited gate binds the generic signer identically.
// (The spender is allowlisted so the ONLY remaining gate is the unlimited-ack ceremony.)
func TestMCP_ContractSendUnlimitedApprove_Denied(t *testing.T) {
	anvil := setupAnvilCLI(t)
	erc20 := testchain.DeployERC20(t, anvil)
	spender := common.HexToAddress("0x000000000000000000000000000000000000A77a")

	// Seal a policy: limits + allowlist on, spender allowed → isolate the unlimited gate.
	adminFile := filepath.Join(t.TempDir(), "admin")
	if err := os.WriteFile(adminFile, []byte("mcp integration admin\n"), 0o600); err != nil {
		t.Fatalf("seed admin pass: %v", err)
	}
	t.Setenv("DAXIE_ADMIN_PASSPHRASE_FILE", adminFile)
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}
	if _, stderr, code := execCLI(t, "policy", "allow", spender.Hex()); code != 0 {
		t.Fatalf("policy allow spender: exit %d, stderr=%s", code, stderr)
	}

	// The inline ERC-20 approve ABI so contract_send can pack approve(spender, MAX) against
	// a raw 0x address (no registry alias — the raw-0x + inline-ABI agent path).
	const erc20ABI = `[{"type":"function","name":"approve","inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"}]`

	allowanceBefore := anvil.ERC20Allowance(t, erc20, anvil.FundedAddress(), spender)

	cs := mcpClient(t)
	res := callTool(t, cs, "contract_send", map[string]any{
		"from":     "funded",
		"contract": erc20.Hex(),
		"method":   "approve",
		"args":     []any{spender.Hex(), maxUint256Dec},
		"abi":      map[string]any{"abi_json": erc20ABI},
		// acknowledge_unlimited OMITTED — the classifier detects an UNLIMITED approve and
		// the unlimited gate must deny it (raw calldata is NOT a bypass, §4.2/§6.4).
		"wait": map[string]any{},
	})
	if !res.IsError {
		t.Fatal("an UNLIMITED approve via contract_send without acknowledge_unlimited was NOT denied over MCP (the classifier must bind the §6.4 gate)")
	}
	env := toolErrorText(res)
	if !strings.Contains(env, "unlimited_unacked") && !strings.Contains(env, "policy.denied") {
		t.Errorf("contract_send unlimited-classified deny code unexpected: %s", env)
	}
	// Nothing signed: the on-chain allowance is unchanged (the deny happened before the tx).
	allowanceAfter := anvil.ERC20Allowance(t, erc20, anvil.FundedAddress(), spender)
	if allowanceBefore.Cmp(allowanceAfter) != 0 {
		t.Fatalf("a denied unlimited contract_send over MCP changed the allowance: before=%s after=%s — nothing must be signed", allowanceBefore, allowanceAfter)
	}
}

// Scenario 2f (sign_typed_data routes through the permit gate over MCP): an EIP-2612
// permit to a NON-allowlisted spender is denied policy.denied.* at SIGNATURE time
// (authorizeSignature, the gasless spend-equivalent gate), with NO signature returned —
// proving a fund-moving permit signature is policy-checked identically over MCP and that
// nothing is signed on a denial. (A permit moves funds with no tx, so this is load-bearing.)
func TestMCP_SignTypedPermitNonAllowlisted_Denied(t *testing.T) {
	anvil := setupAnvilCLI(t)
	owner := anvil.FundedAddress()
	rogue := common.HexToAddress("0x00000000000000000000000000000000000005A1") // NOT allowlisted

	token := testchain.DeployERC2612(t, anvil) // deployer = funded owner holds the supply

	// Seal a policy with an allowlist ON but the permit spender NOT allowed → deny at
	// signature time exactly like an on-chain approve to a non-allowlisted spender.
	adminFile := filepath.Join(t.TempDir(), "admin")
	if err := os.WriteFile(adminFile, []byte("mcp integration admin\n"), 0o600); err != nil {
		t.Fatalf("seed admin pass: %v", err)
	}
	t.Setenv("DAXIE_ADMIN_PASSPHRASE_FILE", adminFile)
	if _, stderr, code := execCLI(t, "policy", "set", "--max-tx", "1eth", "--allowlist", "on"); code != 0 {
		t.Fatalf("policy set: exit %d, stderr=%s", code, stderr)
	}

	value := new(big.Int).Mul(big.NewInt(7), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	deadline := big.NewInt(9_999_999_999)
	nonce := anvil.PermitNonce(t, token, owner)
	doc := testchain.Permit712(testchain.AnvilChainID, token, owner, rogue, value, nonce, deadline)

	cs := mcpClient(t)
	res := callTool(t, cs, "sign_typed_data", map[string]any{
		"account": "funded",
		// 'typed' is []byte → base64 over MCP (the recorded D6 wire form).
		"typed": base64.StdEncoding.EncodeToString(doc),
		// acknowledge_unlimited OMITTED (a bounded permit; the gate that fires is the
		// allowlist, not the unlimited ack).
	})
	if !res.IsError {
		t.Fatal("a permit to a NON-allowlisted spender was NOT denied over MCP (sign_typed_data must route through authorizeSignature)")
	}
	env := toolErrorText(res)
	if !strings.Contains(env, "policy.denied") {
		t.Errorf("sign_typed_data permit deny code is not policy.denied.*: %s", env)
	}
	// No signature returned: the structured content is absent on a plain tool-error path
	// (no dual-signal for signatures), and no SigResult is decodable.
	if res.StructuredContent != nil {
		var sig domain.SigResult
		structResult(t, res, &sig)
		if sig.Signature != "" {
			t.Fatalf("a denied permit over MCP returned a signature %q — nothing must be signed", sig.Signature)
		}
	}
}

// Scenario 3 (the pure smoke, §6.3): the `convert` tool round-trips over the MCP pipe —
// the cheapest live-server proof the OTHER frontend serves real tools/call requests.
func TestMCP_ConvertRoundTrip(t *testing.T) {
	setupAnvilCLI(t)
	cs := mcpClient(t)

	res := callTool(t, cs, "convert", map[string]any{"amount": "1eth", "to": "gwei"})
	if res.IsError {
		t.Fatalf("convert tool errored: %s", toolErrorText(res))
	}
	var out domain.ConvertResult
	structResult(t, res, &out)
	if out.Value != "1000000000" {
		t.Errorf("convert 1eth->gwei value = %q, want 1000000000", out.Value)
	}
}

// Scenario 4 (the REAL stdio serve path end-to-end): spawn an actual `daxie mcp serve
// --transport stdio` SUBPROCESS, perform the MCP initialize/initialized handshake over its
// real OS stdin/stdout pipes (the SDK CommandTransport drives ServeStdio →
// srv.Run(ctx, &mcp.StdioTransport{})), call the `send` tool against local anvil, and
// assert the recipient balance delta + journal Source:"mcp". This proves the LITERAL claim
// "starts `daxie mcp serve` over stdio and drives a real on-chain scenario through it" —
// the StdioTransport framing over real pipes exercised together with a signing/on-chain
// scenario, not just the in-memory transport against the same *mcp.Server object.
func TestMCP_StdioServe_OnChainSend(t *testing.T) {
	setupAnvilCLI(t) // sets DAXIE_* env (inherited by the subprocess) + imports "funded"

	// Build the real daxie binary once for this test (CGO off, matching the gate build).
	bin := filepath.Join(t.TempDir(), "daxie-stdio")
	build := exec.Command("go", "build", "-o", bin, "github.com/daxchain-io/daxie/cmd/daxie")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build daxie binary: %v\n%s", err, out)
	}

	before := balanceWei(t, freshRecipient)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Spawn the REAL serve subprocess; the SDK CommandTransport wires its stdin/stdout and
	// performs the initialize/initialized handshake. The subprocess inherits the test env
	// (DAXIE_CONFIG/KEYSTORE/STATE_DIR/PASSPHRASE_FILE), so it opens the SAME wallet/anvil.
	cmd := exec.CommandContext(ctx, bin, "mcp", "serve", "--transport", "stdio")
	cmd.Env = os.Environ()
	cmd.Stderr = os.Stderr // serve logs go to stderr; stdout is the MCP JSON-RPC pipe

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-stdio-integration", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect to `daxie mcp serve --transport stdio` over real OS pipes: %v", err)
	}
	defer func() { _ = cs.Close() }() // closing the session terminates the subprocess (EOF shutdown)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "send",
		Arguments: map[string]any{
			"from":   "funded",
			"to":     freshRecipient.Hex(),
			"amount": "0.25",
			"wait":   map[string]any{},
		},
	})
	if err != nil {
		t.Fatalf("send over the stdio serve subprocess: protocol error: %v", err)
	}
	if res.IsError {
		t.Fatalf("send tool over stdio serve errored: %s", toolErrorText(res))
	}
	var out domain.TxResult
	structResult(t, res, &out)
	if out.Status != domain.TxStatusConfirmed {
		t.Fatalf("stdio-serve send status = %q, want confirmed", out.Status)
	}

	after := balanceWei(t, freshRecipient)
	delta := new(big.Int).Sub(after, before)
	quarter, _ := new(big.Int).SetString("250000000000000000", 10) // 0.25 ETH
	if delta.Cmp(quarter) != 0 {
		t.Fatalf("recipient delta over the REAL stdio serve = %s wei, want exactly 2.5e17 (0.25 ETH)", delta)
	}

	// The journal (written by the subprocess to the shared STATE_DIR) carries Source:"mcp".
	journal := readJournal(t)
	if !strings.Contains(journal, `"source":"mcp"`) && !strings.Contains(journal, `"source": "mcp"`) {
		t.Errorf("journal has no Source:\"mcp\" record after a stdio-serve MCP send:\n%s", journal)
	}
}

// readJournal returns the chain-31337 journal file contents (one append-only JSONL file
// per chain; setupAnvilCLI configures localanvil at chain-id 31337).
func readJournal(t *testing.T) string {
	t.Helper()
	stateDir := os.Getenv("DAXIE_STATE_DIR")
	if stateDir == "" {
		t.Fatal("DAXIE_STATE_DIR not set (setupAnvilCLI should have set it)")
	}
	path := filepath.Join(stateDir, "journal", "31337.jsonl")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read journal %s: %v", path, err)
	}
	return string(b)
}

// (compile-time sanity: the MCP send produces a confirmed-or-pending status from the
// shared enum, so the agent's branch point is the same as the CLI's exit codes.)
var _ = common.HexToAddress
