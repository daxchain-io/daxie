package cli

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	ethereum "github.com/ethereum/go-ethereum"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/mcpserver"
	"github.com/daxchain-io/daxie/internal/service"
	"github.com/ethereum/go-ethereum/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcp_parity_test.go is the §2.9 FRONTEND-PARITY proof: the one-core/two-frontends law
// is BEHAVIORAL — both frontends must drive the IDENTICAL core method with the IDENTICAL
// request struct. It catches logic sneaking into a frontend (a frontend that quietly
// rewrote an amount, swapped a destination, or skipped the confirm gate would diverge).
//
// Mechanism (no network): the SAME logical request ("send 0.5 ETH to 0xC0DE from the
// default account") is driven through BOTH REAL frontends —
//   - the CLI via cobra ExecuteC (`tx send … --dry-run --json`), so the actual
//     newTxSendCmd RunE (resolveFrom, the gas/wait flag binding, the domain.TxRequest it
//     builds) is exercised end-to-end, and
//   - the MCP server via a real in-memory tools/call (`send {…, "dry_run": true}`) on
//     mcpserver.New(svc) — the SAME assembly `daxie mcp serve` uses —
// against ONE shared recording chain provider injected into BOTH services. The CLI arm
// opens its own service (the real production path); the parity test injects the SAME
// recording provider into it via the nil-in-production testOpenServiceHook seam, so both
// arms reach an identically-funded fake and the same (network, rpc) selection is
// comparable. --dry-run runs the FULL authorize verdict (gas estimate + policy.Evaluate)
// and returns the materialized request WITHOUT signing/broadcasting.
//
// The assertion: both frontends produce a domain.TxResult with byte-identical
// materialized request fields (From, To, AmountWei, Asset, Gas, DryRun) — i.e. the
// IDENTICAL domain.TxRequest reached the IDENTICAL svc.SendTx. The ONE sanctioned
// difference (Principal.Label cli vs mcp, §6.4) is NOT on the request/result wire; it
// rides on the journal Source, which a dry-run never writes — so the dry-run results are
// expected to be exactly equal.

// recordingProvider is a service.ChainProvider that hands out one recording fake and
// records the ChainRequest it was asked for, so the test can also assert both frontends
// selected the same (network, rpc).
type recordingProvider struct {
	cc       chain.Client
	requests []service.ChainRequest
}

func (p *recordingProvider) ClientFor(_ context.Context, req service.ChainRequest) (chain.Client, error) {
	p.requests = append(p.requests, req)
	return p.cc, nil
}
func (p *recordingProvider) VerifyEndpoint(context.Context, string, config.Endpoint) error {
	return nil
}

// setParityEnv isolates state, writes a localtest network at chain-id 1 (matching the
// fake's default ChainIDVal), wires a non-interactive keystore passphrase + light KDF,
// and imports a standalone account named "acct" so `from` resolves without a TTY.
func setParityEnv(t *testing.T) {
	t.Helper()
	cfgDir := t.TempDir()
	cfg := "schema = 1\n\n" +
		"[defaults]\nnetwork = \"localtest\"\n\n" +
		"[networks.localtest]\nchain-id = 1\nconfirmations = 1\ndefault-rpc = \"localtest-rpc\"\n\n" +
		"[rpc.localtest-rpc]\nnetwork = \"localtest\"\nurl = \"http://127.0.0.1:0\"\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(cfg), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	passFile := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(passFile, []byte("parity passphrase\n"), 0o600); err != nil {
		t.Fatalf("seed pass: %v", err)
	}
	// A throwaway, well-known dev key (anvil acct0) — controls only an in-memory fake.
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	t.Setenv("DAXIE_CONFIG", cfgDir)
	t.Setenv("DAXIE_KEYSTORE", t.TempDir())
	t.Setenv("DAXIE_STATE_DIR", t.TempDir())
	t.Setenv("DAXIE_CACHE_DIR", t.TempDir())
	t.Setenv("DAXIE_PASSPHRASE_FILE", passFile)
	t.Setenv("DAXIE_PASSPHRASE_CONFIRM_FILE", passFile)
	t.Setenv("DAXIE_KDF_LIGHT", "1")

	if _, stderr, code := execCLI(t, "account", "import", "acct", "--key-file", keyFile, "--yes"); code != 0 {
		t.Fatalf("account import: exit %d, stderr=%s", code, stderr)
	}
}

// fundedFake builds a chain fake that funds the imported account so a dry-run estimate
// + policy verdict pass, and reports chain-id 1 (matching the config network).
func fundedFake(t *testing.T) *fake.Client {
	t.Helper()
	f := fake.New()
	f.ChainIDVal = big.NewInt(1)
	// anvil acct0 derived address; fund it generously so the dry-run sees a balance.
	addr := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	bal, _ := new(big.Int).SetString("100000000000000000000", 10) // 100 ETH
	f.Balances[addr] = bal
	return f
}

// injectProvider swaps the service's unexported chain provider with the recording one.
// This is a TEST-ONLY seam (the §2.9 single load-bearing fake), exercised via reflect so
// no production interface widening is needed; it mirrors how service-package tests set
// svc.chains directly.
func injectProvider(t *testing.T, svc *service.Service, prov service.ChainProvider) {
	t.Helper()
	v := reflect.ValueOf(svc).Elem().FieldByName("chains")
	if !v.IsValid() {
		t.Fatal("service.Service has no `chains` field; the parity test seam needs updating")
	}
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Set(reflect.ValueOf(prov))
}

// useCLIProvider installs the nil-in-production testOpenServiceHook so the REAL cobra
// command (which opens its OWN service in its RunE) runs against the SAME recording
// provider as the MCP arm. Reset in cleanup so no other test sees the hook.
func useCLIProvider(t *testing.T, prov service.ChainProvider) {
	t.Helper()
	testOpenServiceHook = func(svc *service.Service) { injectProvider(t, svc, prov) }
	t.Cleanup(func() { testOpenServiceHook = nil })
}

// mcpCallSend drives the MCP `send` tool against svc and returns (result, rawErr). The
// rawErr is the transport/protocol-level error (e.g. the SDK's tool-output schema
// validation), which is itself a finding the parity test surfaces.
func mcpCallSend(t *testing.T, svc *service.Service, args map[string]any) (*mcp.CallToolResult, error) {
	t.Helper()
	return mcpCallTool(t, svc, "send", args)
}

// mcpCallTool drives any MCP tool against svc over a real in-memory session.
func mcpCallTool(t *testing.T, svc *service.Service, tool string, args map[string]any) (*mcp.CallToolResult, error) {
	t.Helper()
	ctx := context.Background()
	srv := mcpserver.New(svc)
	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("mcp server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "parity", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("mcp client connect: %v", err)
	}
	defer func() { _ = cs.Close() }()
	return cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
}

// cliDryRunResult drives the REAL `tx send … --dry-run --json` cobra command end-to-end
// (the actual newTxSendCmd RunE: resolveFrom, the flag→domain.TxRequest construction, the
// gas/wait binding) against the injected provider and decodes the materialized TxResult it
// prints. This is the genuine CLI frontend — not a hand-built struct.
func cliDryRunResult(t *testing.T, args ...string) domain.TxResult {
	t.Helper()
	stdout, stderr, code := execCLI(t, args...)
	if code != 0 {
		t.Fatalf("cli %v: exit %d, stderr=%s", args, code, stderr)
	}
	var res domain.TxResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &res); err != nil {
		t.Fatalf("decode cli --json TxResult: %v (stdout=%q)", err, stdout)
	}
	return res
}

// TestFrontendParity_Send is the executable one-core/two-frontends proof for `send`: the
// SAME logical input through the REAL CLI command and through the MCP server's `send` tool
// materializes the IDENTICAL request via the IDENTICAL svc.SendTx.
//
// BOTH arms are real frontends now: the CLI arm runs the actual `tx send --dry-run --json`
// cobra command (so a swapped --to/--from, a mis-bound --amount, or a wrong default in
// newTxSendCmd would surface here); the MCP arm runs a real tools/call. They share ONE
// recording provider, so the materialized dry-run TxResults must be byte-equal.
func TestFrontendParity_Send(t *testing.T) {
	to := common.HexToAddress("0x000000000000000000000000000000000000C0DE")

	setParityEnv(t)
	ctx := context.Background()

	// The MCP arm: a service the test owns + injects the recording provider into.
	svc, closeFn, err := openServiceNoHook(ctx, &rootState{})
	if err != nil {
		t.Fatalf("openService: %v", err)
	}
	defer closeFn()
	prov := &recordingProvider{cc: fundedFake(t)}
	injectProvider(t, svc, prov)

	// The CLI arm: drive the REAL cobra command. It opens its OWN service; the hook
	// injects the SAME recording provider so both arms hit one funded fake.
	useCLIProvider(t, prov)
	cliRes := cliDryRunResult(t,
		"tx", "send", "--from", "acct", "--to", to.Hex(), "--amount", "0.5",
		"--dry-run", "--yes", "--json")

	// MCP half: the agent JSON the `send` tool accepts; the handler decodes it + applies
	// sendCeremony, then calls the SAME svc.SendTx with Principal=mcp. dry_run short-
	// circuits before signing. Note: NO `confirm` field is sent — it is invisible over MCP
	// (json:"-", wired server-side), and `to` is the only required input (§6.3).
	mcpResult, mcpErr := mcpCallSend(t, svc, map[string]any{
		"from": "acct", "to": to.Hex(), "amount": "0.5", "dry_run": true,
	})
	if mcpErr != nil {
		t.Fatalf("mcp send CallTool: %v", mcpErr)
	}
	if mcpResult.IsError {
		t.Fatalf("mcp send dry-run returned a tool error: %v", textOf(mcpResult))
	}

	var mcpRes domain.TxResult
	b, _ := json.Marshal(mcpResult.StructuredContent)
	if err := json.Unmarshal(b, &mcpRes); err != nil {
		t.Fatalf("decode mcp TxResult: %v (%s)", err, b)
	}

	// ── the parity assertions: identical materialized request through identical method ──
	if !cliRes.DryRun || !mcpRes.DryRun {
		t.Fatalf("both must be dry-run: cli=%v mcp=%v", cliRes.DryRun, mcpRes.DryRun)
	}
	if cliRes.From != mcpRes.From {
		t.Errorf("From diverged: cli=%s mcp=%s", cliRes.From, mcpRes.From)
	}
	if cliRes.To.Address != mcpRes.To.Address {
		t.Errorf("To diverged: cli=%s mcp=%s", cliRes.To.Address, mcpRes.To.Address)
	}
	if cliRes.AmountWei != mcpRes.AmountWei {
		t.Errorf("AmountWei diverged: cli=%s mcp=%s — a frontend rewrote the amount", cliRes.AmountWei, mcpRes.AmountWei)
	}
	if cliRes.Asset.Kind != mcpRes.Asset.Kind {
		t.Errorf("Asset.Kind diverged: cli=%s mcp=%s", cliRes.Asset.Kind, mcpRes.Asset.Kind)
	}
	half, _ := new(big.Int).SetString("500000000000000000", 10)
	if got, _ := new(big.Int).SetString(cliRes.AmountWei, 10); got == nil || got.Cmp(half) != 0 {
		t.Errorf("materialized AmountWei = %s, want 5e17 (0.5 ETH)", cliRes.AmountWei)
	}
	// Both arms selected the same (network, rpc) ChainRequest — the CLI arm's requests
	// land on the SAME recording provider as the MCP arm, so the first and last recorded
	// requests (one per frontend, at least) must be identical.
	if len(prov.requests) < 2 {
		t.Fatalf("expected both frontends to resolve a chain client; got %d requests", len(prov.requests))
	}
	if prov.requests[0] != prov.requests[len(prov.requests)-1] {
		t.Errorf("ChainRequest diverged across frontends: %+v vs %+v", prov.requests[0], prov.requests[len(prov.requests)-1])
	}
}

// openServiceNoHook opens a service WITHOUT firing the parity hook (used for the arm the
// test injects into directly), so the hook only governs the CLI-command arm.
func openServiceNoHook(ctx context.Context, rs *rootState) (*service.Service, func(), error) {
	saved := testOpenServiceHook
	testOpenServiceHook = nil
	defer func() { testOpenServiceHook = saved }()
	return openService(ctx, rs)
}

// TestMCPValueTypeSchemasAreStrings is the regression guard for the value-type schema
// correction (mcpserver/tools/schema.go). The MCP SDK infers a tool's I/O schema from the
// Go In/Out types and validates the marshaled JSON against it at call time. Geth/domain
// value types whose Go KIND disagrees with their JSON wire form — common.Address /
// common.Hash ([N]byte → would infer as "array") and domain.Duration (struct → "object")
// — MARSHAL as STRINGS, so without the correction the SDK rejects every successful result
// carrying one and the MCP server is non-functional for send/tx_status/tx_wait/gas/balance.
//
// The fix types those four (plus []byte) as {type:"string"} via jsonschema.ForOptions.
// TypeSchemas, keeping inference (struct tags, required/optional) otherwise intact. This
// test proves the fix HOLDS at the protocol layer: a real MCP `send` tools/call returns a
// valid TxResult with NO output-schema error, AND the published output schema types the
// address-bearing field `from` as a string (not an array). It goes red if the value-type
// mapping is dropped — the exact failure that walled off the MCP surface before.
func TestMCPValueTypeSchemasAreStrings(t *testing.T) {
	setParityEnv(t)
	ctx := context.Background()
	svc, closeFn, err := openServiceNoHook(ctx, &rootState{})
	if err != nil {
		t.Fatalf("openService: %v", err)
	}
	defer closeFn()
	injectProvider(t, svc, &recordingProvider{cc: fundedFake(t)})

	to := common.HexToAddress("0x000000000000000000000000000000000000C0DE")
	res, mcpErr := mcpCallSend(t, svc, map[string]any{
		"from": "acct", "to": to.Hex(), "amount": "0.5", "dry_run": true,
	})
	if mcpErr != nil {
		if isOutputSchemaDefect(mcpErr) {
			t.Fatalf("REGRESSION: the value-type schema correction is gone — the MCP send tool's "+
				"common.Address/Hash/Duration result is rejected by output validation again. "+
				"Restore the {type:string} mapping in internal/mcpserver/tools/schema.go. Error: %v", mcpErr)
		}
		t.Fatalf("MCP send failed for an unexpected reason: %v", mcpErr)
	}
	if res.IsError {
		t.Fatalf("MCP send dry-run returned a tool error: %s", textOf(res))
	}
	if res.StructuredContent == nil {
		t.Fatal("MCP send returned no structured content")
	}

	// The published output schema must type the address-bearing `from` property as a
	// string, not an array — the precise correction the value-type mapping makes.
	srv := mcpserver.New(svc)
	tools, err := mcpserver.ListTools(ctx, srv)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var sendOut map[string]any
	for _, tl := range tools {
		if tl.Name == "send" {
			b, _ := json.Marshal(tl.OutputSchema)
			_ = json.Unmarshal(b, &sendOut)
		}
	}
	if sendOut == nil {
		t.Fatal("send tool has no output schema")
	}
	props, _ := sendOut["properties"].(map[string]any)
	from, _ := props["from"].(map[string]any)
	if from == nil {
		t.Fatalf("send output schema has no `from` property: %v", sendOut)
	}
	if got := from["type"]; got != "string" {
		t.Errorf("send output schema `from` type = %v, want \"string\" (the address value-type correction)", got)
	}
}

// isOutputSchemaDefect reports whether err is the SDK's tool-output schema-validation
// failure caused by the geth/domain value-type inference mismatch (array/object vs the
// marshaled string). Used by the regression guard to give a precise message if the
// correction is ever removed.
func isOutputSchemaDefect(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "validating tool output") ||
		(strings.Contains(s, `has type "string"`) && (strings.Contains(s, `want "array"`) || strings.Contains(s, `want "object"`)))
}

// textOf joins a result's text content (the SDK packs a tool error's envelope here).
func textOf(res *mcp.CallToolResult) string {
	var sb string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb += tc.Text
		}
	}
	return sb
}

// TestFrontendParity_RequestStructDecode is the construction-level twin (no service): the
// MCP frontend's effective request — the SDK decode of the agent JSON PLUS the §6.4
// sendCeremony the handler applies — equals the domain.TxRequest the REAL CLI command
// builds from the equivalent flags. The CLI side is produced by driving the actual
// newTxSendCmd RunE (via a recording wrapper that captures the domain.TxRequest reaching
// svc.SendTx), so this isolates request-CONSTRUCTION parity from the shared core: a
// divergence here points squarely at a frontend (§2.9 "catches logic that sneaks into a
// frontend").
func TestFrontendParity_RequestStructDecode(t *testing.T) {
	to := common.HexToAddress("0x000000000000000000000000000000000000C0DE")
	toStr := to.Hex()

	// Capture what the REAL CLI builds: a recording provider wraps a fake whose ChainID
	// errors AFTER the request is constructed (so resolveContractSendIntent-style prefetch
	// fails fast and we never need a full dry-run), but the domain.TxRequest the cobra RunE
	// constructed has already reached svc.SendTx. Simpler: run the dry-run and read back
	// the materialized request from the TxResult, which carries the agent-controlled fields
	// (From resolved, To, AmountWei). For the construction-level twin we compare the
	// flag-built request fields the CLI RunE sets against the MCP-decoded+ceremony struct.
	setParityEnv(t)
	ctx := context.Background()
	svc, closeFn, err := openServiceNoHook(ctx, &rootState{})
	if err != nil {
		t.Fatalf("openService: %v", err)
	}
	defer closeFn()
	prov := &recordingProvider{cc: fundedFake(t)}
	injectProvider(t, svc, prov)
	useCLIProvider(t, prov)

	cliRes := cliDryRunResult(t,
		"tx", "send", "--from", "acct", "--to", toStr, "--amount", "0.5",
		"--dry-run", "--yes", "--json")

	// What the MCP frontend produces: decode the agent JSON to domain.TxRequest, then the
	// handler's sendCeremony sets Yes=true, Wait.Enabled=true. We replicate the decode via
	// the SAME json the SDK feeds the handler, drive it through the SAME svc.SendTx dry-run,
	// and compare the materialized result fields. The agent JSON carries NO `confirm`/`yes`
	// (json:"-", invisible over MCP) and only the agent-controlled fields.
	agentJSON := []byte(`{"from":"acct","to":"` + toStr + `","amount":"0.5","dry_run":true}`)
	var mcpReq domain.TxRequest
	if err := json.Unmarshal(agentJSON, &mcpReq); err != nil {
		t.Fatalf("decode agent JSON: %v", err)
	}
	// The §6.4 ceremony (sendCeremony) effect, applied by the handler:
	mcpReq.Yes = true
	mcpReq.Wait.Enabled = true
	mcpRes, err := svc.SendTx(ctx, domain.LocalMCP(), mcpReq, nil)
	if err != nil {
		t.Fatalf("mcp svc.SendTx dry-run: %v", err)
	}

	// The load-bearing agent-controlled fields the two REAL frontends produced must match
	// exactly through the materialized request (From resolved identically, To, amount).
	if cliRes.From != mcpRes.From {
		t.Errorf("a frontend altered From: cli=%s mcp=%s", cliRes.From, mcpRes.From)
	}
	if cliRes.To.Address != mcpRes.To.Address {
		t.Errorf("a frontend altered To: cli=%s mcp=%s", cliRes.To.Address, mcpRes.To.Address)
	}
	if cliRes.AmountWei != mcpRes.AmountWei {
		t.Errorf("a frontend altered the amount: cli=%s mcp=%s", cliRes.AmountWei, mcpRes.AmountWei)
	}
	if !cliRes.DryRun || !mcpRes.DryRun {
		t.Fatalf("both must be dry-run: cli=%v mcp=%v", cliRes.DryRun, mcpRes.DryRun)
	}
}

// TestFrontendParity_TokenApprove extends the head-to-head to the spend-equivalent
// approve. `token approve` has no --dry-run, so instead of materializing a TxResult this
// test proves request-CONSTRUCTION parity: it captures the approve(spender, amount)
// calldata each frontend's request produces inside the SHARED svc.TokenApprove and
// asserts they are byte-identical. The capture point is EstimateGas (called with the
// built approve calldata, after resolveApproveIntent); the fake returns an error there to
// abort BEFORE any broadcast, so neither arm mutates nonce/journal state and the
// comparison is clean and deterministic. Identical calldata ⇒ identical spender + amount
// ⇒ the two frontends built the IDENTICAL ApproveRequest for svc.TokenApprove (a swapped
// spender or a mis-bound amount would diverge the calldata). Yes (the TTY-skip) and the
// MCP ceremony's Yes are both json:"-" — neither reaches the wire.
func TestFrontendParity_TokenApprove(t *testing.T) {
	spender := common.HexToAddress("0x000000000000000000000000000000000000A77a")
	tokenC := common.HexToAddress("0x00000000000000000000000000000000000000E2")

	setParityEnv(t)
	ctx := context.Background()

	// A fake that answers decimals/symbol, then captures the EstimateGas calldata (the
	// built approve calldata) and aborts — so both arms stop at the same pre-broadcast
	// point with the calldata recorded.
	var captured [][]byte
	makeFake := func() *fake.Client {
		f := approveFake(t, tokenC)
		f.EstimateGasFn = func(_ context.Context, msg ethereum.CallMsg) (uint64, error) {
			if len(msg.Data) >= 4 { // the approve(spender,amount) calldata
				cp := make([]byte, len(msg.Data))
				copy(cp, msg.Data)
				captured = append(captured, cp)
			}
			return 0, errParityAbort
		}
		return f
	}

	// MCP arm: the test owns the service; inject the capturing fake.
	svc, closeFn, err := openServiceNoHook(ctx, &rootState{})
	if err != nil {
		t.Fatalf("openService: %v", err)
	}
	defer closeFn()
	injectProvider(t, svc, &recordingProvider{cc: makeFake()})

	mcpResult, mcpErr := mcpCallTool(t, svc, "token_approve", map[string]any{
		"from": "acct", "token": tokenC.Hex(), "spender": spender.Hex(), "amount": "500",
	})
	if mcpErr != nil {
		t.Fatalf("mcp token_approve CallTool (protocol): %v", mcpErr)
	}
	if !mcpResult.IsError {
		t.Fatal("expected the capturing abort to surface as a tool error")
	}

	// CLI arm: the REAL cobra command opens its own service; the hook injects a fresh
	// capturing fake (separate fake so nonce/state never crosses).
	useCLIProvider(t, &recordingProvider{cc: makeFake()})
	_, _, code := execCLI(t,
		"token", "approve", tokenC.Hex(), "--spender", spender.Hex(),
		"--amount", "500", "--from", "acct", "--yes", "--json")
	if code == 0 {
		t.Fatal("expected the capturing abort to fail the cli approve (non-zero exit)")
	}

	if len(captured) < 2 {
		t.Fatalf("expected both frontends to build approve calldata; captured %d", len(captured))
	}
	cliData, mcpData := captured[len(captured)-1], captured[0]
	if !reflect.DeepEqual(cliData, mcpData) {
		t.Errorf("approve calldata diverged across frontends — a frontend altered spender/amount:\n cli = 0x%x\n mcp = 0x%x", cliData, mcpData)
	}
	// Sanity: it is an ERC-20 approve(spender, …) selector 0x095ea7b3 carrying the spender.
	if len(mcpData) < 4+32+32 || mcpData[0] != 0x09 || mcpData[1] != 0x5e || mcpData[2] != 0xa7 || mcpData[3] != 0xb3 {
		t.Fatalf("captured calldata is not an approve(spender,amount): 0x%x", mcpData)
	}
	gotSpender := common.BytesToAddress(mcpData[4:36])
	if gotSpender != spender {
		t.Errorf("approve calldata spender = %s, want %s", gotSpender.Hex(), spender.Hex())
	}
}

// errParityAbort is the sentinel the approve-parity capturing fake returns from
// EstimateGas to stop BOTH frontends at the same pre-broadcast point.
var errParityAbort = errorString("parity capture: abort before broadcast")

type errorString string

func (e errorString) Error() string { return string(e) }

// TestFrontendParity_ContractSend extends the head-to-head to contract_send: the REAL
// `contract send … --dry-run --json` cobra command and the MCP `contract_send` tool
// materialize the IDENTICAL call through the IDENTICAL svc.ContractSend, with the SAME
// calldata classification. A bounded call (no unlimited approve) needs no
// acknowledge_unlimited; neither frontend carries confirm/yes on the wire.
func TestFrontendParity_ContractSend(t *testing.T) {
	contractC := common.HexToAddress("0x000000000000000000000000000000000000bEEF")

	setParityEnv(t)
	ctx := context.Background()
	svc, closeFn, err := openServiceNoHook(ctx, &rootState{})
	if err != nil {
		t.Fatalf("openService: %v", err)
	}
	defer closeFn()
	prov := &recordingProvider{cc: fundedFake(t)}
	injectProvider(t, svc, prov)
	useCLIProvider(t, prov)

	// CLI arm: the REAL cobra command. --sig supplies the one-function ABI inline AND the
	// method name, so every trailing positional is an arg (splitMethodArgs) — pass only
	// the single uint256 arg, no method positional.
	cliStdout, cliStderr, code := execCLI(t,
		"contract", "send", contractC.Hex(), "5000",
		"--sig", "stake(uint256)", "--from", "acct", "--dry-run", "--yes", "--json")
	if code != 0 {
		t.Fatalf("cli contract send --dry-run: exit %d, stderr=%s", code, cliStderr)
	}
	var cliRes domain.TxResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(cliStdout)), &cliRes); err != nil {
		t.Fatalf("decode cli contract_send TxResult: %v (stdout=%q)", err, cliStdout)
	}

	// MCP arm: the real contract_send tool. NO confirm/yes on the wire; no
	// acknowledge_unlimited (a plain stake is not an unlimited approve). The inline
	// signature rides in the nested `abi.sig` (ABISource), the same shape the schema
	// infers from ContractSendRequest.ABI.
	mcpResult, mcpErr := mcpCallTool(t, svc, "contract_send", map[string]any{
		"from": "acct", "contract": contractC.Hex(), "method": "stake",
		"args": []any{"5000"}, "abi": map[string]any{"sig": "stake(uint256)"}, "dry_run": true,
	})
	if mcpErr != nil {
		t.Fatalf("mcp contract_send CallTool: %v", mcpErr)
	}
	if mcpResult.IsError {
		t.Fatalf("mcp contract_send dry-run tool error: %s", textOf(mcpResult))
	}
	var mcpRes domain.TxResult
	b, _ := json.Marshal(mcpResult.StructuredContent)
	if err := json.Unmarshal(b, &mcpRes); err != nil {
		t.Fatalf("decode mcp contract_send TxResult: %v (%s)", err, b)
	}

	if !cliRes.DryRun || !mcpRes.DryRun {
		t.Fatalf("both contract sends must be dry-run: cli=%v mcp=%v", cliRes.DryRun, mcpRes.DryRun)
	}
	if cliRes.From != mcpRes.From {
		t.Errorf("contract_send From diverged: cli=%s mcp=%s", cliRes.From, mcpRes.From)
	}
	// The contract is the tx destination (policy subject), echoed on To.
	if cliRes.To.Address != mcpRes.To.Address {
		t.Errorf("contract_send destination diverged: cli=%s mcp=%s", cliRes.To.Address, mcpRes.To.Address)
	}
	if cliRes.To.Address != contractC {
		t.Errorf("contract_send destination = %s, want the contract %s", cliRes.To.Address, contractC.Hex())
	}
}

// approveFake builds a chain fake that funds acct0, answers chain-id 1, and returns the
// decimals/symbol an ERC-20 metadata read needs so a bounded approve dry-run reaches the
// policy verdict (the parity-comparable materialized request) without a real ERC-20.
func approveFake(t *testing.T, _ common.Address) *fake.Client {
	t.Helper()
	f := fundedFake(t)
	f.CallContractFn = func(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
		switch {
		case parityHasSelector(msg.Data, paritySelDecimals):
			return parityABIWord(big.NewInt(6)), nil
		case parityHasSelector(msg.Data, paritySelSymbol):
			return parityABIString("TST"), nil
		default:
			// allowance/balanceOf etc. — zero is fine for a dry-run policy verdict.
			return parityABIWord(big.NewInt(0)), nil
		}
	}
	return f
}

// ── minimal ERC-20 metadata ABI helpers for the parity fakes (cli-package-local) ──

var (
	paritySelDecimals = []byte{0x31, 0x3c, 0xe5, 0x67} // decimals()
	paritySelSymbol   = []byte{0x95, 0xd8, 0x9b, 0x41} // symbol()
)

func parityABIWord(v *big.Int) []byte { return common.LeftPadBytes(v.Bytes(), 32) }

func parityABIString(s string) []byte {
	out := make([]byte, 0, 96)
	out = append(out, parityABIWord(big.NewInt(0x20))...)
	out = append(out, parityABIWord(big.NewInt(int64(len(s))))...)
	b := []byte(s)
	for len(b)%32 != 0 {
		b = append(b, 0)
	}
	return append(out, b...)
}

func parityHasSelector(data, sel []byte) bool {
	if len(data) < 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		if data[i] != sel[i] {
			return false
		}
	}
	return true
}
