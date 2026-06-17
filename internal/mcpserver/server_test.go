package mcpserver

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// server_test.go is the §6.1/§6.6/§6.8 unit suite for the transport-agnostic Server:
//   - New registers EXACTLY the 31 §6.1 tools (count + name set), and the deliberately-
//     excluded set is genuinely ABSENT (the non-regressable security boundary — a
//     prompt-injected agent cannot raise its own limits, exfiltrate a key, or redefine
//     an alias because no such tool exists, §6.1).
//   - the §6.6 error model maps the one domain.Error taxonomy onto the MCP tool-error
//     mechanism (toolError pass-through; dualSignal flags the tx.* cases needing BOTH
//     IsError and structured Out).
//   - the §6.8 transport switch accepts stdio only in v1; http is rejected with a
//     forward-pointing domain.Error, and an unknown transport is a usage error.

// wantTools is the EXACT 31-tool surface from the §6.1 table (the frozen contract the
// golden + this test pin). Order-independent: compared as a set.
var wantTools = []string{
	"balance", "token_list", "token_info", "nft_list", "send",
	"tx_status", "tx_wait", "tx_list", "tx_speedup", "tx_cancel",
	"receive", "token_approve", "token_revoke", "token_allowance",
	"sign_message", "sign_typed_data", "verify",
	"wallet_list", "wallet_show", "accounts_list", "account_show",
	"gas", "convert", "ens_resolve", "ens_reverse", "policy_show",
	"contract_call", "contract_logs", "contract_encode", "contract_decode", "contract_send",
}

// excludedTools is a representative denylist of the §6.1 "Deliberately NOT tools" set.
// If ANY of these is ever registered, the security boundary regressed: policy mutation
// (raise own limits), key export/import/create (exfiltrate/plant a key), derive/alias/
// use (redefine an alias), keystore change-passphrase, network/rpc mutation, *_add
// registry mutation (alias/ABI spoofing). These MUST never be reachable over MCP in v1.
var excludedTools = []string{
	// policy mutations (admin-passphrase-gated; the agent never holds it)
	"policy_set", "policy_allow", "policy_deny", "policy_reset",
	"policy_change_admin_passphrase", "policy_typed_allow", "policy_typed_remove",
	"policy_contract_allow", "policy_contract_remove",
	// key export — no exfiltration through the tool channel, ever, in v1
	"wallet_export", "account_export",
	// key/wallet create & import — secret-emitting / attacker-key-planting
	"wallet_create", "wallet_import", "account_import",
	// account pointer/index mutations
	"account_derive", "account_alias", "account_unalias", "account_use",
	// keystore admin
	"keystore_change_passphrase",
	// network/rpc mutations (incl. the rpc test debugging affordance)
	"network_add", "network_use", "network_remove", "rpc_add", "rpc_remove", "rpc_test",
	// destructive registry/keystore ops
	"wallet_delete", "account_delete", "token_remove", "nft_remove", "contacts_remove",
	// the alias/ABI spoofing primitives
	"token_add", "nft_add", "contacts_add", "contract_add", "contract_remove",
	// registry introspection deferred to v1.1
	"contract_list", "contract_show",
	// self-referential / shell-only
	"mcp_serve", "mcp_tools", "version", "completion", "config",
}

// registeredToolNames lists every tool the server registers, via an in-memory client.
func registeredToolNames(t *testing.T) []string {
	t.Helper()
	ctx := context.Background()
	srv := New(nil) // schema/registration is type-driven; no service dialed

	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "server-test", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	sort.Strings(names)
	return names
}

func TestNewRegistersExactly31Tools(t *testing.T) {
	got := registeredToolNames(t)
	if len(got) != 31 {
		t.Fatalf("registered %d tools, want EXACTLY 31 (§6.1): %v", len(got), got)
	}

	gotSet := make(map[string]bool, len(got))
	for _, n := range got {
		gotSet[n] = true
	}
	for _, want := range wantTools {
		if !gotSet[want] {
			t.Errorf("missing §6.1 tool %q (registered: %v)", want, got)
		}
	}
	// And nothing EXTRA beyond the 31 canonical names (catches a 32nd tool, e.g. an
	// accidental nft_send — D5 — or any unplanned addition).
	wantSet := make(map[string]bool, len(wantTools))
	for _, n := range wantTools {
		wantSet[n] = true
	}
	for _, n := range got {
		if !wantSet[n] {
			t.Errorf("UNEXPECTED tool %q registered; the surface is frozen at the 31 §6.1 tools", n)
		}
	}
}

// TestExcludedToolsAreAbsent is the recorded, non-regressable security boundary (§6.1):
// no policy mutation, key export/import/create, derive/alias/use, keystore change-
// passphrase, network/rpc mutation, or *_add registry mutation is reachable over MCP.
func TestExcludedToolsAreAbsent(t *testing.T) {
	got := registeredToolNames(t)
	gotSet := make(map[string]bool, len(got))
	for _, n := range got {
		gotSet[n] = true
	}
	for _, banned := range excludedTools {
		if gotSet[banned] {
			t.Errorf("SECURITY BOUNDARY VIOLATION: excluded tool %q is registered; the MCP surface must NOT expose it (§6.1 — a prompt-injected agent must not raise its own limits, exfiltrate a key, or redefine an alias through the tool channel)", banned)
		}
	}
	// policy_show (read-only) IS on the surface — assert it stayed reachable.
	if !gotSet["policy_show"] {
		t.Error("policy_show (read-only) must be exposed (§6.1)")
	}
}

// TestServeRejectsHTTP pins the §6.8 v1 transport contract: stdio is the only accepted
// transport; http is rejected with a forward-pointing usage.unsupported domain.Error
// (so v1.1 flips it on with a new file + enum value, not a refactor); an unknown
// transport is a usage error. (stdio is not exercised here — it would block on the
// real transport; the in-memory pipe + the anvil smoke cover the serving path.)
func TestServeRejectsHTTP(t *testing.T) {
	srv := New(nil)

	err := Serve(context.Background(), srv, "http")
	if err == nil {
		t.Fatal("Serve(..., \"http\") returned nil; v1 must REJECT the http transport (§6.8)")
	}
	de := domain.AsError(err)
	if de.Code != domain.CodeUsageUnsupported {
		t.Errorf("http transport rejection code = %q, want %q (forward-pointing to v1.1)", de.Code, domain.CodeUsageUnsupported)
	}

	err = Serve(context.Background(), srv, "carrier-pigeon")
	if err == nil {
		t.Fatal("Serve(..., unknown) returned nil; an unknown transport must be a usage error")
	}
	if code := domain.AsError(err).Code; !strings.HasPrefix(code, "usage.") {
		// usage.invalid (unknown value) or usage.unsupported (reserved http) are both
		// acceptable; what matters is it is a usage-class refusal, not a panic/nil.
		t.Errorf("unknown transport rejection code = %q, want a usage.* code", code)
	}
}

// TestServeHTTPSeamRefuses pins the reserved v1.1 ServeHTTP seam (§6.8/§2.10): the
// signature exists so the auth hook + HTTP handler have a home in v1.1, but the v1 body
// REFUSES (no net/http server is started). This guards that the seam is declared and
// inert, not accidentally wired.
func TestServeHTTPSeamRefuses(t *testing.T) {
	srv := New(nil)
	err := ServeHTTP(context.Background(), srv, HTTPOptions{Addr: "127.0.0.1:0"})
	if err == nil {
		t.Fatal("ServeHTTP returned nil in v1; the HTTP transport ships in v1.1 and must refuse now (§6.8)")
	}
	if code := domain.AsError(err).Code; code != domain.CodeUsageUnsupported {
		t.Errorf("ServeHTTP refusal code = %q, want %q", code, domain.CodeUsageUnsupported)
	}
}

// TestToolErrorPassThrough pins §6.6: toolError passes a *domain.Error straight through
// (so domain.Error.Error() — the JSON envelope byte-identical to the CLI --json error —
// is what the SDK packs into the tool-error TextContent), and returns nil on success.
func TestToolErrorPassThrough(t *testing.T) {
	if got := toolError(nil); got != nil {
		t.Errorf("toolError(nil) = %v, want nil (success path)", got)
	}

	in := domain.New("policy.denied.allowlist", "spender not allowlisted")
	got := toolError(in)
	if got == nil {
		t.Fatal("toolError(domain.Error) = nil, want the error passed through")
	}
	de := domain.AsError(got)
	if de.Code != "policy.denied.allowlist" {
		t.Errorf("code = %q, want policy.denied.allowlist (passed through unchanged)", de.Code)
	}
	// A raw (non-domain) error becomes a generic internal domain.Error.
	rawWrapped := domain.AsError(toolError(errors.New("boom")))
	if rawWrapped.Code != domain.CodeInternal {
		t.Errorf("raw error code = %q, want %q", rawWrapped.Code, domain.CodeInternal)
	}
}

// TestDualSignalCodes pins §6.6: only the three tx.* outcomes that need BOTH IsError
// AND a structured *domain.TxResult are dual-signal — tx.reverted, tx.wait_timeout,
// tx.nonce_gap. A plain policy denial is NOT dual-signal (it returns a plain
// tool-error), and nil is never dual-signal.
func TestDualSignalCodes(t *testing.T) {
	for _, code := range []string{domain.CodeTxReverted, domain.CodeTxWaitTimeout, domain.CodeTxNonceGap} {
		if !dualSignal(domain.New(code, "x")) {
			t.Errorf("dualSignal(%q) = false, want true (needs IsError + structured Out)", code)
		}
	}
	for _, code := range []string{"policy.denied.allowlist", "ref.not_found", "usage.invalid"} {
		if dualSignal(domain.New(code, "x")) {
			t.Errorf("dualSignal(%q) = true, want false (a plain tool-error, not dual-signal)", code)
		}
	}
	if dualSignal(nil) {
		t.Error("dualSignal(nil) = true, want false")
	}
}
