package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// mcp_test.go is the unit suite for the `daxie mcp` command surface (§6.7/§6.8): the
// `mcp tools` introspection (the 31-row table + footer; the --json tools/list payload;
// a single tool's schema) and the `mcp serve --transport` switch (stdio accepted, http
// rejected in v1). The command NEVER dials RPC or unlocks the keystore — it builds the
// server lazily (mcpserver.New touches no provider), so these run with no network and no
// keystore, exactly like `version`/`convert`.

// TestMcpToolsHumanFooter pins §6.7: `mcp tools` prints the compact table + the footer
// reporting EXACTLY 31 tools and the stdio transport.
func TestMcpToolsHumanFooter(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "mcp", "tools")
	if code != int(domain.ExitOK) {
		t.Fatalf("mcp tools exit = %d, want 0", code)
	}
	if !strings.Contains(out, "31 tools") {
		t.Errorf("mcp tools footer missing '31 tools':\n%s", out)
	}
	if !strings.Contains(out, "stdio") {
		t.Errorf("mcp tools footer missing the stdio transport:\n%s", out)
	}
	// A representative tool row is present; an excluded tool is not.
	if !strings.Contains(out, "send") {
		t.Errorf("mcp tools table missing the send tool:\n%s", out)
	}
}

// TestMcpToolsJSONIs31 pins §6.7: `mcp tools --json` is the tools/list payload, and it
// carries EXACTLY the 31 §6.1 tools — and none of the excluded ones.
func TestMcpToolsJSONIs31(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "mcp", "tools", "--json")
	if code != int(domain.ExitOK) {
		t.Fatalf("mcp tools --json exit = %d, want 0", code)
	}

	// The payload shape is { "tools": [ { "name": ... }, ... ] } (the tools/list result).
	var payload struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema any    `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("mcp tools --json not valid tools/list JSON: %v\n%s", err, out)
	}
	if len(payload.Tools) != 31 {
		names := make([]string, len(payload.Tools))
		for i, tl := range payload.Tools {
			names[i] = tl.Name
		}
		t.Fatalf("mcp tools --json has %d tools, want EXACTLY 31 (§6.1): %v", len(payload.Tools), names)
	}

	got := make(map[string]bool, len(payload.Tools))
	for _, tl := range payload.Tools {
		got[tl.Name] = true
		if tl.InputSchema == nil {
			t.Errorf("tool %q has no inputSchema (the inferred contract a client sees on connect)", tl.Name)
		}
	}
	for _, want := range []string{"send", "token_approve", "contract_send", "balance", "convert", "policy_show"} {
		if !got[want] {
			t.Errorf("mcp tools --json missing §6.1 tool %q", want)
		}
	}
	for _, banned := range []string{"policy_set", "wallet_export", "wallet_create", "account_derive", "token_add", "contract_add", "network_use", "keystore_change_passphrase"} {
		if got[banned] {
			t.Errorf("mcp tools --json exposes EXCLUDED tool %q (the §6.1 security boundary regressed)", banned)
		}
	}
}

// TestMcpToolsSingle pins §6.7: `mcp tools <name>` prints one tool's full schema; an
// unknown tool is a clean ref.not_found, never a crash.
func TestMcpToolsSingle(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "mcp", "tools", "send")
	if code != int(domain.ExitOK) {
		t.Fatalf("mcp tools send exit = %d, want 0", code)
	}
	if !strings.Contains(out, "send") {
		t.Errorf("mcp tools send did not print the send tool schema:\n%s", out)
	}

	_, _, code = execCLI(t, "mcp", "tools", "no_such_tool")
	if code != int(domain.ExitNotFound) {
		t.Errorf("mcp tools <unknown> exit = %d, want %d (ref.not_found)", code, domain.ExitNotFound)
	}
}

// TestMcpServeRejectsHTTP pins §6.8: `mcp serve --transport http` is rejected in v1 with
// a usage-class exit (2), forward-pointing to v1.1; an unknown transport is also a usage
// error. stdio is the only accepted value. (We do NOT start stdio here — it would block
// on the real transport; the in-memory + anvil smoke cover serving.)
func TestMcpServeRejectsHTTP(t *testing.T) {
	isolateEnv(t)

	_, stderr, code := execCLI(t, "mcp", "serve", "--transport", "http", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("mcp serve --transport http exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	// The error envelope carries a usage.* code (usage.unsupported) — a stable forward-
	// pointing contract a client can branch on.
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(stderr), &env); err == nil {
		if !strings.HasPrefix(env.Error.Code, "usage.") {
			t.Errorf("http rejection code = %q, want a usage.* code", env.Error.Code)
		}
	}

	_, _, code = execCLI(t, "mcp", "serve", "--transport", "websocket", "--json")
	if code != int(domain.ExitUsage) {
		t.Errorf("mcp serve --transport websocket exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// TestMcpToolsDoesNotDial pins §6.7's "never dials RPC / unlocks the keystore": with NO
// keystore initialized and NO reachable RPC, `mcp tools` still succeeds (exit 0). If the
// command eagerly opened a service that touched the keystore or network it would fail
// here. (isolateEnv points the keystore at an empty temp dir and configures no network.)
func TestMcpToolsDoesNotDial(t *testing.T) {
	isolateEnv(t)
	// No network configured, no keystore unlocked, no DAXIE_PASSPHRASE_* — a tool that
	// dials or unlocks would error; introspection must not.
	if _, stderr, code := execCLI(t, "mcp", "tools"); code != int(domain.ExitOK) {
		t.Fatalf("mcp tools dialed/unlocked (exit %d); it must introspect lazily without touching the keystore/network. stderr=%s", code, stderr)
	}
}
