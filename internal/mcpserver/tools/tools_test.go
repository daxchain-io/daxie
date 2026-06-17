package tools

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// tools_test.go pins the §6.2 schema-inference contract from the tools package itself:
// every tool's INPUT schema is inferred from a domain request struct, so the schema
// validates exactly the JSON the CLI marshals from the SAME struct (J5 — CLI/MCP drift
// is structurally impossible). It drives Register directly (the A↔B coordination
// contract: Register(srv, svc)) so the tools package is exercised in isolation.
//
// No live service is dialed: tools/list and schema resolution are purely type-driven,
// and we validate at the SCHEMA level (resolve + Validate the inferred schema against a
// marshaled domain struct) rather than invoking a handler — so a nil service is fine
// and the test stays a fast, network-free unit.

// buildToolSchemas registers all tools onto a fresh server, lists them via an in-memory
// client, and returns name → inferred input schema (as the client receives it).
func buildToolSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	ctx := context.Background()

	srv := mcp.NewServer(&mcp.Implementation{Name: "tools-test", Version: "0.0.0"}, nil)
	Register(srv, nil) // type-driven registration; no handler runs during tools/list

	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "tools-test-client", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	out := make(map[string]*jsonschema.Schema, len(res.Tools))
	for _, tl := range res.Tools {
		// The client receives InputSchema as the default JSON marshaling of the
		// server's inferred schema; re-decode it into a *jsonschema.Schema we can
		// resolve + validate (the same library the SDK uses for inference/validation).
		raw, err := json.Marshal(tl.InputSchema)
		if err != nil {
			t.Fatalf("%s: marshal input schema: %v", tl.Name, err)
		}
		var sch jsonschema.Schema
		if err := json.Unmarshal(raw, &sch); err != nil {
			t.Fatalf("%s: input schema is not a JSON schema: %v", tl.Name, err)
		}
		out[tl.Name] = &sch
	}
	return out
}

// validateAgainst resolves the named tool's input schema and validates the JSON that
// marshaling the given populated domain request struct produces — proving the inferred
// schema accepts exactly the CLI's wire shape for that struct (§6.2/§2.9).
func validateAgainst(t *testing.T, schemas map[string]*jsonschema.Schema, tool string, req any) {
	t.Helper()
	sch, ok := schemas[tool]
	if !ok {
		t.Fatalf("tool %q not registered", tool)
	}
	resolved, err := sch.Resolve(nil)
	if err != nil {
		t.Fatalf("%s: resolve schema: %v", tool, err)
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("%s: marshal request: %v", tool, err)
	}
	var instance any
	if err := json.Unmarshal(b, &instance); err != nil {
		t.Fatalf("%s: unmarshal request: %v", tool, err)
	}
	if err := resolved.Validate(instance); err != nil {
		t.Errorf("%s: the inferred input schema REJECTED the JSON the CLI marshals from %T:\n  json: %s\n  err: %v\nThis means the MCP schema drifted from the domain struct the CLI binds (§6.2).", tool, req, b, err)
	}
}

// TestInputSchemasAcceptCLIWire is the schema↔marshaling contract for the parity-
// critical tools: a populated domain request struct (exactly what the CLI builds from
// flags) marshals to JSON the inferred MCP input schema accepts. Covers a write tool
// (send/TxRequest), the spend-equivalent approve (token_approve/ApproveRequest with the
// acknowledge_unlimited ack), the arbitrary-call signer (contract_send/
// ContractSendRequest with acknowledge_unlimited), and reads (balance, convert,
// contract_call).
//
// The confirmation flag (TxRequest.Yes / ApproveRequest.Yes / …) carries json:"-", so
// the marshaled JSON never carries it and the schema never declares it — exactly the
// design contract (§6.2). The unlimited ack is the schema-visible acknowledge_unlimited.
//
// The `wait` field is validated in full: the value-type schema correction
// (mcpserver/tools/schema.go) types domain.Duration as the string it marshals to, so the
// wait-bearing tools' `wait.timeout` schema matches the CLI's wire form. The struct is
// validated end-to-end (no field excluded) — a Duration regression would be caught here.
func TestInputSchemasAcceptCLIWire(t *testing.T) {
	schemas := buildToolSchemas(t)

	nonce := uint64(7)
	// Wait-bearing write tools: validate every field INCLUDING the `wait` Duration, which
	// the value-type correction now types as a string matching the CLI wire form. Yes is
	// json:"-" (never marshaled), so it neither appears in the JSON nor needs the schema.
	validateAgainst(t, schemas, "send", domain.TxRequest{
		From: "treasury/0", To: "0x000000000000000000000000000000000000C0DE",
		Amount: "0.5", Network: "sepolia", Yes: true, Nonce: &nonce,
		Wait: domain.WaitOpts{Enabled: true, Timeout: domain.Duration{D: 5 * time.Minute}},
	})
	validateAgainst(t, schemas, "token_approve", domain.ApproveRequest{
		Token: "usdc", Spender: "0x000000000000000000000000000000000000A77a",
		Amount: "500", Yes: true,
		Wait: domain.WaitOpts{Enabled: true, Timeout: domain.Duration{D: 90 * time.Second}},
	})
	// An UNLIMITED approve carrying the acknowledge_unlimited ack must validate (the agent
	// says the dangerous thing out loud through the schema field, §6.3/§6.4).
	validateAgainst(t, schemas, "token_approve", domain.ApproveRequest{
		Token: "usdc", Spender: "0x000000000000000000000000000000000000A77a",
		Unlimited: true, AckUnlimited: true, Yes: true,
		Wait: domain.WaitOpts{Enabled: true},
	})
	validateAgainst(t, schemas, "token_revoke", domain.ApproveRequest{
		Token: "usdc", Spender: "0x000000000000000000000000000000000000A77a", Yes: true,
		Wait: domain.WaitOpts{Enabled: true},
	})
	validateAgainst(t, schemas, "contract_send", domain.ContractSendRequest{
		Contract: "0x000000000000000000000000000000000000bEEF", Method: "stake",
		Args: []string{"5000"}, Value: "0", Yes: true, AckUnlimited: false,
		Wait: domain.WaitOpts{Enabled: true, Timeout: domain.Duration{D: 10 * time.Minute}},
	})
	// The minimal `send` an agent should be able to call: ONLY `to` (from/amount optional,
	// §6.3). A schema that required from/amount/confirm would reject this (the bug fixed).
	validateAgainst(t, schemas, "send", domain.TxRequest{To: "vitalik.eth"})

	// Pure/read tools have no Duration field — validate the full struct.
	validateAgainst(t, schemas, "balance", domain.BalanceRequest{Account: "treasury/0", Network: "sepolia"})
	validateAgainst(t, schemas, "convert", domain.ConvertRequest{Amount: "1eth", To: "gwei"})
	validateAgainst(t, schemas, "contract_call", domain.ContractCallRequest{Contract: "0x000000000000000000000000000000000000bEEF", Method: "earned"})
}

// TestWaitTimeoutSchemaIsString is the regression guard for the domain.Duration schema:
// Duration is a struct {D time.Duration} whose MarshalJSON emits a STRING ("5m", "0s"),
// and whose UnmarshalJSON parses a string — so the wire form an agent must send is a
// string. The MCP SDK's bare inference would type it as an OBJECT (from the Go struct,
// honoring neither json.Marshaler nor a struct tag), which would make `wait.timeout`
// uncallable. The value-type correction (mcpserver/tools/schema.go) maps domain.Duration
// to {type:"string"}, so a wait-bearing tool's `wait.timeout` schema now MATCHES the wire.
// This test pins that: send.wait.timeout must be a string. It goes red if the Duration
// mapping is dropped (the schema would revert to object and reject the CLI's wire form).
func TestWaitTimeoutSchemaIsString(t *testing.T) {
	schemas := buildToolSchemas(t)
	send := schemas["send"]
	wait := send.Properties["wait"]
	if wait == nil {
		t.Fatal("send has no `wait` property; the schema shape changed unexpectedly")
	}
	timeout := wait.Properties["timeout"]
	if timeout == nil {
		t.Fatal("wait has no `timeout` property; the schema shape changed unexpectedly")
	}
	if timeout.Type != "string" {
		t.Errorf("wait.timeout schema type = %q, want \"string\" — the domain.Duration value-type "+
			"correction in internal/mcpserver/tools/schema.go is missing or broken; the schema no longer "+
			"matches the Go duration string the CLI/struct marshal.", timeout.Type)
	}
}

// TestEverySchemaResolves is a smoke check that EVERY registered tool's inferred input
// schema is a valid, resolvable JSON schema (so the SDK can validate calls and
// `daxie mcp tools` can render it). A struct that produces an un-resolvable schema
// (e.g. a cyclic $ref or an unsupported construct) fails here.
func TestEverySchemaResolves(t *testing.T) {
	schemas := buildToolSchemas(t)
	if len(schemas) != 31 {
		t.Fatalf("Register produced %d tool schemas, want 31 (§6.1)", len(schemas))
	}
	for name, sch := range schemas {
		if _, err := sch.Resolve(nil); err != nil {
			t.Errorf("tool %q: inferred input schema does not resolve: %v", name, err)
		}
	}
}

// signingToolSet is the §6.1/§6.7 8-signing-tool set, named here so the schema-shape
// assertions below cover EVERY tool that can move funds / sign.
var signingToolSet = []string{
	"send", "tx_speedup", "tx_cancel",
	"token_approve", "token_revoke",
	"sign_message", "sign_typed_data",
	"contract_send",
}

// TestConfirmFieldNeverOnSchema pins the §6.2/§6.4 contract that the confirmation flag is
// INVISIBLE over MCP: "TxRequest.Yes carries json:\"-\", so the SDK never infers it into
// the schema (it is a CLI-interaction flag; Confirm is wired constant-true over MCP)". No
// signing tool's input schema may carry a `confirm` (or `yes`) property — the interactive
// y/N is wired server-side by the write ceremony, never asked of the agent. (Regression
// guard for the bug where `confirm` was exposed AND marked required, forcing agents to
// pass a field the server overwrites.)
func TestConfirmFieldNeverOnSchema(t *testing.T) {
	schemas := buildToolSchemas(t)
	for _, tool := range signingToolSet {
		sch := schemas[tool]
		if sch == nil {
			t.Fatalf("tool %q not registered", tool)
		}
		for _, leaked := range []string{"confirm", "yes"} {
			if _, ok := sch.Properties[leaked]; ok {
				t.Errorf("%s: schema exposes %q — the confirmation flag is a CLI-interaction concern (json:\"-\") and must NEVER reach the MCP surface (§6.2/§6.4)", tool, leaked)
			}
			for _, r := range sch.Required {
				if r == leaked {
					t.Errorf("%s: schema marks %q REQUIRED — an agent must not be forced to pass a server-overwritten confirmation flag (§6.2/§6.4)", tool, leaked)
				}
			}
		}
	}
}

// TestSendRequiresOnlyTo pins §6.3: the `send` tool's required set is EXACTLY ["to"]
// — from is optional ("Omit to use the default account"), amount is optional ("Plain
// ERC-721: omit"), and confirm is not a field at all. (Regression guard for the bug
// where send required [from, to, amount, confirm].)
func TestSendRequiresOnlyTo(t *testing.T) {
	schemas := buildToolSchemas(t)
	sch := schemas["send"]
	if sch == nil {
		t.Fatal("send tool not registered")
	}
	if len(sch.Required) != 1 || sch.Required[0] != "to" {
		t.Errorf("send required set = %v, want exactly [\"to\"] (§6.3)", sch.Required)
	}
}

// TestNetworkRPCNeverRequired pins §6.2 ("network/rpc selection is optional (empty =
// config defaults)"): NO tool may mark `network` or `rpc` required. This is the
// regression guard for the sign/verify structs that — lacking json tags — inferred
// Go-cased, all-required fields (an agent could not verify a signature on the default
// network without explicitly supplying Network and RPC).
func TestNetworkRPCNeverRequired(t *testing.T) {
	schemas := buildToolSchemas(t)
	for name, sch := range schemas {
		for _, r := range sch.Required {
			if r == "network" || r == "rpc" {
				t.Errorf("%s: marks %q required — network/rpc are optional everywhere (§6.2)", name, r)
			}
			// Go-cased leaks (Network/RPC/Account/NoHash/Acked) are the exact sign/verify
			// regression: snake_case is the convention, so a capitalized required field is
			// a missing-json-tag bug.
			if r == "Network" || r == "RPC" || r == "Account" || r == "NoHash" || r == "Acked" {
				t.Errorf("%s: marks Go-cased %q required — the request struct is missing snake_case json tags (§6.2)", name, r)
			}
		}
	}
}

// TestUnlimitedAckFieldIsConsistent pins the §6 reconciliation note: the ONE named
// unlimited-acknowledgement field `acknowledge_unlimited` appears on each of the three
// signing tools that can grant an unbounded allowance (token_approve, sign_typed_data,
// contract_send), as an OPTIONAL boolean. (Regression guard for the bug where the three
// used three inconsistent mechanisms: confirm / acknowledge_unlimited / Acked.)
func TestUnlimitedAckFieldIsConsistent(t *testing.T) {
	schemas := buildToolSchemas(t)
	for _, tool := range []string{"token_approve", "sign_typed_data", "contract_send"} {
		sch := schemas[tool]
		if sch == nil {
			t.Fatalf("tool %q not registered", tool)
		}
		prop, ok := sch.Properties["acknowledge_unlimited"]
		if !ok {
			t.Errorf("%s: schema has no `acknowledge_unlimited` field — the unlimited ack must be ONE named field across all three unlimited-granting signers (§6 reconciliation)", tool)
			continue
		}
		if prop != nil && prop.Type != "" && prop.Type != "boolean" {
			t.Errorf("%s: `acknowledge_unlimited` type = %q, want boolean", tool, prop.Type)
		}
		// It is OPTIONAL (omitempty): an agent omits it for a bounded grant.
		for _, r := range sch.Required {
			if r == "acknowledge_unlimited" {
				t.Errorf("%s: `acknowledge_unlimited` must be OPTIONAL (omitted for bounded grants), not required", tool)
			}
		}
		// The undescribed Go-cased `Acked` must never leak (the sign_typed_data regression).
		if _, leaked := sch.Properties["Acked"]; leaked {
			t.Errorf("%s: schema exposes the undescribed Go-cased `Acked`; the ack field must be the named acknowledge_unlimited (§6.3)", tool)
		}
	}
}
