package tools

import (
	"context"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// write.go holds the signing/state-changing tools (design §6.1 rows 5, 9, 10, 12,
// 13, 31 + the two off-chain signers 15, 16): the addWrite/addSign wrappers, the
// §6.4 ceremony each request type needs, and the writeSink shape. Every one is the
// SAME call the CLI runs (the central guarantee): the generic addWrite/addSign
// wrappers bind args → the SAME domain request → the SAME service method (the only
// path to domain.Signer, with policy.Reserve + the seal/allowlist/ENS-pin/gas-cap/
// unlimited checks INSIDE it) →
// the result. This package cannot import policy/keys, so it has no way to SKIP the
// check — guardrails bind MCP identically by construction.
//
// The ceremony functions below are the ONE place a write request is touched before
// the call, and they touch ONLY frontend-ceremony fields:
//
//   - Yes = true. The interactive y/N is a TTY convenience that cannot exist
//     over a tool call; wiring it constant-true is the FULL extent of "MCP is
//     non-interactive," NOT a safety waiver (§6.4). It is the --yes confirmation
//     skip, never a safety acknowledgement. It carries json:"-", so it is NEVER an
//     agent-visible schema field (§6.2): the agent cannot — and need not — pass it.
//   - Wait.Enabled = true. Over MCP, waiting for finality is the DEFAULT (agents
//     want the confirmed result + the settle-to-actuals, §6.4/§6.5). An agent that
//     supplies wait.confirmations / wait.timeout tunes the wait; those ride through
//     untouched.
//
// They DELIBERATELY do NOT touch the unlimited-approval acknowledgement (the ONE
// named schema field acknowledge_unlimited → ApproveRequest.AckUnlimited /
// SignTypedRequest.AckUnlimited / ContractSendRequest.AckUnlimited, mapped to
// Check.Acked): that bit comes STRAIGHT FROM THE SCHEMA FIELD, never frontend-set
// (§6.2/§6.4). A compromised agent must say the dangerous thing out loud in the
// audited tool call; the classifier then routes it through the SAME unlimited gate as
// token_approve (policy.denied.unlimited_unacked when absent). The ceremony also never
// touches From/To/Spender/Amount/Token/Contract/gas/nonce/ABI — those are the agent's
// inputs, passed verbatim.

// writeSink is the shape of a signing/state-changing service method: (ctx,
// Principal, In, EventSink) → (TxResult, error). SendTx/Speedup/Cancel/TokenApprove/
// TokenRevoke/ContractSend all match — one result type (TxResult) for every
// broadcasting op (§5.1).
type writeSink[In any] func(context.Context, domain.Principal, In, domain.EventSink) (domain.TxResult, error)

// addWrite registers a signing tool — the §6.4 central guarantee. The handler is the
// SAME call the CLI runs: same Principal-bearing service method, same request struct,
// so policy.Reserve + the seal/allowlist/ENS-pin/gas-cap/unlimited checks run inside
// fn before Signer.SignTx; this package cannot import policy/keys, so it cannot skip
// the check. The mutate hook (the per-type ceremony below) stamps the §6.4 invariants
// onto the request just before the call — the ONLY place a write request is touched,
// and it touches only frontend-ceremony fields (Confirm/Wait), never a policy/signing
// field and never the unlimited ack (which rides the schema field untouched).
// Dual-signal (tx.reverted / tx.wait_timeout / tx.nonce_gap) returns BOTH IsError:true
// AND the structured TxResult (§6.6); a plain denial returns a tool error.
func addWrite[In any](srv *mcp.Server, name, desc string, mutate func(*In), fn writeSink[In]) {
	mcp.AddTool(srv, withSchemas[In, domain.TxResult](writeToolDef(name, desc)),
		func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, *domain.TxResult, error) {
			mutate(&in) // §6.4 ceremony: Confirm/Wait; the unlimited ack is never frontend-set
			out, err := fn(ctx, domain.LocalMCP(), in, progressSink(ctx, req))
			if dualSignal(err) {
				return dualResult(err), &out, nil // BOTH IsError + structured Out
			}
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}

// sendCeremony wires the §6.4 invariants onto a TxRequest (ETH + ERC-20 transfer).
// NOTE the recorded D5 deviation: the v1 `send` tool binds SendTx/TxRequest and
// covers ETH + ERC-20 over MCP; NFT transfer (SendNFT/NFTSendRequest) is NOT on the
// v1 MCP surface (adding a 32nd tool would break the §6.1 count of 31).
func sendCeremony(in *domain.TxRequest) {
	in.Yes = true
	in.Wait.Enabled = true
}

// speedupCeremony / cancelCeremony wire the §6.4 invariants onto the RBF requests.
// A bumped speedup/cancel is re-policy-checked in core (the gas cap re-applies); the
// frontend adds nothing.
func speedupCeremony(in *domain.SpeedupRequest) {
	in.Yes = true
	in.Wait.Enabled = true
}

func cancelCeremony(in *domain.CancelRequest) {
	in.Yes = true
	in.Wait.Enabled = true
}

// approveCeremony / revokeCeremony wire the §6.4 invariants onto an ApproveRequest.
//
// D1 (recorded): there is no domain.RevokeRequest; TokenRevoke takes
// domain.ApproveRequest and forces amount 0 in core. The revoke tool binds
// ApproveRequest verbatim — NO frontend-side amount remap (that would be business
// logic in the frontend). The revoke tool's schema is therefore the approve schema;
// its description states it sets the allowance to 0.
//
// Yes (the TTY-skip) and AckUnlimited (the unlimited acknowledgement) are now SEPARATE
// fields (§6.3/§6.4): Yes carries json:"-" (CLI-interaction; never an agent-visible
// field), AckUnlimited is the schema field acknowledge_unlimited mapped to Check.Acked.
// So the ceremony can wire Yes=true UNCONDITIONALLY — it can no longer satisfy the
// unlimited gate, because the gate consumes AckUnlimited, not Yes. An UNLIMITED approve
// whose acknowledge_unlimited is unset is denied policy.denied.unlimited_unacked: the
// agent must "say the dangerous thing out loud" in the audited tool call. The ceremony
// DELIBERATELY never touches AckUnlimited — it rides the schema field untouched.
func approveCeremony(in *domain.ApproveRequest) {
	in.Yes = true // confirmation-skip only; NEVER the unlimited ack (that is AckUnlimited)
	in.Wait.Enabled = true
}

// revokeCeremony: a revoke (approve(spender,0)) carries no unlimited risk, so the
// blanket TTY-skip is safe; AckUnlimited is irrelevant (a revoke is never unlimited).
func revokeCeremony(in *domain.ApproveRequest) {
	in.Yes = true
	in.Wait.Enabled = true
}

// contractSendCeremony wires the §6.4 invariants onto a ContractSendRequest. The
// unlimited acknowledgement is a SEPARATE field (AckUnlimited ← acknowledge_unlimited
// in the schema) mapped to Check.Acked — DISTINCT from Yes (§4.2 D12), so
// wiring Yes=true here is safe and never satisfies the unlimited ceremony: if
// the calldata classifies as an unlimited approve/permit and AckUnlimited is unset,
// core denies policy.denied.unlimited_unacked exactly like token_approve --unlimited.
// Raw calldata is NOT a policy bypass — ClassifyCalldata runs at stage 2 inside
// authorize, the same insertion point ClassifyTypedData uses for sign_typed_data.
func contractSendCeremony(in *domain.ContractSendRequest) {
	in.Yes = true
	in.Wait.Enabled = true
}

// ─── off-chain signing tools (15, 16): no EventSink, no Confirm field ────────
//
// SignMessage/SignTyped take (ctx, Principal, In) → (SigResult, error) — NO
// EventSink (signing is fire-and-return) and NO Yes/Wait ceremony (there is no
// broadcast to confirm). SignTyped routes a recognized permit through the SAME
// authorizeSignature gate as an on-chain approval (a permit is policy-checked at
// SIGNATURE time); the unlimited ack rides in SignTypedRequest.AckUnlimited from the
// schema field acknowledge_unlimited, never frontend-set — the ONE named ack field
// shared with ApproveRequest/ContractSendRequest. Both surface a policy denial as a
// plain tool error (no dual-signal — there is no TxResult on a signature path).
//
// D6 (recorded): the sign/verify request structs carry []byte fields (Message/Typed)
// the SDK infers as base64-encoded strings (the agent passes message bytes / EIP-712
// JSON as base64). All OTHER fields now carry snake_case json + jsonschema tags
// (network/rpc/account optional via omitempty, no_hash/acknowledge_unlimited described)
// so the realized schema matches the other tools' conventions and §6.2's optional
// network/rpc/from rule. Group C's golden test pins the inferred surface so it can
// never silently change. The frontend adds NO MCP-only wrapper (the design forbids it).

// signFn is an off-chain signing service method: (ctx, Principal, In) → (SigResult,
// error). SignMessage and SignTyped both match.
type signFn[In any] func(context.Context, domain.Principal, In) (domain.SigResult, error)

// addSign registers an off-chain signing tool. It is a write tool (it touches the
// key + the policy typed gate) but has no broadcast/wait/dual-signal, so it is the
// thinnest signing wrapper: bind In → the SAME service method → SigResult, with the
// signing annotations (the host treats it as state-changing for confirmation UX).
func addSign[In any](srv *mcp.Server, name, desc string, fn signFn[In]) {
	mcp.AddTool(srv, withSchemas[In, domain.SigResult](writeToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, *domain.SigResult, error) {
			out, err := fn(ctx, domain.LocalMCP(), in)
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}
