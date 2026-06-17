package tools

import (
	"context"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// progress.go is the design §6.5 long-running-op wiring: it maps the core's single
// domain.EventSink onto MCP progress notifications, gated on the client's progress
// token. Long-running tools (tx_wait, receive, and any wait-bearing send/approve/
// speedup) BLOCK and stream — the handler holds the call open and emits one
// notification per intermediate domain.Event while the agent's CallTool future
// stays pending.
//
// It lives in package tools (the handlers call progressSink unqualified; mcpserver
// imports tools, so tools cannot import mcpserver — this is the cycle-free home).
//
// The receive exception (§6.5): the core emits EvListening (carrying the receiving
// address) as its FIRST event before the watch loop; progressSink forwards it as
// the first progress notification, so the counterparty gets the address before the
// block. The final result is always the tool's return value; progress is
// best-effort (a dropped notification never affects the outcome, which is fully
// captured in the return value).

// progressSink builds the domain.EventSink a write/stream handler hands to the
// service method. When the client sent no progress token it returns nil — the core
// tolerates a nil sink (domain.Emit is nil-safe) and the final result still
// carries the full picture, so omitting progress is never an error. Otherwise it
// returns a sink that forwards each domain.Event to the client over the call's
// session, keyed by the progress token.
func progressSink(ctx context.Context, req *mcp.CallToolRequest) domain.EventSink {
	if req == nil || req.Session == nil || req.Params == nil {
		return nil
	}
	token := req.Params.GetProgressToken()
	if token == nil {
		return nil // no progress token ⇒ no-op sink
	}
	return func(ev domain.Event) {
		// Best-effort: a notify failure (client drop, slow consumer) must not
		// affect the tool outcome, which is fully captured in the return value.
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Message:       string(ev.Kind), // same vocabulary the CLI renders + receive --json emits
			Meta:          eventMeta(ev),   // typed payload (resolved addr, conf depth/target, listening addr)
		})
	}
}

// eventMeta projects a domain.Event's typed payload into the notification _meta map
// so an agent that reads progress (not just the final result) sees the same fields
// the CLI streams: the resolved/listening address, the confirmation depth and
// target, the tx hash, and any human detail. Only non-zero fields are included so a
// "broadcast" line does not carry empty confirmation counters. Keys are namespaced
// under "daxie/" to avoid colliding with SDK/protocol meta keys.
func eventMeta(ev domain.Event) mcp.Meta {
	m := mcp.Meta{}
	if ev.Hash != "" {
		m["daxie/hash"] = ev.Hash
	}
	if ev.Address != (common.Address{}) {
		m["daxie/address"] = ev.Address.Hex()
	}
	if ev.Conf != 0 {
		m["daxie/confirmations"] = ev.Conf
	}
	if ev.Target != 0 {
		m["daxie/target"] = ev.Target
	}
	if ev.Detail != "" {
		m["daxie/detail"] = ev.Detail
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
