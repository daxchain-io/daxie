package tools

import (
	"context"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// stream.go holds the receive tool (design §6.1 row 11, §6.5). receive is the
// long-running invoice-watch op: the handler BLOCKS and streams progress (it does
// not return-then-poll). The §6.5 exception is wired for free by the core +
// progressSink: the core emits EvListening (carrying the receiving address) as its
// FIRST event before the watch loop, so progressSink forwards it as the first
// progress notification — the counterparty gets the address before the block, exactly
// as the CLI emits the up-front {"event":"listening","address":…} NDJSON line.
//
// receive is counted READ-ONLY (the §6.7 footer's 23): it derives/echoes an address
// (ReceiveRequest.new:true is the ONE derivation path on the agent surface, and it
// fails keystore.read_only on a Secret-mounted keystore) but it NEVER signs. So it
// uses the read annotations, not the signing ones — there is no Confirm/Wait
// ceremony and no dual-signal.
//
// A receive TIMEOUT is NOT a tool error (§6.5): the core returns the ReceiveResult
// (Status:"timeout", Exit 8, with a Resume command) and a NIL Go error — it is
// "still listening," resumable; re-call to resume. Only a genuine fault (RPC down,
// bad ref, --new on a read-only keystore) returns a Go error, which becomes a plain
// tool error. receive's wait.timeout defaults to BLOCK FOREVER (not the tx 10m
// default); the schema description (descReceive) tells agents to set one so the call
// is bounded.

// addReceive registers the receive tool. Its shape is the read-with-sink shape
// (ctx, Principal, ReceiveRequest, EventSink) → (ReceiveResult, error), but it is
// long-running so the call holds open while progress streams. No ceremony, no
// dual-signal: complete and timeout both come back as (result, nil).
func addReceive(srv *mcp.Server, name, desc string, fn func(context.Context, domain.Principal, domain.ReceiveRequest, domain.EventSink) (domain.ReceiveResult, error)) {
	mcp.AddTool(srv, withSchemas[domain.ReceiveRequest, domain.ReceiveResult](readToolDef(name, desc)),
		func(ctx context.Context, req *mcp.CallToolRequest, in domain.ReceiveRequest) (*mcp.CallToolResult, *domain.ReceiveResult, error) {
			out, err := fn(ctx, domain.LocalMCP(), in, progressSink(ctx, req))
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}
