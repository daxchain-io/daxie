package tools

import (
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// errors.go is the design §6.6 error model: ONE domain.Error taxonomy projected
// onto MCP's tool-error mechanism. The dotted error.code an agent reads is the
// SAME string the CLI puts in its --json error and maps to an exit code (§5.7) —
// an agent branches on error.code, a shell on $?.
//
// These helpers live in package tools (not the mcpserver core) because the
// handlers call them unqualified and because mcpserver imports tools (for
// Register), so tools cannot import mcpserver — putting the helpers here is the
// cycle-free home. They are the coordination contract every handler wrapper in
// register.go uses.
//
// Three handler paths:
//
//	SUCCESS      return (nil, &out, nil)
//	             — the SDK fills StructuredContent from Out and packs a JSON
//	               TextContent; one serialization, two transports (§6.2).
//	PLAIN ERROR  return (nil, nil, toolError(err))
//	             — the SDK auto-packs the *domain.Error into Content with
//	               IsError:true; domain.Error.Error() is the JSON envelope
//	               byte-identical to the CLI --json error (§6.6).
//	DUAL-SIGNAL  return (dualResult(err), &out, nil)
//	             — the agent needs BOTH IsError:true AND the structured Out
//	               (tx.reverted / tx.wait_timeout / tx.nonce_gap). The SDK fills
//	               StructuredContent only on the nil-error return, so we return a
//	               NIL Go error with a hand-built IsError result + the populated
//	               Out (§6.6).

// toolError projects any error onto a *domain.Error for the SDK to pack as a tool
// error. A *domain.Error anywhere in the chain passes straight through (preserving
// its canonical code/exit/data); a raw Go error becomes {code:"internal",exit:1}
// via domain.AsError. nil maps to nil (the success path).
func toolError(err error) error {
	if err == nil {
		return nil
	}
	return domain.AsError(err)
}

// dualSignal reports whether err is one of the design §6.6 dual-signal codes: the
// agent must see IsError:true AND the structured *domain.TxResult. These are the
// tx outcomes that are simultaneously an error band (exit 7/8/9) and a
// fully-populated result an agent inspects (a reverted receipt, a still-pending
// tx, a reconciliation nonce gap).
func dualSignal(err error) bool {
	if err == nil {
		return false
	}
	switch domain.AsError(err).Code {
	case domain.CodeTxReverted, domain.CodeTxWaitTimeout, domain.CodeTxNonceGap:
		return true
	}
	return false
}

// dualResult builds the hand-rolled IsError CallToolResult for a dual-signal
// outcome. The caller returns it with a NIL Go error and the populated Out, so the
// SDK still marshals Out into StructuredContent while the result is flagged as an
// error. The TextContent carries the SAME JSON envelope domain.Error.Error()
// emits, byte-identical to the CLI --json error and to the plain-error path above.
func dualResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: domain.AsError(err).Error()}},
	}
}

// ToolError and DualSignal are the exported single-source-of-truth projections the
// mcpserver core forwards to (mcpserver imports tools for Register, so this is the
// cycle-free direction). They let the core expose the SAME error mapping under its
// own package without a second implementation — there is exactly one §6.6 taxonomy
// projection, here.
func ToolError(err error) error { return toolError(err) }
func DualSignal(err error) bool { return dualSignal(err) }
