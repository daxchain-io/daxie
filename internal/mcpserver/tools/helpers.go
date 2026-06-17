package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// helpers.go holds the tool-definition builders (design §6.4 annotations) the 31
// tools share. They are PURE frontend glue — they need only the MCP SDK, contain
// ZERO business logic, and physically cannot reach a provider. The §6.6 error
// helpers (toolError/dualSignal/dualResult) and the §6.5 progress wiring
// (progressSink/eventMeta) the handler wrappers also use live in errors.go /
// progress.go in this same package (the cycle-free home: mcpserver.New imports
// tools, so tools cannot import mcpserver).
//
// readToolDef / writeToolDef stamp the agent-visible name, description, and the MCP
// behavioural annotations. InputSchema/OutputSchema are left nil so the SDK INFERS
// them from the handler's In/Out Go types — the §6.2 contract that makes CLI/MCP
// drift impossible (the In type IS the domain request struct the CLI binds).

// readToolDef marks a read-only tool: ReadOnlyHint=true tells a host the tool does
// not modify its environment, so `mcp tools` classifies it "read-only" and a
// cautious host may auto-run it. Pure tools (convert/encode/decode) use this too.
func readToolDef(name, desc string) *mcp.Tool {
	return &mcp.Tool{
		Name:        name,
		Description: desc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}
}

// writeToolDef marks a signing/state-changing tool: ReadOnlyHint=false +
// DestructiveHint=true (it moves funds / grants allowances / broadcasts) so a host
// surfaces a confirmation affordance and `mcp tools` classifies it "signing". The
// policy guarantee is in the core, not the annotation: the hint is advisory, the
// authorize path is law (§6.4).
func writeToolDef(name, desc string) *mcp.Tool {
	return &mcp.Tool{
		Name:        name,
		Description: desc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(true)},
	}
}

// ptr returns a pointer to v. The SDK's optional-bool annotations (DestructiveHint/
// OpenWorldHint) are *bool so "false" is distinguishable from "unset"; ptr lets the
// definitions read declaratively.
func ptr[T any](v T) *T { return &v }
