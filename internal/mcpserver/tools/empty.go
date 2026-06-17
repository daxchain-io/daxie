package tools

import (
	"context"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/service"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// empty.go holds the policy_show tool (design §6.1 row 26) — the ONE policy verb on
// the agent surface, and it is READ-ONLY (every policy MUTATION is deliberately NOT
// a tool, §6.1: admin-passphrase-gated, the agent never holds it). policy_show lets
// an agent read the active limits/allowlist before it tries a send, so it can
// pre-flight whether a transfer is in-policy.
//
// Two deviations land here, recorded:
//
//   - PolicyShow's signature is (ctx, Principal) → (PolicyShowResult, error): it
//     takes NO request struct. The MCP input schema needs a concrete Go type to
//     infer from, so the tool's In is Empty (an empty object the SDK infers as
//     {"type":"object"}). The agent calls it with {} or no arguments.
//   - The Out is service.PolicyShowResult — a SERVICE type, not a domain type (D2).
//     mcpserver/tools legally imports service, so the inferred OUTPUT schema for this
//     one tool comes from a service struct. Group C's golden test pins it.

// Empty is the input type for tools whose service method takes no request struct
// (policy_show). The SDK infers it as an empty object schema; the agent supplies no
// arguments. It is a real exported type so the golden/parity tests can name it.
type Empty struct{}

// addPolicyShow registers the read-only policy_show tool. PolicyShow takes (ctx,
// Principal) with no request, so the handler ignores the Empty input and returns the
// SAME service.PolicyShowResult the CLI `policy show --json` renders.
func addPolicyShow(srv *mcp.Server, name, desc string, fn func(context.Context, domain.Principal) (service.PolicyShowResult, error)) {
	mcp.AddTool(srv, withSchemas[Empty, service.PolicyShowResult](readToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, _ Empty) (*mcp.CallToolResult, *service.PolicyShowResult, error) {
			out, err := fn(ctx, domain.LocalMCP())
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}
