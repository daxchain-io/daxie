package tools

import (
	"context"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// pure.go holds the convert tool (design §6.1 row 23, §6.3). convert is the
// cheapest live-server smoke test: it touches no chain, no keystore, no policy — a
// pure unit conversion over math/big in core. The other two pure tools
// (contract_encode/contract_decode, §6.1 rows 29/30) take a Principal in their
// service signature even though they too are pure, so they register via the generic
// addReadPlain wrapper (register.go); convert is the ONE tool whose service method
// takes NO Principal (the D3 deviation), so it needs this thin wrapper that supplies
// no Principal.

// addConvert registers the convert tool. Convert's service signature is (ctx, In) →
// (Out, error) — no Principal (a pure conversion has no actor). The handler binds
// the SAME domain.ConvertRequest the CLI binds and returns domain.ConvertResult.
func addConvert(srv *mcp.Server, name, desc string, fn func(context.Context, domain.ConvertRequest) (domain.ConvertResult, error)) {
	mcp.AddTool(srv, withSchemas[domain.ConvertRequest, domain.ConvertResult](readToolDef(name, desc)),
		func(ctx context.Context, _ *mcp.CallToolRequest, in domain.ConvertRequest) (*mcp.CallToolResult, *domain.ConvertResult, error) {
			out, err := fn(ctx, in)
			if err != nil {
				return nil, nil, toolError(err)
			}
			return nil, &out, nil
		})
}
