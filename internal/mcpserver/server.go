package mcpserver

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sort"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/mcpserver/tools"
	"github.com/daxchain-io/daxie/internal/service"
	"github.com/daxchain-io/daxie/internal/version"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// server.go assembles the transport-agnostic *mcp.Server ONCE over the SAME
// *service.Service both frontends share (design §6.8, §1a). New is transport-free:
// it registers all 31 tools and never changes when a transport is added. It
// touches no keystore/network (lazy) so `daxie mcp tools` introspection is safe.

// New builds the *mcp.Server over svc and registers the 31 tools (design §6.1) via
// the ONE tools.Register call. Both `mcp serve` (which then picks a transport) and
// `mcp tools` (which introspects the registered schemas) call New. svc may be nil
// only for pure schema introspection paths that never invoke a handler (the golden
// schema test relies on this — registration binds svc into closures but does not
// call it).
func New(svc *service.Service) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "daxie",
		Title:   "Daxie — the Ethereum wallet for AI",
		Version: version.Get().Version,
	}, nil)
	// A panic in any service method reached through a tool would otherwise
	// propagate up the SDK's per-request goroutine — which has no recover() — and
	// crash the WHOLE `mcp serve` process, killing every in-flight session, not
	// just the offending call. This receiving middleware sits above the typed tool
	// dispatch and converts a panic into a per-call internal error so the long-
	// lived server survives a single bad input.
	srv.AddReceivingMiddleware(recoverMiddleware)
	tools.Register(srv, svc)
	return srv
}

// recoverMiddleware wraps every inbound request so a panic in a handler becomes a
// CodeInternal error for that one call instead of taking down the process. The
// panic value and stack go to stderr (the operator's channel — stdout carries the
// stdio protocol) for diagnosis; the client receives only a generic message so a
// panic string can never leak state to the agent.
func recoverMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (result mcp.Result, err error) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "daxie mcp: recovered panic in %q: %v\n%s\n", method, r, debug.Stack())
				result = nil
				err = domain.Newf(domain.CodeInternal, "internal error handling %q", method)
			}
		}()
		return next(ctx, method, req)
	}
}

// ServeStdio is the v1 wiring (design §6.8): one line, no per-connection state. It
// blocks until the client disconnects or ctx is canceled (SIGINT/SIGTERM threaded
// from the cli host).
func ServeStdio(ctx context.Context, srv *mcp.Server) error {
	return srv.Run(ctx, &mcp.StdioTransport{})
}

// Serve is the design §6.8 transport switch the cli binds. stdio is the ONLY
// accepted value in v1; http is rejected with a forward-pointing domain.Error so
// the CLI contract is stable when v1.1 flips it on (a new enum value + a
// transport_http.go body, not a refactor). An unknown value is a usage error.
func Serve(ctx context.Context, srv *mcp.Server, transport string) error {
	switch transport {
	case "", "stdio":
		return ServeStdio(ctx, srv)
	case "http":
		return domain.New(domain.CodeUsageUnsupported,
			"the http transport ships in v1.1; v1 serves MCP over --transport stdio only")
	default:
		return domain.Newf("usage.invalid", "unknown --transport %q (v1: stdio)", transport)
	}
}

// ListTools enumerates every registered tool's name, description, inferred input/
// output schema, and annotations — the exact tools/list payload a client sees on
// connect (design §6.7). It is the introspection primitive `daxie mcp tools` and
// the golden-schema test (§6.7) both use. It connects an in-memory client to srv
// (the SDK-blessed way to read the inferred schemas, since the per-tool list is
// server-internal), runs no transport over the OS, and dials no RPC / unlocks no
// keystore — so it is safe over a srv built from a never-opened service. The
// returned slice is sorted by tool name for a stable, diffable contract.
func ListTools(ctx context.Context, srv *mcp.Server) ([]*mcp.Tool, error) {
	serverT, clientT := mcp.NewInMemoryTransports()
	// The server must be connected before the client (the client initializes the
	// session on connect).
	ss, err := srv.Connect(ctx, serverT, nil)
	if err != nil {
		return nil, domain.Wrap(domain.CodeInternal, "mcp: connect server for introspection", err)
	}
	defer func() { _ = ss.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "daxie-introspect", Version: version.Get().Version}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		return nil, domain.Wrap(domain.CodeInternal, "mcp: connect client for introspection", err)
	}
	defer func() { _ = cs.Close() }()

	var out []*mcp.Tool
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return nil, domain.Wrap(domain.CodeInternal, "mcp: list tools", err)
		}
		out = append(out, tool)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
