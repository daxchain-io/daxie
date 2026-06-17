package mcpserver

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// transport_http.go is the RESERVED v1.1 HTTP + auth seam (design §6.8, §2.10). It
// is declared NOW so the Authenticator/Principal hook has a home and v1.1 is a body
// swap touching nothing above — a new file body + a new --transport enum value, not
// a refactor. In v1 no net/http server is started; ServeHTTP refuses with a
// forward-pointing domain.Error.
//
// Four properties already in place make HTTP a drop-in (none built in v1, only the
// seams): (1) service.Service is concurrency-safe (file locks hold under N HTTP
// sessions); (2) handlers keep zero per-connection state (one *mcp.Server serves
// every connection; the per-request principal rides in ctx); (3) the Principal seam
// is already threaded — v1.1's Authenticator fills Principal.ID from a bearer/mTLS
// identity, a value change not a plumbing change; (4) progressSink + the SDK's
// NotifyProgress already deliver over HTTP transparently.

// HTTPOptions is the reserved v1.1 HTTP listener config. The Authenticator turns a
// request identity into a domain.Principal; a nil Authenticator means "refuse
// non-loopback" (v1.1 policy). The field is unused in v1 — its presence is the
// whole point: every service method already takes a Principal, so wiring auth is a
// value change, not a plumbing change.
type HTTPOptions struct {
	Addr          string
	Authenticator func(r *http.Request) (domain.Principal, error) // nil ⇒ refuse non-loopback (v1.1)
	TLS           *tls.Config
}

// ServeHTTP is the v1.1 entry point. In v1 it refuses: NO net/http server is
// started. v1.1 lands the body here (mcp.NewStreamableHTTPHandler + the
// Authenticator middleware), touching nothing in server.go. The blank parameters
// keep the v1.1 signature stable while documenting what v1.1 binds.
func ServeHTTP(_ context.Context, _ *mcp.Server, _ HTTPOptions) error {
	return domain.New(domain.CodeUsageUnsupported,
		"the http transport ships in v1.1; use --transport stdio")
}
