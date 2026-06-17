package chain

import "net/http"

// headerRoundTripper attaches a fixed set of custom headers to EVERY outbound
// RPC request before delegating to the base transport. go-ethereum's
// rpc.WithHeaders already injects headers for both HTTP and websocket
// connections, but routing them through the transport as well is belt-and-
// suspenders: it guarantees the headers ride on every HTTP request even on the
// reconnect/retry paths inside the rpc client, and it is the single place mTLS
// (the base *http.Transport) and auth headers compose.
//
// The header set is cloned once at construction; the round-tripper never mutates
// the caller's request headers in place beyond setting its own keys, and it
// clones the request so concurrent reuse is safe.
type headerRoundTripper struct {
	base    http.RoundTripper
	headers http.Header
}

// newHeaderRoundTripper wraps base so that headers are set on every request. A
// nil/empty headers map returns base unchanged (no allocation, no wrapper). A
// nil base falls back to http.DefaultTransport.
func newHeaderRoundTripper(base http.RoundTripper, headers map[string]string) http.RoundTripper {
	if len(headers) == 0 {
		if base == nil {
			return http.DefaultTransport
		}
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	h := make(http.Header, len(headers))
	for k, v := range headers {
		h.Set(k, v)
	}
	return &headerRoundTripper{base: base, headers: h}
}

// RoundTrip sets the configured headers on a shallow clone of req and delegates.
// Cloning avoids mutating a request the caller may reuse and keeps the
// round-tripper safe for concurrent use.
func (t *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	for k, vs := range t.headers {
		// Replace any inherited value so the configured header always wins.
		r2.Header.Del(k)
		for _, v := range vs {
			r2.Header.Add(k, v)
		}
	}
	return t.base.RoundTrip(r2)
}
