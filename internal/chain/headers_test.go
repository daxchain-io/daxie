package chain

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHeaderRoundTripper_AttachesToEveryRequest proves the custom-header
// round-tripper sets the configured headers on EVERY outbound request — the
// non-negotiable from the M2 plan (auth headers must ride every RPC call).
func TestHeaderRoundTripper_AttachesToEveryRequest(t *testing.T) {
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Clone())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newHeaderRoundTripper(srv.Client().Transport, map[string]string{
		"Authorization": "Bearer secret-token",
		"X-Api-Key":     "abc123",
	})
	hc := &http.Client{Transport: rt}

	// Two separate requests: both must carry the headers (not just the first).
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_ = resp.Body.Close()
	}

	if len(seen) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(seen))
	}
	for i, h := range seen {
		if got := h.Get("Authorization"); got != "Bearer secret-token" {
			t.Errorf("request %d Authorization = %q, want %q", i, got, "Bearer secret-token")
		}
		if got := h.Get("X-Api-Key"); got != "abc123" {
			t.Errorf("request %d X-Api-Key = %q, want %q", i, got, "abc123")
		}
	}
}

// TestHeaderRoundTripper_NoHeadersReturnsBase confirms the no-op fast path: an
// empty header map returns the base transport unwrapped (no needless allocation
// or behavioral change).
func TestHeaderRoundTripper_NoHeadersReturnsBase(t *testing.T) {
	base := http.DefaultTransport
	if got := newHeaderRoundTripper(base, nil); got != base {
		t.Errorf("nil headers: got wrapped transport, want base unchanged")
	}
	if got := newHeaderRoundTripper(base, map[string]string{}); got != base {
		t.Errorf("empty headers: got wrapped transport, want base unchanged")
	}
	// A nil base with no headers must fall back to the default transport, not nil.
	if got := newHeaderRoundTripper(nil, nil); got == nil {
		t.Errorf("nil base + nil headers: got nil transport")
	}
}

// TestHeaderRoundTripper_DoesNotMutateCallerRequest proves the round-tripper
// clones the request: the caller's original request headers are untouched, so a
// reused request object never accumulates the injected headers.
func TestHeaderRoundTripper_DoesNotMutateCallerRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt := newHeaderRoundTripper(srv.Client().Transport, map[string]string{"X-Api-Key": "k"})
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	_ = resp.Body.Close()

	if got := req.Header.Get("X-Api-Key"); got != "" {
		t.Errorf("caller request was mutated: X-Api-Key = %q, want empty", got)
	}
}
