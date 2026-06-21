package mcpserver

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// recover_test.go covers the receiving middleware that keeps a single panicking
// handler from taking down the whole `mcp serve` process (the SDK dispatches each
// request on its own goroutine with no recover of its own).

// TestRecoverMiddleware_ConvertsPanicToError asserts a panic in a handler becomes a
// CodeInternal error for that one call rather than crashing the process.
func TestRecoverMiddleware_ConvertsPanicToError(t *testing.T) {
	// The middleware writes the recovered value + stack to stderr; redirect it so
	// the (expected) trace does not clutter test output.
	restore := muffleStderr(t)
	defer restore()

	panicking := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		panic("boom: nil deref in a service method")
	}
	res, err := recoverMiddleware(panicking)(context.Background(), "tools/call", nil)
	if err == nil {
		t.Fatal("expected an error from a panicking handler, got nil (panic would have crashed the server)")
	}
	if res != nil {
		t.Errorf("expected a nil result on panic, got %v", res)
	}
	if de := domain.AsError(err); de == nil || de.Code != domain.CodeInternal {
		t.Errorf("recovered error = %v, want code %q", err, domain.CodeInternal)
	}
}

// TestRecoverMiddleware_PassesThroughNormalReturn asserts the middleware is
// transparent when nothing panics.
func TestRecoverMiddleware_PassesThroughNormalReturn(t *testing.T) {
	called := false
	ok := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		called = true
		return nil, nil
	}
	if _, err := recoverMiddleware(ok)(context.Background(), "ping", nil); err != nil {
		t.Fatalf("unexpected error from a non-panicking handler: %v", err)
	}
	if !called {
		t.Fatal("middleware did not invoke the wrapped handler")
	}
}

// muffleStderr swaps os.Stderr for a drained pipe for the duration of a test,
// returning a restore func. Used to keep an expected panic stack out of the logs.
func muffleStderr(t *testing.T) func() {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, r); close(done) }()
	return func() {
		os.Stderr = old
		_ = w.Close()
		<-done
		_ = r.Close()
	}
}
