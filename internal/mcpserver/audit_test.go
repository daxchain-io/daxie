package mcpserver

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func auditCapture(t *testing.T, base mcp.MethodHandler, method string, req mcp.Request) string {
	t.Helper()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	if _, err := auditMiddleware(log)(base)(context.Background(), method, req); err != nil && domain.AsError(err) == nil {
		t.Fatalf("unexpected non-domain error: %v", err)
	}
	return buf.String()
}

// TestAuditMiddleware_ToolError logs the tool name and the in-band tool-error outcome.
func TestAuditMiddleware_ToolError(t *testing.T) {
	base := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return &mcp.CallToolResult{IsError: true}, nil
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "send"}}
	out := auditCapture(t, base, "tools/call", req)
	for _, want := range []string{"method=tools/call", "tool=send", "outcome=tool_error"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit line %q missing %q", out, want)
		}
	}
}

// TestAuditMiddleware_Error logs the outcome and the domain error code.
func TestAuditMiddleware_Error(t *testing.T) {
	base := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return nil, domain.New(domain.CodePolicyDenied, "over the day limit")
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: "token_approve"}}
	out := auditCapture(t, base, "tools/call", req)
	for _, want := range []string{"tool=token_approve", "outcome=error", "code=" + domain.CodePolicyDenied} {
		if !strings.Contains(out, want) {
			t.Errorf("audit line %q missing %q", out, want)
		}
	}
}

// TestAuditMiddleware_OkNonTool logs ok and omits the tool field for a non-tool method.
func TestAuditMiddleware_OkNonTool(t *testing.T) {
	base := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		return &mcp.ListToolsResult{}, nil
	}
	out := auditCapture(t, base, "tools/list", &mcp.ListToolsRequest{})
	if !strings.Contains(out, "outcome=ok") || !strings.Contains(out, "method=tools/list") {
		t.Errorf("audit line %q missing ok/method", out)
	}
	if strings.Contains(out, "tool=") {
		t.Errorf("audit line %q should not carry a tool field for a non-tool method", out)
	}
}
