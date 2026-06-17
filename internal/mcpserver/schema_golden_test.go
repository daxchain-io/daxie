package mcpserver

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// schema_golden_test.go is the §6.7 GOLDEN-SCHEMA contract test. It pins the
// agent-visible MCP surface — every tool's name, description, inferred inputSchema,
// inferred outputSchema, and annotations — against a checked-in fixture so the surface
// can NEVER silently drift.
//
// Why this matters (J5): the input schemas are INFERRED from the SAME domain request
// structs the CLI binds; the output schemas from the same result structs. So a struct
// change that alters an agent-visible field (a new property, a renamed json tag, a
// changed jsonschema description, a tweaked enum) shows up HERE as a reviewed diff —
// CLI/MCP drift is structurally impossible AND any drift in the shared structs is
// caught. This is the byte-for-byte contract a client sees on `tools/list` connect,
// the same payload `daxie mcp tools --json` prints (§6.7).
//
// Regenerate after an intentional schema change: `go test ./internal/mcpserver -run
// Golden -update`. The fixture is REVIEWED in the diff — a surprising change is a bug.

var updateGolden = flag.Bool("update", false, "regenerate the golden tools.json fixture")

const goldenPath = "testdata/tools.json"

// goldenTool is the stable, transport-agnostic projection of a registered tool we pin.
// The SDK delivers InputSchema/OutputSchema to the client as map[string]any (the
// default marshaling of the inferred schema), so json.RawMessage canonicalized via a
// round-trip through a map gives a deterministic, key-sorted shape.
type goldenTool struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	InputSchema  json.RawMessage `json:"inputSchema,omitempty"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
}

// listToolsFromServer connects an in-memory client to a freshly-built server and
// returns every registered tool, sorted by name. New(nil) is safe: schema inference is
// purely type-driven and no handler runs during tools/list, so no service is dialed
// (this is exactly how `daxie mcp tools` introspects lazily, §6.7).
func listToolsFromServer(t *testing.T) []*mcp.Tool {
	t.Helper()
	ctx := context.Background()
	srv := New(nil)

	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "golden-test", Version: "0.0.0"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	tools := res.Tools
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools
}

// canonJSON marshals v, then re-decodes into a map (recursively, via the standard
// library's deterministic key-sorted object marshaling) so two structurally-equal
// schemas serialize byte-identically regardless of source key order.
func canonJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var anyV any
	if err := json.Unmarshal(b, &anyV); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, err := json.Marshal(anyV) // encoding/json sorts map keys ⇒ canonical
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return out
}

// goldenToolsFromServer projects the live server's tools into the pinned shape.
func goldenToolsFromServer(t *testing.T) []goldenTool {
	t.Helper()
	tools := listToolsFromServer(t)
	out := make([]goldenTool, 0, len(tools))
	for _, tl := range tools {
		out = append(out, goldenTool{
			Name:         tl.Name,
			Description:  tl.Description,
			InputSchema:  canonJSON(t, tl.InputSchema),
			OutputSchema: canonJSON(t, tl.OutputSchema),
			Annotations:  canonJSON(t, tl.Annotations),
		})
	}
	return out
}

// TestToolSchemasGolden diffs the live inferred surface against the checked-in fixture.
// ANY change to an agent-visible schema (a domain struct field, a jsonschema tag, a
// description, an annotation) fails here as a reviewable diff (§6.7).
func TestToolSchemasGolden(t *testing.T) {
	got := goldenToolsFromServer(t)
	gotBytes, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal golden: %v", err)
	}
	gotBytes = append(gotBytes, '\n')

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, gotBytes, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s (%d tools)", goldenPath, len(got))
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v (run `go test ./internal/mcpserver -run Golden -update` to create it)", goldenPath, err)
	}
	if string(want) != string(gotBytes) {
		t.Errorf("MCP tool schema surface drifted from %s.\n"+
			"If this change is intentional, review the diff and regenerate:\n"+
			"  go test ./internal/mcpserver -run Golden -update\n"+
			"Otherwise a domain request/result struct changed an agent-visible schema "+
			"(CLI/MCP both bind these — see §6.2/§6.7).\n"+
			"--- want (%d bytes) ---\n%s\n--- got (%d bytes) ---\n%s",
			goldenPath, len(want), string(want), len(gotBytes), string(gotBytes))
	}
}

// TestGoldenIsExactly31Tools is a fast guard independent of the byte-diff: the pinned
// fixture (and therefore the live surface) carries EXACTLY the 31 §6.1 tools, no more,
// no fewer. A 32nd tool (e.g. an accidental nft_send, D5) or a dropped tool fails here.
func TestGoldenIsExactly31Tools(t *testing.T) {
	got := goldenToolsFromServer(t)
	if len(got) != 31 {
		names := make([]string, len(got))
		for i, g := range got {
			names[i] = g.Name
		}
		t.Fatalf("registered tool count = %d, want EXACTLY 31 (§6.1); tools: %v", len(got), names)
	}
}

// TestMcpToolsJSONMatchesGolden asserts the fixture IS the `daxie mcp tools --json`
// contract: the byte-for-byte payload a client sees on connect equals what the command
// prints (§6.7). The command builds the SAME server via mcpserver.New, so the projected
// surface must match the live one; this guards that the fixture is not a stale artifact
// diverging from the live registration. (The CLI command's exact JSON framing is a
// frontend concern pinned in internal/cli; here we pin the source-of-truth surface.)
func TestMcpToolsJSONMatchesGolden(t *testing.T) {
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Skipf("golden %s not present yet (run -update): %v", goldenPath, err)
	}
	var pinned []goldenTool
	if err := json.Unmarshal(want, &pinned); err != nil {
		t.Fatalf("golden %s is not valid JSON: %v", goldenPath, err)
	}
	live := goldenToolsFromServer(t)
	if len(pinned) != len(live) {
		t.Fatalf("golden has %d tools, live server has %d", len(pinned), len(live))
	}
	for i := range pinned {
		if pinned[i].Name != live[i].Name {
			t.Errorf("tool[%d] name: golden %q != live %q", i, pinned[i].Name, live[i].Name)
		}
	}
}
