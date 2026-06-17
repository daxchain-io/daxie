package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcp.go renders `daxie mcp tools` (design §6.7): the human TOOL / KIND /
// DESCRIPTION table + the contract footer, the --json tools/list payload (the
// byte-for-byte contract a client sees on connect, also the golden-test artifact),
// and one tool's full schema for `mcp tools <name>`. It formats *mcp.Tool values
// the mcpserver core enumerates; it imports the MCP SDK (third-party, ungoverned
// by the frontend matrix) like the rest of the frontend imports ethunit/cobra. No
// network/keystore is touched — this is pure formatting.

// MCPToolsList is the --json shape: the tools/list payload {"tools":[…]}. It
// mirrors the SDK's ListToolsResult tools field so `mcp tools --json` and the
// golden fixture marshal identically.
type mcpToolsList struct {
	Tools []*mcp.Tool `json:"tools"`
}

// toolKind classifies a tool for the human table's KIND column from its
// annotations: a ReadOnlyHint tool is "read", otherwise it is a state-changing
// "sign" tool. Data-driven (the annotation Group B sets), so the renderer needs no
// hardcoded name list and cannot drift from the registered surface.
func toolKind(t *mcp.Tool) string {
	if t.Annotations != nil && t.Annotations.ReadOnlyHint {
		return "read"
	}
	return "sign"
}

// firstLine returns the first non-empty line of s, trimmed, for the compact table
// DESCRIPTION cell (the full multi-sentence description is in --json / the
// single-tool view).
func firstLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			return t
		}
	}
	return ""
}

// MCPTools writes the `daxie mcp tools` output.
//
//   - JSON mode: the exact tools/list payload {"tools":[…]} (every tool's name,
//     description, inputSchema, outputSchema, annotations) — the client-on-connect
//     contract and the golden-snapshot artifact.
//   - Human mode: a TOOL / KIND / DESCRIPTION table + the §6.7 footer. The
//     read/sign counts are derived from the tools themselves, so the footer can
//     never disagree with the registered surface.
func MCPTools(w io.Writer, m Mode, tools []*mcp.Tool) error {
	if m.JSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(mcpToolsList{Tools: tools})
	}

	tbl := NewTable(w)
	tbl.Row("TOOL", "KIND", "DESCRIPTION")
	var read, sign int
	for _, t := range tools {
		kind := toolKind(t)
		if kind == "read" {
			read++
		} else {
			sign++
		}
		tbl.Row(t.Name, kind, firstLine(t.Description))
	}
	if err := tbl.Flush(); err != nil {
		return err
	}
	// The footer is essential contract output (the §6.7 wording), so it prints
	// even under --quiet — it is the answer to "what can this server do", not
	// chatter.
	_, _ = fmt.Fprintf(w,
		"\n%d tools (%d read-only, %d signing). Transport: stdio (v1). "+
			"Signing tools enforce policy in core; no policy-mutation or key-export tools are exposed.\n",
		len(tools), read, sign)
	return nil
}

// MCPToolSchema writes one tool's full schema for `daxie mcp tools <name>`.
//
//   - JSON mode: the single *mcp.Tool object (name, description, inputSchema,
//     outputSchema, annotations).
//   - Human mode: the name + kind + full description, then the input and output
//     schemas pretty-printed.
func MCPToolSchema(w io.Writer, m Mode, t *mcp.Tool) error {
	if m.JSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(t)
	}

	_, _ = fmt.Fprintf(w, "%s (%s)\n\n%s\n", t.Name, toolKind(t), strings.TrimSpace(t.Description))
	if t.InputSchema != nil {
		_, _ = fmt.Fprint(w, "\ninput schema:\n")
		if err := writeIndentedJSON(w, t.InputSchema); err != nil {
			return err
		}
	}
	if t.OutputSchema != nil {
		_, _ = fmt.Fprint(w, "\noutput schema:\n")
		if err := writeIndentedJSON(w, t.OutputSchema); err != nil {
			return err
		}
	}
	return nil
}

func writeIndentedJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
