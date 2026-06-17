package cli

import (
	"context"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/mcpserver"
	"github.com/spf13/cobra"
)

// mcp.go is the `daxie mcp` command tree (design §6, cli-spec §`daxie mcp`): the
// Cobra side of Frontend 2. Two subcommands:
//
//   - `daxie mcp serve --transport stdio` opens the SAME service every command
//     opens, builds the transport-agnostic *mcp.Server (mcpserver.New), and serves
//     it. --transport defaults to "stdio"; "http" is REJECTED in v1 with a
//     forward-pointing usage.unsupported error (the v1.1 seam is reserved, §6.8).
//     This is the ONE sanctioned cli→mcpserver import edge (arch matrix line ~223).
//   - `daxie mcp tools [<name>]` introspects the registered surface (§6.7): the
//     compact TOOL/KIND/DESCRIPTION table + footer, or --json the exact tools/list
//     payload, or one tool's full schema for [<name>]. It builds the server LAZILY
//     and never dials RPC / unlocks the keystore — mcpserver.New touches no
//     keystore/network, and ListTools introspects over an in-memory pipe.
//
// mcp.go contains ZERO business logic: serve hands the service straight to
// mcpserver.Serve; tools formats what the SDK infers. All tool behavior lives in
// the mcpserver package and the shared service methods.
func newMcpCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run the MCP server (Frontend 2) or inspect its tools",
		Long: "Daxie's Model Context Protocol server exposes the SAME wallet over the SAME\n" +
			"policy guardrails as the CLI — a second thin frontend, not a second core.\n\n" +
			"`mcp serve` runs the server over stdio (the v1 transport; http ships in v1.1).\n" +
			"`mcp tools` prints the tool surface a connecting client sees — 31 tools that\n" +
			"can move funds within policy and read everything, but cannot mutate policy,\n" +
			"export/import/create keys, or redefine an alias (the §6.1 exclusion boundary).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newMcpServeCmd(ctx, rs),
		newMcpToolsCmd(ctx, rs),
	)
	return cmd
}

// newMcpServeCmd builds `daxie mcp serve --transport stdio`.
func newMcpServeCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var transport string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the MCP tool surface over a transport (v1: stdio)",
		Long: "Open the wallet and serve the MCP server until the client disconnects or the\n" +
			"process is signaled (SIGINT/SIGTERM). The same guardrails the CLI enforces\n" +
			"apply identically to MCP-initiated signing (policy runs in the core, below\n" +
			"both frontends).\n\nExamples:\n" +
			"  daxie mcp serve                   # stdio (the default and only v1 transport)\n" +
			"  daxie mcp serve --transport stdio\n\n" +
			"The keystore passphrase is acquired the same way as every signing command\n" +
			"(DAXIE_PASSPHRASE[_FILE]); a long-lived server caches its unlock — restart\n" +
			"after a `keystore change-passphrase` (hot-reload is deliberately unsupported).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Reject http BEFORE opening the service so the unsupported-transport
			// error is fast and side-effect-free (no keystore unlock attempt). The
			// switch is owned by mcpserver.Serve; this is a cheap pre-check that
			// returns the identical domain.Error.
			if transport == "http" {
				return domain.New(domain.CodeUsageUnsupported,
					"the http transport ships in v1.1; v1 serves MCP over --transport stdio only")
			}

			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			srv := mcpserver.New(svc)
			// cmd.Context() carries the SIGINT/SIGTERM cancellation main installs;
			// mcpserver.Serve blocks until the client disconnects or ctx is done.
			return mcpserver.Serve(cmd.Context(), srv, transport)
		},
	}
	cmd.Flags().StringVar(&transport, "transport", "stdio",
		"MCP transport: stdio (v1; http reserved for v1.1)")
	return cmd
}

// newMcpToolsCmd builds `daxie mcp tools [<name>]`.
func newMcpToolsCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "tools [name]",
		Short: "List the MCP tools (or one tool's full schema) — never dials RPC",
		Long: "Print the tool surface a connecting MCP client sees. Default: a compact\n" +
			"TOOL/KIND/DESCRIPTION table with a contract footer. --json emits the exact\n" +
			"tools/list payload (every name, description, inputSchema, outputSchema,\n" +
			"annotations) — the byte-for-byte contract on connect and the golden-snapshot\n" +
			"artifact. A positional <name> prints that one tool's full schema.\n\n" +
			"This command builds the server lazily; it never unlocks the keystore or\n" +
			"dials an RPC endpoint, so it works in any environment.\n\nExamples:\n" +
			"  daxie mcp tools\n" +
			"  daxie mcp tools --json\n" +
			"  daxie mcp tools convert",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Lazy build: mcpserver.New touches no keystore/network, and ListTools
			// introspects over an in-memory pipe. We still open the service so the
			// server is built exactly as `serve` would build it (one assembly path),
			// but no provider is invoked by introspection.
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			srv := mcpserver.New(svc)
			tools, err := mcpserver.ListTools(cmd.Context(), srv)
			if err != nil {
				return err
			}

			m := rs.flags.Mode()
			if len(args) == 1 {
				for _, t := range tools {
					if t.Name == args[0] {
						return render.MCPToolSchema(cmd.OutOrStdout(), m, t)
					}
				}
				return domain.Newf(domain.CodeRefNotFound, "no MCP tool named %q", args[0])
			}
			return render.MCPTools(cmd.OutOrStdout(), m, tools)
		},
	}
}
