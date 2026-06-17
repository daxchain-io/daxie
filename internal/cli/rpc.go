package cli

import (
	"context"
	"io"
	"strings"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// rpc.go is the `daxie rpc` command tree (cli-spec §rpc): add, list, show, use,
// test, rename, remove. An ENDPOINT is a named connection bound to ONE network;
// many endpoints per network; one default per network; any command overrides per
// invocation with --rpc (§7.5). URLs/headers may embed ${env:}/${file:} secret
// references; the config stores the reference, resolves it in-memory at connect
// time, and `rpc show`/`rpc list` MASK it. `rpc test` connects, verifies
// eth_chainId matches the network, and reports latency. Thin host over the service
// use cases; same human + --json + §5.7 exit-code discipline as the M1 commands.

func newRpcCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rpc",
		Short: "Manage named RPC endpoints",
		Long: "An endpoint is a named connection to a network. Many endpoints per\n" +
			"network; each network has one default, overridable per call with --rpc.\n" +
			"URLs/headers may embed ${env:VAR}/${file:path} secret references —\n" +
			"the config stores the reference, never the resolved secret.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newRpcAddCmd(ctx, rs),
		newRpcListCmd(ctx, rs),
		newRpcShowCmd(ctx, rs),
		newRpcUseCmd(ctx, rs),
		newRpcTestCmd(ctx, rs),
		newRpcRenameCmd(ctx, rs),
		newRpcRemoveCmd(ctx, rs),
	)
	return cmd
}

func newRpcAddCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var network, url string
	var headers []string
	var tlsCert, tlsKey, tlsCA string
	var strictSecrets bool
	cmd := &cobra.Command{
		Use:   "add <name> --network <net> --url <url>",
		Short: "Add a named RPC endpoint",
		Long: "Add a named endpoint bound to a network. The URL and --header values\n" +
			"may embed ${env:VAR}/${file:path} references (stored as references,\n" +
			"resolved at connect time). mTLS via --tls-cert/--tls-key/--tls-ca\n" +
			"(file paths, not secrets). A literal secret in --url/--header warns;\n" +
			"--strict-secrets makes it a hard error.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("network") {
				return domain.New(domain.CodeUsage+".missing_network", "--network is required")
			}
			if !cmd.Flags().Changed("url") {
				return domain.New(domain.CodeUsage+".missing_url", "--url is required")
			}
			hdrs, err := parseHeaders(headers)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.RPCAdd(cmd.Context(), domain.LocalCLI(), domain.RPCAddRequest{
				Name:          args[0],
				Network:       network,
				URL:           url,
				Headers:       hdrs,
				TLSCert:       tlsCert,
				TLSKey:        tlsKey,
				TLSCA:         tlsCA,
				StrictSecrets: strictSecrets,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				// Warnings (the literal-secret heuristic) go to stderr so stdout stays
				// clean; they print even under --quiet (a security signal is essential).
				for _, warn := range res.Warnings {
					_, _ = io.WriteString(cmd.ErrOrStderr(), "warning: "+warn+"\n")
				}
				render.Line(w, m, "added endpoint %s -> network %s (%s)", res.RPC.Name, res.RPC.Network, res.RPC.URL)
			})
		},
	}
	cmd.Flags().StringVar(&network, "network", "", "the network this endpoint reaches (required)")
	cmd.Flags().StringVar(&url, "url", "", "the endpoint URL; may embed ${env:}/${file:} (required)")
	cmd.Flags().StringArrayVar(&headers, "header", nil, "custom header 'Name: Value' (repeatable); value may embed ${env:}/${file:}")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "mTLS client certificate path")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "mTLS client key path (perms-checked)")
	cmd.Flags().StringVar(&tlsCA, "tls-ca", "", "mTLS CA bundle path (default: system roots)")
	cmd.Flags().BoolVar(&strictSecrets, "strict-secrets", false, "reject a literal secret in --url/--header (default: warn)")
	return cmd
}

func newRpcListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var network string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List endpoints (URLs masked)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.RPCList(cmd.Context(), domain.LocalCLI(), domain.RPCListRequest{Network: network})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("NAME", "NETWORK", "URL", "DEFAULT")
				}
				for _, e := range res.RPCs {
					tbl.Row(e.Name, e.Network, e.URL, mark(e.Default))
				}
				_ = tbl.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&network, "network", "", "filter to one network's endpoints")
	return cmd
}

func newRpcShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show an endpoint (secrets masked)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.RPCShow(cmd.Context(), domain.LocalCLI(), domain.RPCShowRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				e := res.RPC
				_, _ = io.WriteString(w, e.Name+"\n")
				render.Line(w, m, "network: %s", e.Network)
				render.Line(w, m, "url: %s", e.URL)
				render.Line(w, m, "headers: %t   tls: %t   default: %t", e.HasHeaders, e.HasTLS, e.Default)
			})
		},
	}
}

func newRpcUseCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Make an endpoint the default for its network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.RPCUse(cmd.Context(), domain.LocalCLI(), domain.RPCUseRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "default endpoint for %s: %s", res.RPC.Network, res.RPC.Name)
			})
		},
	}
}

func newRpcTestCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "test <name>",
		Short: "Connect, verify chain-id, report latency",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.RPCTest(cmd.Context(), domain.LocalCLI(), domain.RPCTestRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "ok: %s reaches %s (chain-id %d) in %dms",
					res.Name, res.Network, res.ChainID, res.LatencyMS)
			})
		},
	}
}

func newRpcRenameCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename an endpoint",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.RPCRename(cmd.Context(), domain.LocalCLI(), domain.RPCRenameRequest{Old: args[0], New: args[1]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "renamed %s -> %s", args[0], res.RPC.Name)
			})
		},
	}
}

func newRpcRemoveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an endpoint",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := confirmDestructive(cmd, rs, name, "remove endpoint"); err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.RPCRemove(cmd.Context(), domain.LocalCLI(), domain.RPCRemoveRequest{Name: name})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "removed endpoint %s", res.Name)
				if res.ClearedAsDefaultFor != "" {
					render.Line(w, m, "(was the default for network %s; now unset)", res.ClearedAsDefaultFor)
				}
			})
		},
	}
	return cmd
}

// parseHeaders splits each "Name: Value" flag into a map. An entry missing the
// colon is a usage error. The value keeps any ${env:}/${file:} reference verbatim
// (resolution is the service/config layer's job at dial time). Leading space after
// the colon is trimmed (so "Authorization: Bearer x" yields "Bearer x").
func parseHeaders(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(raw))
	for _, h := range raw {
		i := strings.IndexByte(h, ':')
		if i < 0 {
			return nil, domain.Newf(domain.CodeUsage+".bad_header",
				"header %q is not in 'Name: Value' form", h)
		}
		name := strings.TrimSpace(h[:i])
		if name == "" {
			return nil, domain.Newf(domain.CodeUsage+".bad_header",
				"header %q has an empty name", h)
		}
		out[name] = strings.TrimSpace(h[i+1:])
	}
	return out, nil
}
