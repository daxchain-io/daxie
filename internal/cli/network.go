package cli

import (
	"context"
	"io"
	"strconv"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// network.go is the `daxie network` command tree (cli-spec §network): list, add,
// use, show, remove. A NETWORK is a chain (name, chain-id, native symbol) — it is
// strictly separate from an ENDPOINT (`daxie rpc`), §7.5. Thin host over the
// service use cases; same human + --json + §5.7 exit-code discipline as the M1
// commands.

func newNetworkCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Define and select chains (networks)",
		Long: "A network is a chain: name, chain ID, native currency. It says nothing\n" +
			"about HOW to reach the chain — that is an endpoint (`daxie rpc`).\n" +
			"Mainnet and Sepolia are built in.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newNetworkListCmd(ctx, rs),
		newNetworkAddCmd(ctx, rs),
		newNetworkUseCmd(ctx, rs),
		newNetworkShowCmd(ctx, rs),
		newNetworkRemoveCmd(ctx, rs),
	)
	return cmd
}

func newNetworkListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List networks (built-ins + user-added)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.NetworkList(cmd.Context(), domain.LocalCLI(), domain.NetworkListRequest{})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("NAME", "CHAIN-ID", "DEFAULT-RPC", "BUILTIN", "DEFAULT")
				}
				for _, n := range res.Networks {
					tbl.Row(n.Name, strconv.FormatUint(n.ChainID, 10), n.DefaultRPC, mark(n.Builtin), mark(n.Default))
				}
				_ = tbl.Flush()
			})
		},
	}
}

func newNetworkAddCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var chainID uint64
	var rpcURL string
	var legacy bool
	var symbol string
	cmd := &cobra.Command{
		Use:   "add <name> --chain-id <id>",
		Short: "Define a chain",
		Long: "Define a new chain. With --rpc-url, also create an endpoint\n" +
			"\"<name>-default\" bound to it and make that the network's default.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.Flags().Changed("chain-id") {
				return domain.New(domain.CodeUsage+".missing_chain_id", "--chain-id is required")
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.NetworkAdd(cmd.Context(), domain.LocalCLI(), domain.NetworkAddRequest{
				Name:         args[0],
				ChainID:      chainID,
				RPCURL:       rpcURL,
				Legacy:       legacy,
				NativeSymbol: symbol,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "added network %s (chain-id %d)", res.Network.Name, res.Network.ChainID)
				if res.Network.DefaultRPC != "" {
					render.Line(w, m, "default endpoint: %s", res.Network.DefaultRPC)
				}
			})
		},
	}
	cmd.Flags().Uint64Var(&chainID, "chain-id", 0, "the chain's EIP-155 chain ID (required)")
	cmd.Flags().StringVar(&rpcURL, "rpc-url", "", "convenience: also create endpoint \"<name>-default\" at this URL")
	cmd.Flags().BoolVar(&legacy, "legacy", false, "the chain uses legacy (pre-1559) gas pricing")
	cmd.Flags().StringVar(&symbol, "native-symbol", "", "native currency symbol (default ETH)")
	return cmd
}

func newNetworkUseCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Set the default network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.NetworkUse(cmd.Context(), domain.LocalCLI(), domain.NetworkUseRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "default network: %s", res.Network.Name)
			})
		},
	}
}

func newNetworkShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a network's definition",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.NetworkShow(cmd.Context(), domain.LocalCLI(), domain.NetworkShowRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				n := res.Network
				_, _ = io.WriteString(w, n.Name+"\n")
				render.Line(w, m, "chain-id: %d   confirmations: %d", n.ChainID, n.Confirmations)
				if n.DefaultRPC != "" {
					render.Line(w, m, "default-rpc: %s", n.DefaultRPC)
				}
				if n.NativeSymbol != "" {
					render.Line(w, m, "native-symbol: %s", n.NativeSymbol)
				}
				render.Line(w, m, "builtin: %t   default: %t", n.Builtin, n.Default)
			})
		},
	}
}

func newNetworkRemoveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a user network (refuses if endpoints reference it; --force)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := confirmDestructive(cmd, rs, name, "remove network"); err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.NetworkRemove(cmd.Context(), domain.LocalCLI(), domain.NetworkRemoveRequest{
				Name:  name,
				Force: force,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "removed network %s", res.Name)
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "remove even if endpoints still reference the network")
	return cmd
}

// mark renders a boolean column cell as "*" (true) or "" (false) for the human
// tables, matching the account-list convention.
func mark(b bool) string {
	if b {
		return "*"
	}
	return ""
}
