package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// balance.go is the `daxie balance` command (cli-spec §balance): the read-only ETH
// balance of an account or raw address. With no arg it reads the default account
// (§7.7). The network is the global --network; the endpoint is the global --rpc
// override (§2.8). --token (ERC-20) and --all (the local registry) are M5 and an
// ENS arg is M7: the flags are PLUMBED here but the service rejects those paths
// cleanly with usage.unsupported — never faked. Thin host over svc.Balance; same
// human + --json + §5.7 exit-code discipline as the M1 commands.

func newBalanceCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var token string
	var all bool
	cmd := &cobra.Command{
		Use:   "balance [<account-or-address>]",
		Short: "Show the ETH balance of an account or address (read-only)",
		Long: "Show the native ETH balance. With no argument, the default account is\n" +
			"used. A raw 0x address, a keystore account ref (wallet/index,\n" +
			"wallet/alias, name) all work. The --network selects the chain and\n" +
			"--rpc overrides the endpoint per call. (--token/--all land in M5; an\n" +
			"ENS name lands in M7.)",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			req := domain.BalanceRequest{
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
				Token:   token,
				All:     all,
			}
			if len(args) == 1 {
				req.Account = args[0]
			}

			res, err := svc.Balance(cmd.Context(), domain.LocalCLI(), req, nil)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				// The balance IS the essential output (printed even under --quiet); the
				// address/network context is non-essential chatter via render.Line.
				_, _ = io.WriteString(w, res.Eth+" "+res.Symbol+"\n")
				render.Line(w, m, "address: %s   network: %s", res.Address, res.Network)
				render.Line(w, m, "wei: %s", res.Wei)
			})
		},
	}
	// M5 flags: plumbed so the surface is stable, but the service fails clean.
	cmd.Flags().StringVar(&token, "token", "", "M5: ERC-20 balance by alias or contract address")
	cmd.Flags().BoolVar(&all, "all", false, "M5: ETH + every token in the local registry")
	return cmd
}
