package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// balance.go is the `daxie balance` command (cli-spec §balance): the read-only
// balance of an account or raw address. With no arg it reads the default account
// (§7.7). The network is the global --network; the endpoint is the global --rpc
// override (§2.8). --token reads a single ERC-20 balance (by registry alias or 0x
// contract — alias resolution is registry-only); --all reads ETH + every registry
// token the account holds a nonzero balance of. An ENS arg is M7 (fails clean).
// Thin host over svc.Balance; same human + --json + §5.7 exit-code discipline.

func newBalanceCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var token string
	var all bool
	cmd := &cobra.Command{
		Use:   "balance [<account-or-address>]",
		Short: "Show the ETH or token balance of an account or address (read-only)",
		Long: "Show a balance. With no argument, the default account is used. A raw 0x\n" +
			"address, a keystore account ref (wallet/index, wallet/alias, name) all work.\n" +
			"--token <alias|0x> reads a single ERC-20 balance (aliases resolve\n" +
			"registry-only — a name not registered, and not a bundled major, is an\n" +
			"error). --all reads ETH plus every registry token with a nonzero balance.\n" +
			"The --network selects the chain and --rpc overrides the endpoint per call.\n" +
			"(An ENS name lands in M7.)",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if token != "" && all {
				return domain.New(domain.CodeUsage+".bad_flags", "--token and --all are mutually exclusive")
			}
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
				switch {
				case res.Token != nil:
					render.BalanceToken(w, m, res)
				case all:
					render.BalanceAll(w, m, res)
				default:
					// The ETH balance IS the essential output (printed even under --quiet);
					// the address/network context is non-essential chatter via render.Line.
					_, _ = io.WriteString(w, res.Eth+" "+res.Symbol+"\n")
					render.Line(w, m, "address: %s   network: %s", res.Address, res.Network)
					render.Line(w, m, "wei: %s", res.Wei)
				}
			})
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "ERC-20 balance by registry alias or 0x contract address")
	cmd.Flags().BoolVar(&all, "all", false, "ETH + every registry token with a nonzero balance")
	return cmd
}
