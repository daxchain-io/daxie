package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// gas.go is the `daxie gas` command (cli-spec §`daxie gas`, design §5.4): the
// read-only current base fee + slow/normal/fast fee suggestions. It signs nothing
// and touches no policy (a pure read, like `balance`) — a thin host over
// svc.Gas. The same gas engine (eth_feeHistory(20,latest,[25,50,90]) folded by
// chain.SuggestFees, maxFee = base-fee-multiplier × nextBaseFee + tip) powers
// both `daxie gas` and the `tx send` build path, so the displayed quote matches
// what a send would actually use.

func newGasCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var speed string
	var legacy bool
	cmd := &cobra.Command{
		Use:   "gas",
		Short: "Show the current base fee + slow/normal/fast fee suggestions",
		Long: "Read the chain's current base fee and the EIP-1559 priority-fee\n" +
			"percentiles for slow/normal/fast. --legacy shows a single gas-price\n" +
			"suggestion per speed for pre-1559 chains.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.Gas(cmd.Context(), domain.LocalCLI(), domain.GasRequest{
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
				Speed:   speed,
				Legacy:  legacy,
			}, nil)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.GasQuotes(w, m, res)
			})
		},
	}
	cmd.Flags().StringVar(&speed, "speed", "", "mark which suggestion is the selected default: slow|normal|fast")
	cmd.Flags().BoolVar(&legacy, "legacy", false, "show legacy (pre-1559) gas-price suggestions")
	return cmd
}
