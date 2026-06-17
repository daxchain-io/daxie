package cli

import (
	"context"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// txrbf.go is the `daxie tx speedup` + `daxie tx cancel` hosts (cli-spec §`daxie
// tx`, design §5.5 replace-by-fee). Both rebuild a pending Daxie-originated tx at
// bumped fees on the SAME nonce: speedup rebuilds the identical intent, cancel
// replaces with a 0-value self-send (to=from, gas 21000). The service
// reconstructs the original intent from the journal record (the cli passes only
// the hash + optional fee overrides) and routes through the identical authorize →
// broadcast → settle path SendTx uses (§2.7) — so RBF cannot route around policy.
//
// Exit codes (§5.7): 0 ok; 9 tx.replaced/already_mined/replacement_underpriced
// (an override below the +12.5% bump floor); 10 ref.not_found (a foreign/unknown
// hash); 3 policy.denied.gas_cap (a bump above policy.max-gas-price). RBF counts
// only the positive gas delta against the spend limit (value is not re-counted).

// rbfFeeFlags is the fee-override group for speedup/cancel. Unlike `tx send`'s
// gasFlags there is NO --gas-limit/--legacy/--nonce: the limit + nonce come from
// the original record, and legacy-ness is inherited. Only the fee knobs may be
// overridden above the bump floor.
type rbfFeeFlags struct {
	maxFee      string
	priorityFee string
	gasPrice    string
	speed       string
}

func (f *rbfFeeFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.maxFee, "max-fee", "", "override the bumped EIP-1559 max fee per gas (must clear the +12.5% floor)")
	fl.StringVar(&f.priorityFee, "priority-fee", "", "override the bumped EIP-1559 max priority fee per gas")
	fl.StringVar(&f.gasPrice, "gas-price", "", "override the bumped legacy gas price")
	fl.StringVar(&f.speed, "speed", "", "re-quote at this speed before applying the bump floor")
}

func newTxSpeedupCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var f rbfFeeFlags
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "speedup <txhash>",
		Short: "Rebroadcast a stuck tx with bumped fees (replace-by-fee)",
		Long: "Rebuild the identical pending transaction at higher fees on the same\n" +
			"nonce (≥ +12.5% per protocol rules, or higher via --max-fee). Critical for\n" +
			"agents: one underpriced tx blocks every later nonce. Only the positive gas\n" +
			"delta counts against the spend limit.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := wf.toWaitOpts(cmd)
			if err != nil {
				return err
			}
			req := domain.SpeedupRequest{
				Hash:        args[0],
				MaxFee:      f.maxFee,
				PriorityFee: f.priorityFee,
				GasPrice:    f.gasPrice,
				Speed:       f.speed,
				Network:     rs.flags.Network,
				RPC:         rs.flags.RPC,
				Yes:         rs.flags.Yes, // TTY-skip only (json:"-")
				Wait:        w,
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.Speedup(cmd.Context(), domain.LocalCLI(), req, sink)
			// §5.3/§5.9: a --wait that times out/reverts/replaces still emits the one
			// final object (incl. the replaces cross-link) on stdout, then exits.
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	f.bind(cmd)
	wf.bind(cmd)
	return cmd
}

func newTxCancelCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var f rbfFeeFlags
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "cancel <txhash>",
		Short: "Replace a pending tx with a 0-value self-send at higher fee",
		Long: "Cancel a stuck transaction by replacing it (same nonce) with a 0-value\n" +
			"self-send at 21000 gas and bumped fees. The original flips to replaced.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := wf.toWaitOpts(cmd)
			if err != nil {
				return err
			}
			req := domain.CancelRequest{
				Hash:        args[0],
				MaxFee:      f.maxFee,
				PriorityFee: f.priorityFee,
				GasPrice:    f.gasPrice,
				Speed:       f.speed,
				Network:     rs.flags.Network,
				RPC:         rs.flags.RPC,
				Yes:         rs.flags.Yes, // TTY-skip only (json:"-")
				Wait:        w,
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.Cancel(cmd.Context(), domain.LocalCLI(), req, sink)
			// §5.3/§5.9: a --wait that times out/reverts/replaces still emits the one
			// final object (incl. the replaces cross-link) on stdout, then exits.
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	f.bind(cmd)
	wf.bind(cmd)
	return cmd
}
