package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// newConvertCmd builds `daxie convert <amount> <to-unit>`.
//
// The amount carries its source unit as a suffix ("1.5eth") or is a bare number
// requiring the suffix form — there is no implicit source unit, since "100"
// alone is ambiguous (the service rejects it as usage). The to-unit is the second
// positional. Agents use this so they never hand-roll 10^18 math (cli-spec §Utility).
//
// Output:
//   - human: the converted value alone on stdout, e.g. `daxie convert 1.5eth wei`
//     prints `1500000000000000000` — a clean scalar a script can capture directly.
//   - --json: the full domain.ConvertResult {input,wei,from,to,value}.
//
// Exit codes: 0 on success; 2 (usage) for a bad unit, missing unit, or
// unparseable amount (all map through usage.convert.* → ExitUsage). convert is
// pure — it opens the service but the use case touches no provider, so it runs in
// any environment.
func newConvertCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "convert <amount> <to-unit>",
		Short: "Convert between eth, gwei, and wei",
		Long: "Convert an amount between Ethereum units. The amount carries its source unit\n" +
			"as a suffix; the second argument is the target unit (eth|gwei|wei).\n\nExamples:\n" +
			"  daxie convert 1.5eth wei          # 1500000000000000000\n" +
			"  daxie convert 30000000000wei gwei # 30\n" +
			"  daxie convert 1eth gwei --json",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.Convert(cmd.Context(), domain.ConvertRequest{
				Amount: args[0],
				To:     args[1],
			})
			if err != nil {
				return err
			}

			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				// Human output is the bare value so `$(daxie convert …)` captures
				// a clean scalar; --quiet has no further effect (the value is the
				// essential output, never suppressed).
				_, _ = io.WriteString(w, res.Value+"\n")
			})
		},
	}
}
