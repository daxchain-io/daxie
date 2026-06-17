package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// ens.go is the `daxie ens` command tree (cli-spec §`daxie ens`, design §2.8/§4.8):
// resolve (name → address) and reverse (address → primary name, forward-verified).
// Resolution is per-invocation against the connected network's ENS registry — the
// --network selects the chain and --rpc overrides the endpoint per call (§2.8), so
// the same name resolves independently on mainnet vs Sepolia. The resolved address
// is the load-bearing output: an agent/human must see what a name actually points to
// before trusting it (the same address the send path echoes via EvResolved before
// signing). Thin host over svc.EnsResolve/EnsReverse; same human + --json + §5.7
// exit-code discipline.
//
// Exit codes (§5.7): 0 ok; 2 usage (bad ENS shape / no registry on this network);
// 6 rpc.* (resolution transport failure); 10 ref.not_found (a name that does not
// resolve where a destination/read was required).
//
// ENS is also accepted WHEREVER a destination or read-only address is — `tx send
// --to vitalik.eth`, `nft send --to`, `token` transfers, `approve --spender`,
// `balance vitalik.eth`, `policy allow vitalik.eth` (pins name+address at allow
// time), `contacts add <name> vitalik.eth` — all route through service's
// resolveDest / ParseAccountRef without a new flag here.

func newEnsCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ens",
		Short: "Resolve ENS names against the connected network",
		Long: "ENS forward/reverse resolution. Resolution is per-invocation against the\n" +
			"--network's ENS registry (--rpc overrides the endpoint). A reverse name is\n" +
			"only trusted when it forward-resolves back to the address (forward-verified).\n" +
			"ENS names are also accepted directly as a `--to` destination, a `balance`\n" +
			"target, a `policy allow` pin, and a `contacts add` address.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newEnsResolveCmd(ctx, rs),
		newEnsReverseCmd(ctx, rs),
	)
	return cmd
}

func newEnsResolveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "resolve <name>",
		Short: "Forward-resolve an ENS name to its address",
		Long: "Resolve an ENS name (e.g. vitalik.eth) to its 0x address on the selected\n" +
			"network. An unresolved name is ref.not_found (exit 10); a network with no\n" +
			"ENS registry is usage (exit 2).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.EnsResolve(cmd.Context(), domain.LocalCLI(), domain.EnsResolveRequest{
				Name:    args[0],
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
			}, sink)
			if err != nil {
				return err
			}
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				// The address IS the essential output (printed even under --quiet); the
				// name/network context is non-essential chatter via render.Line.
				_, _ = io.WriteString(w, res.Address+"\n")
				render.Line(w, m, "%s -> %s   network: %s", res.Name, res.Address, res.Network)
			})
		},
	}
}

func newEnsReverseCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "reverse <address>",
		Short: "Reverse-resolve an address to its primary ENS name (forward-verified)",
		Long: "Reverse-resolve a 0x address to its primary ENS name on the selected\n" +
			"network. The name is FORWARD-VERIFIED: it is only returned when it\n" +
			"forward-resolves back to the address. An address with no trusted primary\n" +
			"name prints \"(no primary name)\".",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.EnsReverse(cmd.Context(), domain.LocalCLI(), domain.EnsReverseRequest{
				Address: args[0],
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
			}, sink)
			if err != nil {
				return err
			}
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				if res.Verified && res.Name != "" {
					_, _ = io.WriteString(w, res.Name+"\n")
					render.Line(w, m, "%s -> %s (verified)   network: %s", res.Address, res.Name, res.Network)
				} else {
					_, _ = io.WriteString(w, "(no primary name)\n")
					render.Line(w, m, "%s has no verified primary name   network: %s", res.Address, res.Network)
				}
			})
		},
	}
}
