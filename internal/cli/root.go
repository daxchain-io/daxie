// Package cli is Frontend 1: the Cobra command tree. It is a thin host — it
// parses flags/env/stdin into service request structs, opens the service, and
// renders results. It imports ONLY service, domain, version, ethunit (output),
// and its own render subpackage — never a provider (the arch matrix enforces
// this as a failing test). Business logic physically cannot live here.
//
// One file per noun; M0 shipped version/completion/config/convert, M1 adds
// wallet/account/keystore, M2 adds network/rpc/balance, and M3 adds tx (send/
// status/wait/list + speedup/cancel), gas, and contacts.
package cli

import (
	"context"

	"github.com/spf13/cobra"
)

// flags is the single FlagValues the root binds and every command reads through
// the *cobra.Command's context. It is created per Execute call (no global state).
type rootState struct {
	flags FlagValues
}

// newRootCmd builds the root command tree with all global persistent flags bound
// onto rs.flags. The caller (Execute) runs it. SilenceErrors/SilenceUsage are
// set so the central registry in render.go owns all error→exit mapping (§5.7);
// Cobra never prints an error itself.
func newRootCmd(ctx context.Context, rs *rootState) *cobra.Command {
	root := &cobra.Command{
		Use:   "daxie",
		Short: "Daxie — the Ethereum wallet for AI",
		Long: "Daxie is an agent-first Ethereum CLI wallet: non-interactive flags/env/stdin,\n" +
			"--json output, deterministic exit codes, and a built-in MCP server.",
		SilenceErrors: true, // the §5.7 registry in render.go prints errors, not Cobra
		SilenceUsage:  true, // usage on error is noise for agents; --help still works
		// Cobra's default completion command would shadow our explicit one; we
		// install our own (cli/completion.go) and disable the built-in so its
		// flags/behavior match the documented surface exactly.
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		// No Run on the root: bare `daxie` prints help and exits non-zero usage.
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	root.SetFlagErrorFunc(flagErrorFunc)

	pf := root.PersistentFlags()
	pf.BoolVar(&rs.flags.JSON, "json", false, "machine-readable JSON output")
	pf.BoolVar(&rs.flags.Quiet, "quiet", false, "suppress non-essential human output")
	pf.StringVar(&rs.flags.Network, "network", "", "network (chain) name; overrides the configured default")
	pf.StringVar(&rs.flags.RPC, "rpc", "", "RPC endpoint name; overrides the network's default endpoint for this call")
	pf.StringVar(&rs.flags.Config, "config", "", "config file or directory (default: platform XDG path)")
	pf.StringVar(&rs.flags.Keystore, "keystore", "", "keystore directory (default: platform data path)")
	pf.StringVar(&rs.flags.StateDir, "state-dir", "", "mutable state directory (default: platform state path)")
	pf.BoolVarP(&rs.flags.Yes, "yes", "y", false, "skip confirmations; required for mutating ops when non-interactive")

	root.AddCommand(
		newVersionCmd(rs),
		newCompletionCmd(),
		newConfigCmd(ctx, rs),
		newConvertCmd(ctx, rs),
		newWalletCmd(ctx, rs),   // M1
		newAccountCmd(ctx, rs),  // M1
		newKeystoreCmd(ctx, rs), // M1
		newNetworkCmd(ctx, rs),  // M2
		newRpcCmd(ctx, rs),      // M2
		newBalanceCmd(ctx, rs),  // M2
		newTxCmd(ctx, rs),       // M3
		newGasCmd(ctx, rs),      // M3
		newContactsCmd(ctx, rs), // M3
		newPolicyCmd(ctx, rs),   // M4
	)

	return root
}
