package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/spf13/cobra"
)

// newConfigCmd builds `daxie config get|set|list`.
//
// These are Viper-backed operator settings (cli-spec §Utility). policy.* keys are
// OUT OF SCOPE: spend limits/allowlist live in the sealed policy file and are set
// only via `daxie policy …` (admin passphrase); `config set policy.max-tx` is
// rejected with a usage error. The five path vars are never listed (§7.3).
//
// Exit codes (per §5.7): 0 ok; 2 (usage) for a rejected policy.* set or bad args;
// 10 (ref.not_found) for an unknown key on get; 10 (config.read_only) for a set
// against a read-only config mount.
func newConfigCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Get, set, and list operator config keys",
		Long: "Inspect and modify operator settings in config.toml.\n\n" +
			"Policy keys (spend limits, allowlists) are NOT managed here — they live in\n" +
			"the sealed policy file, set only via `daxie policy` with the admin passphrase.\n" +
			"`config set policy.<key>` is rejected.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newConfigListCmd(ctx, rs),
		newConfigGetCmd(ctx, rs),
		newConfigSetCmd(ctx, rs),
	)
	return cmd
}

func newConfigListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all operator config keys with their effective values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			kvs := svc.ConfigList(cmd.Context())
			m := rs.flags.Mode()
			// --json emits an array of {key,value,source} objects.
			return render.Result(cmd.OutOrStdout(), m, kvs, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("KEY", "VALUE", "SOURCE")
				}
				for _, kv := range kvs {
					tbl.Row(kv.Key, kv.Value, kv.Source)
				}
				_ = tbl.Flush()
			})
		},
	}
}

func newConfigGetCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Print one config key's effective value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			val, err := svc.ConfigGet(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			// --json emits a single {key,value} object; human prints the bare value.
			return render.Result(cmd.OutOrStdout(), m, jsonGet{Key: args[0], Value: val}, func(w io.Writer) {
				_, _ = io.WriteString(w, val+"\n")
			})
		},
	}
}

// jsonGet is the --json shape for `config get` — a single key/value object,
// deliberately distinct from the list KV (no Source field on a direct get).
type jsonGet struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func newConfigSetCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set one config key (targeted config.toml rewrite)",
		Long: "Write one operator key into config.toml via an atomic targeted rewrite.\n\n" +
			"policy.* keys are rejected (use `daxie policy`). A read-only config mount\n" +
			"fails with config.read_only (exit 10).",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			key, value := args[0], args[1]
			if err := svc.ConfigSet(cmd.Context(), key, value); err != nil {
				return err
			}
			m := rs.flags.Mode()
			res := jsonGet{Key: key, Value: value}
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "set %s = %s", key, value)
			})
		},
	}
}
