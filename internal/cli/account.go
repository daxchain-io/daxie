package cli

import (
	"context"
	"io"
	"math"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/service"
	"github.com/spf13/cobra"
)

// account.go is the `daxie account` command tree (cli-spec §account): derive,
// alias, unalias, import, use, list, show (incl. --qr), export, delete. Thin host
// over the service use cases; same secret-channel + exit-code discipline as
// wallet.go.

func newAccountCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Derive, alias, import, and manage accounts",
		Long: "Accounts are HD-derived (an index within a wallet) or standalone\n" +
			"(an imported raw key). References: <wallet>/<index>, <wallet>/<alias>,\n" +
			"or <name> for a standalone account.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newAccountDeriveCmd(ctx, rs),
		newAccountAliasCmd(ctx, rs),
		newAccountUnaliasCmd(ctx, rs),
		newAccountImportCmd(ctx, rs),
		newAccountUseCmd(ctx, rs),
		newAccountListCmd(ctx, rs),
		newAccountShowCmd(ctx, rs),
		newAccountExportCmd(ctx, rs),
		newAccountDeleteCmd(ctx, rs),
	)
	return cmd
}

func newAccountDeriveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var index int
	var name string
	var pf passphraseFlags
	cmd := &cobra.Command{
		Use:   "derive <wallet>",
		Short: "Derive an account from an HD wallet (default: next index)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			req := domain.AccountDeriveRequest{Wallet: args[0], Name: name, Yes: rs.flags.Yes}
			if cmd.Flags().Changed("index") {
				if index < 0 || int64(index) > math.MaxUint32 {
					return domain.New("usage.bad_index", "--index must be in [0, 4294967295]")
				}
				idx := uint32(index) // #nosec G115 — bounds-checked above
				req.Index = &idx
			}

			res, err := svc.AccountDerive(cmd.Context(), domain.LocalCLI(), req,
				service.AccountDeriveInput{PassphraseStdin: pf.stdin, PassphraseFile: pf.file}, nil)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				_, _ = io.WriteString(w, res.Ref+" "+res.Address+"\n")
			})
		},
	}
	cmd.Flags().IntVar(&index, "index", 0, "derive a specific index (default: next unused)")
	cmd.Flags().StringVar(&name, "name", "", "alias the derived index in one step")
	pf.bind(cmd)
	return cmd
}

func newAccountAliasCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "alias <wallet/index> <alias>",
		Short: "Name an existing HD index",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.AccountAlias(cmd.Context(), domain.LocalCLI(),
				domain.AccountAliasRequest{Ref: args[0], Alias: args[1]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "aliased %s -> %s (%s)", args[0], res.Alias, res.Address)
			})
		},
	}
}

func newAccountUnaliasCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "unalias <wallet/alias>",
		Short: "Remove an index's alias (the index survives)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.AccountUnalias(cmd.Context(), domain.LocalCLI(),
				domain.AccountUnaliasRequest{Ref: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "removed alias %q from %s/%s", res.RemovedAlias, res.Wallet, utoa32(int(res.Index)))
			})
		},
	}
}

func newAccountImportCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var pf passphraseFlags
	var cf confirmFlags
	var kf keyFlags
	cmd := &cobra.Command{
		Use:   "import <name>",
		Short: "Import a standalone account from a raw private key",
		Long: "Import a raw 32-byte hex private key as a named standalone account\n" +
			"(stored as a stock geth v3 file). The key arrives via --key-stdin /\n" +
			"--key-file (never a flag value).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.AccountImport(cmd.Context(), domain.LocalCLI(),
				domain.AccountImportRequest{Name: args[0], Yes: rs.flags.Yes},
				service.AccountImportInput{
					KeyStdin: kf.stdin, KeyFile: kf.file,
					PassphraseStdin: pf.stdin, PassphraseFile: pf.file,
					ConfirmStdin: cf.stdin, ConfirmFile: cf.file,
				}, nil)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				_, _ = io.WriteString(w, res.Name+" "+res.Address+"\n")
			})
		},
	}
	pf.bind(cmd)
	cf.bind(cmd)
	kf.bind(cmd)
	return cmd
}

func newAccountUseCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "use <ref>",
		Short: "Set the default account (--from/--account become optional)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.AccountUse(cmd.Context(), domain.LocalCLI(),
				domain.AccountUseRequest{Ref: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "default account: %s (%s)", res.Ref, res.Address)
			})
		},
	}
}

func newAccountListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wallet string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all accounts (HD + standalone)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.AccountList(cmd.Context(), domain.LocalCLI(),
				domain.AccountListRequest{Wallet: wallet})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("REF", "ADDRESS", "KIND", "DEFAULT")
				}
				for _, a := range res.Accounts {
					def := ""
					if a.Default {
						def = "*"
					}
					tbl.Row(a.Ref, a.Address, a.Kind, def)
				}
				_ = tbl.Flush()
			})
		},
	}
	cmd.Flags().StringVar(&wallet, "wallet", "", "filter to one wallet's accounts")
	return cmd
}

func newAccountShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var qr bool
	cmd := &cobra.Command{
		Use:   "show <ref>",
		Short: "Show an account's address and path (optionally as a QR)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.AccountShow(cmd.Context(), domain.LocalCLI(),
				domain.AccountShowRequest{Ref: args[0], QR: qr})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				// The address is the ESSENTIAL output (printed even under --quiet); the
				// QR block is decoration suppressed by --quiet (§5.9 essential rule).
				_, _ = io.WriteString(w, res.Address+"\n")
				render.Line(w, m, "ref: %s   kind: %s", res.Ref, res.Kind)
				if res.Path != "" {
					render.Line(w, m, "path: %s", res.Path)
				}
				if qr {
					render.QR(w, m, res.Address)
				}
			})
		},
	}
	cmd.Flags().BoolVar(&qr, "qr", false, "render the address as a terminal QR code")
	return cmd
}

func newAccountExportCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var pf passphraseFlags
	cmd := &cobra.Command{
		Use:   "export <ref>",
		Short: "Print a standalone account's private key (guarded)",
		Long: "Print a standalone account's raw private key to STDOUT only (§3.9).\n" +
			"HD accounts cannot export here — export the wallet mnemonic instead.\n" +
			"Guarded: a freshly-resolved passphrase plus a confirmation ceremony.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			if err := confirmDestructive(cmd, rs, ref, "export the private key for"); err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.AccountExport(cmd.Context(), domain.LocalCLI(),
				domain.AccountExportRequest{Ref: ref, Yes: rs.flags.Yes},
				service.AccountExportInput{PassphraseStdin: pf.stdin, PassphraseFile: pf.file})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				// The private key IS the essential output — printed even under --quiet.
				_, _ = io.WriteString(w, res.PrivateKey+"\n")
			})
		},
	}
	pf.bind(cmd)
	return cmd
}

func newAccountDeleteCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <ref>",
		Short: "Delete an account (HD: forget the index; standalone: remove the key)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ref := args[0]
			if err := confirmDestructive(cmd, rs, ref, "delete account"); err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.AccountDelete(cmd.Context(), domain.LocalCLI(),
				domain.AccountDeleteRequest{Ref: ref, Yes: rs.flags.Yes})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "%s account %q (%s)", res.Mode, res.Ref, deletedWord(res.Deleted))
			})
		},
	}
	return cmd
}

func deletedWord(b bool) string {
	if b {
		return "deleted"
	}
	return "not deleted"
}
