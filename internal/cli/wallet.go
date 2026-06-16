package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/service"
	"github.com/spf13/cobra"
)

// wallet.go is the `daxie wallet` command tree (cli-spec §wallet): create,
// import, list, show, rename, export, delete. It is a thin host — it binds
// flags/env/stdin into service request + Input structs, opens the service, and
// renders. Secrets are NEVER flag values; the secret_flags groups select channels
// only and the core resolves the bytes (§3.6).
//
// Exit codes (§5.7) flow through the central mapError funnel: 0 ok; 2 usage
// (collision, confirmation-required without --yes/TTY); 4 auth (bad/missing
// passphrase, first-init confirm mismatch); 10 not-found/read-only; 12 integrity
// (insecure perms). No command sets an exit code directly.

func newWalletCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wallet",
		Short: "Create and manage HD (mnemonic) wallets",
		Long: "Manage BIP-39 HD wallets. A wallet generates accounts at derivation\n" +
			"indexes (m/44'/60'/0'/0/N); name them with `account alias`.\n\n" +
			"Secrets (mnemonic, passphrase) are never flag values — use the\n" +
			"--*-stdin / --*-file channels or the DAXIE_PASSPHRASE[_FILE] env (§3.6).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newWalletCreateCmd(ctx, rs),
		newWalletImportCmd(ctx, rs),
		newWalletListCmd(ctx, rs),
		newWalletShowCmd(ctx, rs),
		newWalletRenameCmd(ctx, rs),
		newWalletExportCmd(ctx, rs),
		newWalletDeleteCmd(ctx, rs),
	)
	return cmd
}

func newWalletCreateCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var words int
	var pf passphraseFlags
	var cf confirmFlags
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new HD wallet (generates a fresh mnemonic, shown ONCE)",
		Long: "Generate a fresh BIP-39 mnemonic, show it ONCE, and encrypt it into the\n" +
			"keystore. RECORD THE MNEMONIC: it is the only backup and is never shown\n" +
			"again. On the first wallet, the keystore passphrase is confirmed by\n" +
			"double-entry (a typo cannot fork the keystore, §3.3).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// §3.5 preflight: refuse a create whose fresh mnemonic could not be shown
			// safely (no TTY and no --yes) BEFORE any secret is written, so we never
			// leave a created-but-undisplayable wallet on disk.
			if err := preflightMnemonicDisplay(rs.flags.Yes); err != nil {
				return err
			}

			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletCreate(cmd.Context(), domain.LocalCLI(),
				domain.WalletCreateRequest{Name: args[0], Words: words, Yes: rs.flags.Yes},
				toWalletCreateInput(pf, cf),
				nil,
			)
			if err != nil {
				return err
			}

			// §3.5 display-once + recorded-it proof. At a TTY without --yes this shows
			// the mnemonic once on stderr, clears the screen, and verifies two random
			// word positions. With --yes the mnemonic is echoed once in the result
			// below; with no TTY and no --yes it refuses (usage.confirmation_required).
			disp, cerr := mnemonicCeremony(cmd.ErrOrStderr(), rs.flags.Yes, res.Mnemonic, res.BIP39Passphrase)
			if cerr != nil {
				return cerr
			}
			if !disp.echoInResult {
				// The mnemonic was already shown once during the interactive ceremony;
				// redact it from the result so it is not repeated (in human OR --json
				// output). The address/id/path remain so the result is still useful.
				res.Mnemonic = ""
				res.BIP39Passphrase = ""
				res.Sensitive = false
			}

			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "wallet %q created (%s)", res.Name, res.WalletID)
				render.Line(w, m, "account %s -> %s", res.Account0, res.Account0Address)
				if disp.echoInResult {
					render.Line(w, m, "")
					render.Line(w, m, "RECORD THIS MNEMONIC — it is shown only once:")
					// The mnemonic is the ESSENTIAL output of the --yes path; print it
					// even under --quiet (it is never shown again). It goes to stdout (not
					// the journal, not a log, §3.10) exactly once.
					_, _ = io.WriteString(w, res.Mnemonic+"\n")
					if res.BIP39Passphrase != "" {
						_, _ = io.WriteString(w, "bip39-passphrase: "+res.BIP39Passphrase+"\n")
					}
				}
			})
		},
	}
	cmd.Flags().IntVar(&words, "words", 12, "mnemonic length: 12 or 24")
	pf.bind(cmd)
	cf.bind(cmd)
	return cmd
}

func newWalletImportCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var pf passphraseFlags
	var cf confirmFlags
	var mf mnemonicFlags
	var bf bip39Flags
	cmd := &cobra.Command{
		Use:   "import <name>",
		Short: "Import an existing BIP-39 mnemonic",
		Long: "Import a BIP-39 mnemonic (NFKD-normalized, checksum-validated). The\n" +
			"mnemonic arrives via --mnemonic-stdin / --mnemonic-file (never a flag\n" +
			"value). An optional BIP-39 passphrase (25th word) via --bip39-passphrase-*.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletImport(cmd.Context(), domain.LocalCLI(),
				domain.WalletImportRequest{Name: args[0], Yes: rs.flags.Yes},
				toWalletImportInput(pf, cf, mf, bf),
				nil,
			)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "wallet %q imported (%s)", res.Name, res.WalletID)
				_, _ = io.WriteString(w, res.Account0+" "+res.Account0Address+"\n")
			})
		},
	}
	pf.bind(cmd)
	cf.bind(cmd)
	mf.bind(cmd)
	bf.bind(cmd)
	return cmd
}

func newWalletListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List wallets (names, account counts, created dates)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletList(cmd.Context(), domain.LocalCLI(), domain.WalletListRequest{})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("NAME", "WALLET_ID", "ACCOUNTS", "CREATED")
				}
				for _, wallet := range res.Wallets {
					tbl.Row(wallet.Name, wallet.WalletID, utoa32(wallet.Accounts), wallet.CreatedAt)
				}
				_ = tbl.Flush()
			})
		},
	}
}

func newWalletShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show a wallet's derivation path, accounts, and aliases",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletShow(cmd.Context(), domain.LocalCLI(), domain.WalletShowRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "wallet %q (%s)", res.Name, res.WalletID)
				render.Line(w, m, "path: %s   next-index: %s", res.PathPrefix, utoa32(int(res.NextIndex)))
				tbl := render.NewTable(w)
				if !m.Quiet {
					tbl.Row("REF", "ADDRESS", "ALIAS")
				}
				for _, a := range res.Accounts {
					tbl.Row(a.Ref, a.Address, a.Alias)
				}
				_ = tbl.Flush()
			})
		},
	}
}

func newWalletRenameCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename a wallet (metadata only; the secret blob is untouched)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletRename(cmd.Context(), domain.LocalCLI(),
				domain.WalletRenameRequest{Old: args[0], New: args[1]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "renamed %q -> %q", res.Old, res.New)
			})
		},
	}
}

func newWalletExportCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var pf passphraseFlags
	cmd := &cobra.Command{
		Use:   "export <name>",
		Short: "Print a wallet's mnemonic (guarded: passphrase + confirm)",
		Long: "Print the wallet mnemonic + BIP-39 passphrase to STDOUT only (never a\n" +
			"file, never the journal, §3.9). Guarded: a freshly-resolved passphrase\n" +
			"plus a confirmation ceremony — at a TTY, type the wallet name; non-\n" +
			"interactively, pass --yes.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := confirmDestructive(cmd, rs, name, "export the mnemonic for"); err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletExport(cmd.Context(), domain.LocalCLI(),
				domain.WalletExportRequest{Name: name, Yes: rs.flags.Yes},
				toWalletExportInput(pf),
			)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				// The mnemonic IS the essential output — printed even under --quiet.
				_, _ = io.WriteString(w, res.Mnemonic+"\n")
				if res.BIP39Passphrase != "" {
					_, _ = io.WriteString(w, "bip39-passphrase: "+res.BIP39Passphrase+"\n")
				}
			})
		},
	}
	pf.bind(cmd)
	return cmd
}

func newWalletDeleteCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a wallet (guarded: confirm or --yes)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := confirmDestructive(cmd, rs, name, "delete wallet"); err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.WalletDelete(cmd.Context(), domain.LocalCLI(),
				domain.WalletDeleteRequest{Name: name, Yes: rs.flags.Yes})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "deleted wallet %q (%s)", res.Name, res.WalletID)
			})
		},
	}
}

// ── flag → service Input projections ─────────────────────────────────────────

func toWalletCreateInput(pf passphraseFlags, cf confirmFlags) service.WalletCreateInput {
	return service.WalletCreateInput{
		PassphraseStdin: pf.stdin, PassphraseFile: pf.file,
		ConfirmStdin: cf.stdin, ConfirmFile: cf.file,
	}
}

func toWalletImportInput(pf passphraseFlags, cf confirmFlags, mf mnemonicFlags, bf bip39Flags) service.WalletImportInput {
	return service.WalletImportInput{
		MnemonicStdin: mf.stdin, MnemonicFile: mf.file,
		BIP39Stdin: bf.stdin, BIP39File: bf.file,
		PassphraseStdin: pf.stdin, PassphraseFile: pf.file,
		ConfirmStdin: cf.stdin, ConfirmFile: cf.file,
	}
}

func toWalletExportInput(pf passphraseFlags) service.WalletExportInput {
	return service.WalletExportInput{PassphraseStdin: pf.stdin, PassphraseFile: pf.file}
}
