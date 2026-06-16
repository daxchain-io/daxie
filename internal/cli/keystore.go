package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/service"
	"github.com/spf13/cobra"
)

// keystore.go is the `daxie keystore` command tree (cli-spec §keystore):
// change-passphrase and info. change-passphrase is CLI-only administration (no
// MCP tool, §3.9) and re-encrypts the whole keystore atomically (§3.8).

func newKeystoreCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keystore",
		Short: "Keystore maintenance (re-encrypt, info)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newKeystoreChangePassphraseCmd(ctx, rs),
		newKeystoreInfoCmd(ctx, rs),
	)
	return cmd
}

func newKeystoreChangePassphraseCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var pf passphraseFlags // the OLD passphrase (--passphrase-*)
	var nf newPassphraseFlags
	cmd := &cobra.Command{
		Use:   "change-passphrase",
		Short: "Re-encrypt the keystore under a new passphrase (atomic)",
		Long: "Re-encrypt every keystore file (verifier, wallet blobs, standalone keys)\n" +
			"under a new passphrase. The rotation is atomic and crash-safe (§3.8): a\n" +
			"crash leaves the all-old or all-new keystore, never a mix.\n\n" +
			"Old passphrase: --passphrase-* / DAXIE_PASSPHRASE[_FILE].\n" +
			"New passphrase: --new-passphrase-* / DAXIE_NEW_PASSPHRASE[_FILE].\n\n" +
			"NOTE: rotating under a running `mcp serve` requires restarting it (§3.8).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.KeystoreChangePassphrase(cmd.Context(), domain.LocalCLI(),
				domain.KeystoreChangePassphraseRequest{Yes: rs.flags.Yes},
				service.KeystoreChangePassphraseInput{
					OldStdin: pf.stdin, OldFile: pf.file,
					NewStdin: nf.stdin, NewFile: nf.file,
					NewConfirmStdin: nf.confirmStdin, NewConfirmFile: nf.confirmFile,
				}, nil)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "keystore re-encrypted: %s file(s) rotated", utoa32(res.RotatedFiles))
			})
		},
	}
	pf.bind(cmd)
	nf.bind(cmd)
	return cmd
}

func newKeystoreInfoCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show keystore path, format, and wallet/account counts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.KeystoreInfo(cmd.Context(), domain.LocalCLI())
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				tbl.Row("path", res.Path)
				tbl.Row("format", utoa32(res.Format))
				tbl.Row("initialized", boolWord(res.Initialized))
				tbl.Row("wallets", utoa32(res.Wallets))
				tbl.Row("hd-accounts", utoa32(res.HDAccounts))
				tbl.Row("standalone", utoa32(res.Accounts))
				tbl.Row("kdf", res.KDF)
				tbl.Row("scrypt-n", utoa32(res.ScryptN))
				_ = tbl.Flush()
			})
		},
	}
}

func boolWord(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
