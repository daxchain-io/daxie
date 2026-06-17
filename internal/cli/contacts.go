package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// contacts.go is the `daxie contacts` command tree (cli-spec §`daxie contacts`,
// design §7.8): add, list, show, remove. A contact is a network-agnostic
// name→address entry; any `--to` accepts a contact name (resolved in service's
// SendTx pipeline). Thin host over the Contact* use cases; same human + --json +
// §5.7 exit-code discipline as the M1/M2 commands.
//
// Exit codes (§5.7): 0 ok; 2 usage (bad name grammar, duplicate); 10
// ref.not_found (show/remove of an unknown name) / read-only mount.

func newContactsCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contacts",
		Short: "Manage the local address book (name → address)",
		Long: "A contact maps a name to an address, network-agnostic (an address is an\n" +
			"address across EVM chains). Any `--to` accepts a contact name.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newContactsAddCmd(ctx, rs),
		newContactsListCmd(ctx, rs),
		newContactsShowCmd(ctx, rs),
		newContactsRemoveCmd(ctx, rs),
	)
	return cmd
}

func newContactsAddCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "add <name> <address>",
		Short: "Add a name → address contact",
		Long:  "Add a contact. The name follows the account-ref grammar; the address is a\nraw 0x address. A duplicate name is a usage error.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContactAdd(cmd.Context(), domain.LocalCLI(), domain.ContactAddRequest{
				Name:    args[0],
				Address: args[1],
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "added contact %s -> %s", res.Contact.Name, res.Contact.Address)
			})
		},
	}
}

func newContactsListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List contacts (name-sorted)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContactList(cmd.Context(), domain.LocalCLI(), domain.ContactListRequest{})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.ContactsTable(w, m, res.Contacts)
			})
		},
	}
}

func newContactsShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one contact by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContactShow(cmd.Context(), domain.LocalCLI(), domain.ContactShowRequest{Name: args[0]})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Contact(w, m, res.Contact)
			})
		},
	}
}

func newContactsRemoveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a contact by name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := confirmDestructive(cmd, rs, name, "remove contact"); err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContactRemove(cmd.Context(), domain.LocalCLI(), domain.ContactRemoveRequest{Name: name})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "removed contact %s", res.Name)
			})
		},
	}
	return cmd
}
