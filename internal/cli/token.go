package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// token.go is the `daxie token` command tree (cli-spec §`daxie token`, design
// §2.8/§4.2/§7.8): the token registry (info/add/rename/list/remove) and the ERC-20
// approval surface (approve/allowance/revoke). A token is named by a REGISTRY ALIAS
// or a raw 0x contract — resolution is registry-only for an alias (a miss is an
// error, never an on-chain symbol() lookup; the anti-spoofing property). The
// transfer path is `tx send --token` (tx.go); this file owns registry mgmt +
// approvals.
//
// Thin host: it binds flags into the domain request structs, opens the service,
// wires the §5.9 stderr-progress sink for the broadcasting approve/revoke, and
// renders the single result. All signing-side logic (the spend-equivalent gates,
// the policy chokepoint) lives in service.
//
// Exit codes (§5.7): 0 ok; 2 usage (bad alias/address, --unlimited without --yes,
// --unlimited with --amount, duplicate alias requiring --name); 3 policy.denied
// (allowlist / fail-closed-no-allowlist / unlimited_unacked); 10 ref.not_found
// (unknown alias) / read-only mount; plus the #19 broadcasting outcomes on
// approve/revoke --wait: 7 reverted, 8 timeout (resumable), 9 replaced/conflict.

func newTokenCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage the local token registry and ERC-20 approvals",
		Long: "A token is named by a registry alias or a 0x contract address. Aliases are\n" +
			"per-network and resolved registry-only (a name not registered — and not a\n" +
			"compiled-in major like usdc/usdt/weth/dai — is an error, never an on-chain\n" +
			"symbol() lookup; symbol spoofing is free). Use `token add` to register one,\n" +
			"`tx send --token` to transfer, and `token approve/allowance/revoke` for\n" +
			"ERC-20 allowances (spend-equivalents — governed by the same policy gates).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newTokenInfoCmd(ctx, rs),
		newTokenAddCmd(ctx, rs),
		newTokenRenameCmd(ctx, rs),
		newTokenListCmd(ctx, rs),
		newTokenRemoveCmd(ctx, rs),
		newTokenApproveCmd(ctx, rs),
		newTokenAllowanceCmd(ctx, rs),
		newTokenRevokeCmd(ctx, rs),
	)
	return cmd
}

// ── registry: info / add / rename / list / remove ────────────────────────────

func newTokenInfoCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "info <alias|0x>",
		Short: "Read a token's on-chain metadata (symbol/decimals); does not register",
		Long: "Read the on-chain symbol/decimals + kind for a token, by registry alias or\n" +
			"raw 0x contract. This does NOT register the token; the symbol shown is for\n" +
			"display only and is never used to resolve an alias.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.TokenInfo(cmd.Context(), domain.LocalCLI(), domain.TokenInfoRequest{
				Token:   args[0],
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
			}, nil)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.TokenInfo(w, m, res)
			})
		},
	}
}

func newTokenAddCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "add <0x> [--name <alias>]",
		Short: "Register a token alias → contract on the current network",
		Long: "Register a token by its 0x contract address. The alias defaults to the\n" +
			"case-folded on-chain symbol; override it with --name. A collision with an\n" +
			"existing alias or a bundled major requires a different --name. The kind and\n" +
			"decimals are detected on-chain and stored.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.TokenAdd(cmd.Context(), domain.LocalCLI(), domain.TokenAddRequest{
				Contract: args[0],
				Name:     name,
				Network:  rs.flags.Network,
				RPC:      rs.flags.RPC,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "added token %s -> %s on %s", res.Token.Alias, res.Token.Contract, res.Token.Network)
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "alias for the token (default: the case-folded on-chain symbol)")
	return cmd
}

func newTokenRenameCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename a registered token alias",
		Long:  "Rename a file-backed token alias. A bundled major cannot be renamed in place\n(add it under the new alias instead, which overrides the bundled one).",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.TokenRename(cmd.Context(), domain.LocalCLI(), domain.TokenRenameRequest{
				Old:     args[0],
				New:     args[1],
				Network: rs.flags.Network,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "renamed token %s -> %s", args[0], res.Token.Alias)
			})
		},
	}
}

func newTokenListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered + bundled tokens for the network (alias-sorted)",
		Long:  "List the merged token set: compiled-in majors (usdc/usdt/weth/dai) overlaid\nby your registered tokens, marked by provenance.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.TokenList(cmd.Context(), domain.LocalCLI(), domain.TokenListRequest{
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.TokenList(w, m, res)
			})
		},
	}
}

func newTokenRemoveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <alias>",
		Short: "Remove a registered token alias",
		Long:  "Remove a file-backed token alias. A bundled major cannot be removed (it is\ncompiled in).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := confirmDestructive(cmd, rs, args[0], "remove token"); err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.TokenRemove(cmd.Context(), domain.LocalCLI(), domain.TokenRemoveRequest{
				Alias:   args[0],
				Network: rs.flags.Network,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "removed token %s", res.Alias)
			})
		},
	}
}

// ── approvals: approve / allowance / revoke ──────────────────────────────────

func newTokenApproveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var from, spender, amount string
	var unlimited bool
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "approve <token> --spender <addr|contact> [--amount N | --unlimited]",
		Short: "Approve a spender to move your tokens (a spend-equivalent)",
		Long: "Build, sign, and broadcast an ERC-20 approve(spender, amount). The spender\n" +
			"is the policy subject (the allowlist + fail-closed-no-allowlist rules apply\n" +
			"to it, not the token contract). --unlimited grants an infinite allowance and\n" +
			"REQUIRES --yes (the unlimited acknowledgement ceremony). --wait blocks for\n" +
			"confirmations. (--token is the first positional arg: an alias or 0x contract.)",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if spender == "" {
				return domain.New(domain.CodeUsage+".missing_spender", "--spender is required")
			}
			if unlimited && amount != "" {
				return domain.New(domain.CodeUsage+".bad_amount", "--unlimited and --amount are mutually exclusive")
			}
			if !unlimited && amount == "" {
				return domain.New(domain.CodeUsage+".missing_amount", "--amount is required (or use --unlimited)")
			}
			// The unlimited acknowledgement ceremony (§4.2): an infinite approval needs
			// the explicit --yes. Refuse early with a clear usage error so the agent
			// learns the requirement without burning a signing attempt. (The service +
			// policy enforce it again — defense in depth.)
			if unlimited && !rs.flags.Yes {
				return domain.New(domain.CodeUsage+".unlimited_unacked",
					"--unlimited grants an infinite allowance; re-run with --yes to acknowledge")
			}
			w, err := wf.toWaitOpts(cmd)
			if err != nil {
				return err
			}
			req := domain.ApproveRequest{
				Token:     args[0],
				Spender:   spender,
				Amount:    amount,
				Unlimited: unlimited,
				From:      resolveFrom(rs, from),
				Network:   rs.flags.Network,
				RPC:       rs.flags.RPC,
				Confirm:   rs.flags.Yes,
				Yes:       rs.flags.Yes,
				Wait:      w,
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.TokenApprove(cmd.Context(), domain.LocalCLI(), req, sink)
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "approving account ref (default: the configured default account)")
	cmd.Flags().StringVar(&spender, "spender", "", "the spender to approve: a 0x address or a contact name (required)")
	cmd.Flags().StringVar(&amount, "amount", "", "allowance amount in token units, e.g. 100 (or use --unlimited)")
	cmd.Flags().BoolVar(&unlimited, "unlimited", false, "grant an infinite allowance (requires --yes)")
	wf.bind(cmd)
	return cmd
}

func newTokenRevokeCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var from, spender string
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "revoke <token> --spender <addr|contact>",
		Short: "Revoke a spender's allowance (approve spender 0)",
		Long: "Set a spender's allowance to zero: an ERC-20 approve(spender, 0). The same\n" +
			"spend-equivalent path as `token approve`, governed by the same policy gates.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if spender == "" {
				return domain.New(domain.CodeUsage+".missing_spender", "--spender is required")
			}
			w, err := wf.toWaitOpts(cmd)
			if err != nil {
				return err
			}
			req := domain.ApproveRequest{
				Token:   args[0],
				Spender: spender,
				From:    resolveFrom(rs, from),
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
				Confirm: rs.flags.Yes,
				Yes:     rs.flags.Yes,
				Wait:    w,
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.TokenRevoke(cmd.Context(), domain.LocalCLI(), req, sink)
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "approving account ref (default: the configured default account)")
	cmd.Flags().StringVar(&spender, "spender", "", "the spender whose allowance to revoke (required)")
	wf.bind(cmd)
	return cmd
}

func newTokenAllowanceCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var owner, spender string
	cmd := &cobra.Command{
		Use:   "allowance <token> --spender <addr|contact> [--owner <ref>]",
		Short: "Read a spender's allowance over an owner's tokens (read-only)",
		Long: "Read allowance(owner, spender) for a token. --owner defaults to the active\n" +
			"account. No signing, no policy — a pure read.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if spender == "" {
				return domain.New(domain.CodeUsage+".missing_spender", "--spender is required")
			}
			ownerRef := owner
			if ownerRef == "" {
				ownerRef = rs.flags.Account
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.TokenAllowance(cmd.Context(), domain.LocalCLI(), domain.AllowanceRequest{
				Token:   args[0],
				Owner:   ownerRef,
				Spender: spender,
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
			}, nil)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Allowance(w, m, res)
			})
		},
	}
	cmd.Flags().StringVar(&owner, "owner", "", "the owner whose allowance to read (default: the active account)")
	cmd.Flags().StringVar(&spender, "spender", "", "the spender to read the allowance for (required)")
	return cmd
}
