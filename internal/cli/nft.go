package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// nft.go is the `daxie nft` command tree (cli-spec §`daxie nft`, design §2.8/§4.2/
// §7.8): the NFT registry (add/alias/aliases), the ownership reads (list/show), and
// the ERC-721/1155 send. A collection is named by a REGISTRY ALIAS or a raw 0x
// contract; an individual NFT by a <collection>#<tokenId> reference (collection an
// alias or 0x) or by an individual-NFT alias — resolution is registry-only for
// alias forms (a miss is an error, never an on-chain name() lookup; the
// anti-spoofing property, identical to tokens).
//
// Thin host: it binds flags into the domain request structs, opens the service,
// wires the §5.9 stderr-progress sink for the broadcasting `nft send`, and renders
// the single result. All signing-side logic (the ERC-165 detection, the standard-
// correct safeTransferFrom, the policy chokepoint with the RECIPIENT as the policy
// subject + the §4.3 fail-closed-no-allowlist gate) lives in service; this file
// physically cannot route around the policy chokepoint (the arch matrix forbids
// frontend→provider).
//
// Exit codes (§5.7): 0 ok; 2 usage (bad alias/address/ref, not-an-NFT, bad
// --amount); 3 policy.denied (allowlist / fail-closed-no-allowlist on a send); 6
// rpc.unreachable; 10 ref.not_found (unknown collection/nft alias) / read-only
// mount; plus the broadcasting outcomes on `nft send --wait`: 7 reverted, 8 timeout
// (resumable), 9 replaced/conflict.

func newNFTCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nft",
		Short: "Manage NFTs (ERC-721 / ERC-1155): registry, ownership, transfers",
		Long: "An NFT collection is named by a registry alias or a 0x contract address; an\n" +
			"individual NFT by <collection>#<tokenId> or an NFT alias. Aliases are\n" +
			"per-network and resolved registry-only (an unregistered name is an error,\n" +
			"never an on-chain name() lookup). Use `nft add` to register a collection\n" +
			"(its standard is detected via ERC-165 and stored), `nft alias` to name an\n" +
			"individual token, `nft list`/`nft show` to read ownership, and `nft send`\n" +
			"to transfer (the recipient — not the collection — is the policy subject).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newNFTAddCmd(ctx, rs),
		newNFTAliasCmd(ctx, rs),
		newNFTAliasesCmd(ctx, rs),
		newNFTListCmd(ctx, rs),
		newNFTShowCmd(ctx, rs),
		newNFTSendCmd(ctx, rs),
	)
	return cmd
}

// ── registry: add / alias / aliases ──────────────────────────────────────────

func newNFTAddCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "add <0x> [--name <alias>]",
		Short: "Register an NFT collection (its standard is detected via ERC-165)",
		Long: "Register a collection by its 0x contract address. The standard\n" +
			"(erc721|erc1155) is detected on-chain via ERC-165 and stored; a non-NFT\n" +
			"address is rejected. The alias defaults to the case-folded on-chain symbol;\n" +
			"override it with --name. A collision with an existing alias requires a\n" +
			"different --name.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.NFTAdd(cmd.Context(), domain.LocalCLI(), domain.NFTAddRequest{
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
				render.NFTCollection(w, m, res)
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "alias for the collection (default: the case-folded on-chain symbol)")
	return cmd
}

func newNFTAliasCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "alias <collection#tokenId> <alias>",
		Short: "Name an individual NFT (binds an alias to a registered collection + token id)",
		Long: "Give an individual NFT an alias. The collection part of <collection#tokenId>\n" +
			"must be a REGISTERED collection alias (register it with `nft add` first); the\n" +
			"token id is stored as a decimal string.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.NFTAlias(cmd.Context(), domain.LocalCLI(), domain.NFTAliasRequest{
				Ref:     args[0],
				Alias:   args[1],
				Network: rs.flags.Network,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.NFTAlias(w, m, res)
			})
		},
	}
}

func newNFTAliasesCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "aliases",
		Short: "List the individual-NFT aliases for the network (alias-sorted)",
		Long:  "List every individual-NFT alias registered on the current network.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.NFTAliases(cmd.Context(), domain.LocalCLI(), domain.NFTAliasesRequest{
				Network: rs.flags.Network,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.NFTAliasList(w, m, res)
			})
		},
	}
}

// ── reads: list / show ───────────────────────────────────────────────────────

func newNFTListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var account string
	cmd := &cobra.Command{
		Use:   "list [--account <ref>]",
		Short: "List owned NFTs across registered collections",
		Long: "List the NFTs an account owns among your REGISTERED collections + named\n" +
			"NFTs (v1 reads the registry, not an on-chain indexer). --account defaults to\n" +
			"the active account.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			res, err := svc.NFTList(cmd.Context(), domain.LocalCLI(), domain.NFTListRequest{
				Account: resolveFrom(rs, account),
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
			}, nil)
			if err != nil {
				return err
			}
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.NFTList(w, m, res)
			})
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "the account to list NFTs for (default: the active account)")
	return cmd
}

func newNFTShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var contract, tokenID, account string
	cmd := &cobra.Command{
		Use:   "show <collection#tokenId|alias> | --contract <0x> --token-id <N>",
		Short: "Show an NFT's ownership/metadata (ERC-721 owner / ERC-1155 balance)",
		Long: "Read one NFT by <collection#tokenId> (collection an alias or 0x), by an NFT\n" +
			"alias, or by --contract + --token-id. ERC-721 reports the owner; ERC-1155\n" +
			"reports balanceOf(account, id) when --account is given. Read-only; no IPFS\n" +
			"metadata fetch in v1.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var ref string
			if len(args) == 1 {
				ref = args[0]
			}
			if ref == "" && contract == "" {
				return domain.New(domain.CodeUsage+".bad_nft_ref",
					"give a <collection#tokenId>/NFT alias, or --contract with --token-id")
			}
			if ref != "" && contract != "" {
				return domain.New(domain.CodeUsage+".bad_nft_ref",
					"pass either a <collection#tokenId>/alias OR --contract/--token-id, not both")
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			res, err := svc.NFTShow(cmd.Context(), domain.LocalCLI(), domain.NFTShowRequest{
				NFT:      ref,
				Contract: contract,
				TokenID:  tokenID,
				Account:  resolveFrom(rs, account),
				Network:  rs.flags.Network,
				RPC:      rs.flags.RPC,
			}, nil)
			if err != nil {
				return err
			}
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.NFTShow(w, m, res)
			})
		},
	}
	cmd.Flags().StringVar(&contract, "contract", "", "the collection 0x contract (alternative to the <collection#tokenId> arg)")
	cmd.Flags().StringVar(&tokenID, "token-id", "", "the token id (with --contract; a decimal integer)")
	cmd.Flags().StringVar(&account, "account", "", "the account to read an ERC-1155 balance for (default: the active account)")
	return cmd
}

// ── send (a transfer through the SAME pipeline → a TxResult) ──────────────────

func newNFTSendCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var from, to, nft, amount string
	var dryRun bool
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "send --to <addr|contact> --nft <collection#tokenId|alias> [--amount N]",
		Short: "Build, sign, and broadcast an NFT transfer (ERC-721 / ERC-1155)",
		Long: "Send an NFT via safeTransferFrom. --nft names it by <collection#tokenId>\n" +
			"(collection an alias or 0x) or an NFT alias. The collection's standard\n" +
			"(721/1155) selects the calldata; --amount is the ERC-1155 quantity (default\n" +
			"1; rejected/ignored for a 721). --to is the recipient — and the policy\n" +
			"subject (the allowlist + fail-closed-no-allowlist rules apply to it, NOT the\n" +
			"collection contract). --wait blocks for confirmations; --dry-run previews\n" +
			"without signing; --yes is required when non-interactive.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if to == "" {
				return domain.New(domain.CodeUsage+".missing_to", "--to is required")
			}
			if nft == "" {
				return domain.New(domain.CodeUsage+".missing_nft", "--nft is required (a <collection#tokenId> or an NFT alias)")
			}
			w, err := wf.toWaitOpts(cmd)
			if err != nil {
				return err
			}
			req := domain.NFTSendRequest{
				NFT:     nft,
				To:      to,
				Amount:  amount,
				From:    resolveFrom(rs, from),
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
				DryRun:  dryRun,
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
			// §5.9: send/wait progress → stderr (never stdout); under --json the one
			// result object is the only thing on stdout.
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.SendNFT(cmd.Context(), domain.LocalCLI(), req, sink)
			// An NFT send returns a TxResult — reuse the shared (TxResult, error) →
			// render+exit projection (timeout/reverted/replaced still emit one final
			// object on stdout before the §5.7 exit code).
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "sending account ref (default: the configured default account)")
	cmd.Flags().StringVar(&to, "to", "", "recipient: a raw 0x address or a contact name (required)")
	cmd.Flags().StringVar(&nft, "nft", "", "the NFT: <collection#tokenId> (alias or 0x) or an NFT alias (required)")
	cmd.Flags().StringVar(&amount, "amount", "", "ERC-1155 quantity (default 1); omit/1 for ERC-721")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "build + estimate + preview; do not sign or broadcast")
	wf.bind(cmd)
	return cmd
}
