package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/service"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

// policy.go is the `daxie policy` command tree (cli-spec §policy, design §4.7) —
// the agent signing guardrails surface. EVERY mutation requires the ADMIN
// passphrase (a separate secret from the keystore passphrase the agent holds, §1
// secret-input rule): a compromised agent can sign WITHIN policy but cannot CHANGE
// policy. `policy show`/`verify`/`check`/`pin` are unauthenticated reads.
//
// M4 surface (this file): show / set / allow / deny (+ --remove) / verify / check /
// counters [release <id>] / pin --print|--verify / change-admin-passphrase
// (--stage|--commit) / reset --force. NOT in M4: `policy typed allow|remove` (M9)
// and `policy contract allow|remove` (M10) — their body fields are reserved + sealed
// but their mutation commands land later.
//
// The admin passphrase flows through the §3.6 channels ONLY (TTY prompt,
// --admin-passphrase-stdin|file, DAXIE_ADMIN_PASSPHRASE[_FILE]) — never a flag
// value, never in an agent pod's environment. The frontend binds the channel
// selection; the core's secret.Acquire reads the bytes.

func newPolicyCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Agent signing guardrails (spend limits, allowlist, seal)",
		Long: "Inspect and administer the sealed policy that gates every signing op.\n\n" +
			"Mutations (set/allow/deny/reset/change-admin-passphrase) require the ADMIN\n" +
			"passphrase — a separate secret from the keystore passphrase. A compromised\n" +
			"agent can sign within policy but cannot change it. `show`/`verify`/`check`/\n" +
			"`pin` are unauthenticated reads.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newPolicyShowCmd(ctx, rs),
		newPolicySetCmd(ctx, rs),
		newPolicyAllowCmd(ctx, rs),
		newPolicyDenyCmd(ctx, rs),
		newPolicyVerifyCmd(ctx, rs),
		newPolicyCheckCmd(ctx, rs),
		newPolicyCountersCmd(ctx, rs),
		newPolicyPinCmd(ctx, rs),
		newPolicyChangeAdminCmd(ctx, rs),
		newPolicyResetCmd(ctx, rs),
		newPolicyTypedCmd(ctx, rs), // M9
	)
	return cmd
}

// ── typed allow | remove (M9) ─────────────────────────────────────────────────

// newPolicyTypedCmd is the `daxie policy typed` parent: the per-domain typed-data
// allow registry (design §4.3 stage-5 + §4.5 typed_data.allowed[]). It manages the
// sealed allowlist of (chain_id, verifying_contract, primary_type) triples that let
// an OTHERWISE-unknown EIP-712 message pass the stage-5 deny-by-default gate. Both
// mutations require the ADMIN passphrase (like every policy mutation): a compromised
// agent that can sign within policy cannot widen the set of typed messages it may
// sign.
func newPolicyTypedCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "typed",
		Short: "Manage the per-domain EIP-712 typed-data allow registry (admin passphrase)",
		Long: "Allow / remove a specific EIP-712 typed-data domain so an otherwise-unknown\n" +
			"message can be signed. An entry pins the triple (chain-id, verifying-contract,\n" +
			"primary-type); a signed `sign typed` whose document matches a pinned entry\n" +
			"passes the stage-5 deny-by-default gate, everything else is refused\n" +
			"(typed_data.unknown) once a policy is active. Recognized spend-equivalent\n" +
			"permits (EIP-2612 / DAI / Permit2) do NOT need an entry — they are gated by the\n" +
			"approvals path instead.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newPolicyTypedAllowCmd(ctx, rs),
		newPolicyTypedRemoveCmd(ctx, rs),
	)
	return cmd
}

func newPolicyTypedAllowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var af adminPassphraseFlags
	var chainID int
	var contract, primaryType, label, anOut string
	cmd := &cobra.Command{
		Use:   "allow --chain-id <id> --contract <0x> --primary-type <Name> [--label <note>]",
		Short: "Allow an EIP-712 typed-data domain by its (chain-id, contract, primary-type) triple (admin passphrase)",
		Long: "Pin a typed-data domain into the stage-5 allow registry. An unknown EIP-712\n" +
			"message whose domain.chainId / domain.verifyingContract / primaryType match the\n" +
			"pinned triple then passes the deny-by-default gate. --contract is matched\n" +
			"case-insensitively; --primary-type is the EIP-712 primaryType string.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyTyped(ctx, cmd, rs, af, chainID, contract, primaryType, label, anOut, false)
		},
	}
	fl := cmd.Flags()
	fl.IntVar(&chainID, "chain-id", 0, "the EIP-712 domain chain-id (required)")
	fl.StringVar(&contract, "contract", "", "the EIP-712 domain.verifyingContract (0x, required)")
	fl.StringVar(&primaryType, "primary-type", "", "the EIP-712 primaryType (required)")
	fl.StringVar(&label, "label", "", "an operator note stored with the entry")
	fl.StringVar(&anOut, "anchor-out", "", "write the updated anchor to this path (read-only config)")
	af.bind(cmd)
	return cmd
}

func newPolicyTypedRemoveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var af adminPassphraseFlags
	var chainID int
	var contract, primaryType, anOut string
	cmd := &cobra.Command{
		Use:   "remove --chain-id <id> --contract <0x> --primary-type <Name>",
		Short: "Remove an EIP-712 typed-data domain from the allow registry (admin passphrase)",
		Long: "Remove a previously-allowed typed-data triple. After removal an EIP-712\n" +
			"message matching it is once again refused by the stage-5 deny-by-default gate\n" +
			"(once a policy is active).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyTyped(ctx, cmd, rs, af, chainID, contract, primaryType, "", anOut, true)
		},
	}
	fl := cmd.Flags()
	fl.IntVar(&chainID, "chain-id", 0, "the EIP-712 domain chain-id (required)")
	fl.StringVar(&contract, "contract", "", "the EIP-712 domain.verifyingContract (0x, required)")
	fl.StringVar(&primaryType, "primary-type", "", "the EIP-712 primaryType (required)")
	fl.StringVar(&anOut, "anchor-out", "", "write the updated anchor to this path (read-only config)")
	af.bind(cmd)
	return cmd
}

// runPolicyTyped is the shared body for `policy typed allow|remove`: validate the
// required triple flags, open the service, build the request, call the admin-gated
// use case, and render the mutate result (the same renderMutate set/allow/deny use).
func runPolicyTyped(ctx context.Context, cmd *cobra.Command, rs *rootState, af adminPassphraseFlags, chainID int, contract, primaryType, label, anOut string, remove bool) error {
	if chainID <= 0 {
		return domain.New(domain.CodeUsage+".bad_typed_allow", "--chain-id must be a positive chain id")
	}
	if !common.IsHexAddress(contract) {
		return domain.New(domain.CodeUsage+".bad_typed_allow", "--contract must be a 0x address (the EIP-712 verifyingContract)")
	}
	if primaryType == "" {
		return domain.New(domain.CodeUsage+".bad_typed_allow", "--primary-type is required (the EIP-712 primaryType)")
	}
	svc, closeFn, err := openService(ctx, rs)
	if err != nil {
		return err
	}
	defer closeFn()

	req := service.PolicyTypedAllowRequest{
		ChainID:           chainID,
		VerifyingContract: contract,
		PrimaryType:       primaryType,
		Label:             label,
		Remove:            remove,
		AnchorOut:         anOut,
	}
	in := service.AdminInput{Stdin: af.stdin, File: af.file}
	var res service.PolicyMutateResult
	if remove {
		res, err = svc.PolicyTypedRemove(cmd.Context(), domain.LocalCLI(), req, in)
	} else {
		res, err = svc.PolicyTypedAllow(cmd.Context(), domain.LocalCLI(), req, in)
	}
	if err != nil {
		return err
	}
	label2 := "policy typed allow"
	if remove {
		label2 = "policy typed remove"
	}
	return renderMutate(cmd, rs, res, label2)
}

// ── show ─────────────────────────────────────────────────────────────────────

func newPolicyShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the active policy, seal status, limits, and pins (unauthenticated)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.PolicyShow(cmd.Context(), domain.LocalCLI())
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				tbl := render.NewTable(w)
				tbl.Row("active", boolWord(res.Active))
				tbl.Row("seal", sealWord(res))
				if res.Reason != "" {
					tbl.Row("reason", res.Reason)
				}
				tbl.Row("nonce", utoa64(res.Nonce))
				tbl.Row("watermark", utoa64(res.Watermark))
				if res.WrittenBy != "" {
					tbl.Row("written-by", res.WrittenBy)
				}
				tbl.Row("max-tx", dashEmpty(res.Default.MaxTxWei))
				tbl.Row("max-day", dashEmpty(res.Default.MaxDayWei))
				tbl.Row("max-gas-price", dashEmpty(res.Default.MaxGasPriceWei))
				tbl.Row("allowlist", dashEmpty(res.Default.Allowlist))
				tbl.Row("include-self", dashEmpty(res.Default.IncludeSelf))
				_ = tbl.Flush()
				for _, p := range res.Allowlist {
					render.Line(w, m, "allow  %s %s %s", p.Source, p.Address, p.Name)
				}
				for _, p := range res.Denylist {
					render.Line(w, m, "deny   %s %s %s", p.Source, p.Address, p.Name)
				}
			})
		},
	}
}

// ── set ──────────────────────────────────────────────────────────────────────

func newPolicySetCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var (
		af                                      adminPassphraseFlags
		maxTx, maxDay, maxGasPrice              string
		allowlist, includeSelf, typedUnknown    string
		messages, tokensNoAllow, network, anOut string
	)
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set limits / gates (admin passphrase). The first set bootstraps the anchor.",
		Long: "Set spend limits, the gas cap, and the gate switches under the admin\n" +
			"passphrase. Amount literals accept eth|gwei|wei units, plus `none` (no limit\n" +
			"on this scope) and `inherit` (fall back to the default block).\n\n" +
			"The FIRST `policy set` BOOTSTRAPS the anchor (verify key + salt + watermark).\n" +
			"On a read-only config (K8s ConfigMap) it emits the anchor JSON — land it into\n" +
			"the ConfigMap, or pass --anchor-out <path> to stage it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			req := service.PolicySetRequest{
				Network:       network,
				MaxTx:         flagPtr(cmd, "max-tx", maxTx),
				MaxDay:        flagPtr(cmd, "max-day", maxDay),
				MaxGasPrice:   flagPtr(cmd, "max-gas-price", maxGasPrice),
				Allowlist:     flagPtr(cmd, "allowlist", allowlist),
				IncludeSelf:   flagPtr(cmd, "include-self", includeSelf),
				TypedUnknown:  flagPtr(cmd, "typed-unknown", typedUnknown),
				Messages:      flagPtr(cmd, "messages", messages),
				TokensNoAllow: flagPtr(cmd, "allow-tokens-without-allowlist", tokensNoAllow),
				AnchorOut:     anOut,
			}
			res, err := svc.PolicySet(cmd.Context(), domain.LocalCLI(), req, service.AdminInput{Stdin: af.stdin, File: af.file})
			if err != nil {
				return err
			}
			return renderMutate(cmd, rs, res, "policy set")
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&maxTx, "max-tx", "", "per-tx ETH limit (e.g. 0.1eth | none | inherit)")
	fl.StringVar(&maxDay, "max-day", "", "rolling-24h ETH limit")
	fl.StringVar(&maxGasPrice, "max-gas-price", "", "gas-cap: refuse to sign above this maxFeePerGas")
	fl.StringVar(&allowlist, "allowlist", "", "allowlist gate: on|off")
	fl.StringVar(&includeSelf, "include-self", "", "let own accounts pass the allowlist: on|off")
	fl.StringVar(&typedUnknown, "typed-unknown", "", "unknown typed-data: allow|deny")
	fl.StringVar(&messages, "messages", "", "EIP-191 message signing kill switch: allow|deny")
	fl.StringVar(&tokensNoAllow, "allow-tokens-without-allowlist", "", "permit token ops when no allowlist is set: on|off")
	fl.StringVar(&network, "network-rule", "", "scope the limits to one network (default: the default block)")
	fl.StringVar(&anOut, "anchor-out", "", "write the bootstrapped/updated anchor to this path (read-only config)")
	af.bind(cmd)
	return cmd
}

// ── allow / deny ─────────────────────────────────────────────────────────────

func newPolicyAllowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var af adminPassphraseFlags
	var remove bool
	var label, anOut string
	cmd := &cobra.Command{
		Use:   "allow <address|contact|ens>",
		Short: "Add (or --remove) an allowlist pin (admin passphrase)",
		Long: "Pin a destination/spender into the allowlist. A 0x address is pinned\n" +
			"as-is; a contact/ENS name is resolved NOW and the resolved address pinned\n" +
			"(the sealed allowlist never stores a bare name, §4.8). --remove takes it out.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			req, perr := resolvePinRequest(args[0], label, remove, anOut)
			if perr != nil {
				return perr
			}
			res, err := svc.PolicyAllow(cmd.Context(), domain.LocalCLI(), req, service.AdminInput{Stdin: af.stdin, File: af.file})
			if err != nil {
				return err
			}
			return renderMutate(cmd, rs, res, "policy allow")
		},
	}
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the entry instead of adding it")
	cmd.Flags().StringVar(&label, "label", "", "an operator note stored with the pin")
	cmd.Flags().StringVar(&anOut, "anchor-out", "", "write the updated anchor to this path (read-only config)")
	af.bind(cmd)
	return cmd
}

func newPolicyDenyCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var af adminPassphraseFlags
	var remove bool
	var label, anOut string
	cmd := &cobra.Command{
		Use:   "deny <address|contact|ens>",
		Short: "Add (or --remove) a denylist pin (admin passphrase)",
		Long: "Pin a destination/spender into the denylist (denylist beats allowlist beats\n" +
			"include_self, §4.5). A contact/ENS deny matches by pinned address OR by name,\n" +
			"so a re-pointed name stays blocked. --remove takes it out.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			req, perr := resolvePinRequest(args[0], label, remove, anOut)
			if perr != nil {
				return perr
			}
			res, err := svc.PolicyDeny(cmd.Context(), domain.LocalCLI(), req, service.AdminInput{Stdin: af.stdin, File: af.file})
			if err != nil {
				return err
			}
			return renderMutate(cmd, rs, res, "policy deny")
		},
	}
	cmd.Flags().BoolVar(&remove, "remove", false, "remove the entry instead of adding it")
	cmd.Flags().StringVar(&label, "label", "", "an operator note stored with the pin")
	cmd.Flags().StringVar(&anOut, "anchor-out", "", "write the updated anchor to this path (read-only config)")
	af.bind(cmd)
	return cmd
}

// ── verify ───────────────────────────────────────────────────────────────────

func newPolicyVerifyCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify the sealed policy against the pinned anchor (exit 0/8, no passphrase)",
		Long: "Check the on-disk policy.json seal against the pinned anchor verify key.\n" +
			"Exit 0 on a good seal; exit 8 (policy.seal_violation / rollback) on failure.\n" +
			"Passphrase-free — run it as a K8s readiness probe or CI gate.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.PolicyVerify(cmd.Context(), domain.LocalCLI())
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "policy seal verified (nonce %s, watermark %s)", utoa64(res.Nonce), utoa64(res.Watermark))
			})
		},
	}
}

// ── check (what-if) ──────────────────────────────────────────────────────────

func newPolicyCheckCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var from, to, amount, maxGasPrice, network string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "What-if: evaluate a hypothetical send against the policy (no reservation)",
		Long: "Run the full 8-stage policy pipeline against a hypothetical send WITHOUT\n" +
			"reserving or signing. Exit 0 if it would be allowed; exit 3 with the §4.9\n" +
			"code + every accumulated violation if it would be denied. Agents pre-flight\n" +
			"with this before burning a signing attempt.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.PolicyCheck(cmd.Context(), domain.LocalCLI(), service.PolicyCheckRequest{
				From: from, To: to, Amount: amount, MaxGasPrice: maxGasPrice, Network: network,
			})
			if err != nil {
				return err // a denied verdict is exit 3 with the code + violations
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "allowed")
			})
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&from, "from", "", "the signing account address (0x)")
	fl.StringVar(&to, "to", "", "the recipient/spender address (0x)")
	fl.StringVar(&amount, "amount", "", "the ETH amount (e.g. 0.5eth)")
	fl.StringVar(&maxGasPrice, "max-gas-price", "", "the maxFeePerGas to test against the cap")
	fl.StringVar(&network, "network-rule", "", "the network whose limits to apply (default: the active network)")
	_ = cmd.MarkFlagRequired("from")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

// ── counters [release <id>] ──────────────────────────────────────────────────

func newPolicyCountersCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "counters",
		Short: "Inspect or release spend counters",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newPolicyCountersReleaseCmd(ctx, rs))
	return cmd
}

func newPolicyCountersReleaseCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var af adminPassphraseFlags
	cmd := &cobra.Command{
		Use:   "release <reservation-id>",
		Short: "Release a stuck pre-signature reservation by id (admin passphrase)",
		Long: "Free a reservation that is stuck in the pre-signature state (admin\n" +
			"passphrase). A COMMITTED reservation is never released — over-counting is the\n" +
			"safe direction once signed bytes exist (§4.4).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			if err := svc.PolicyCountersRelease(cmd.Context(), domain.LocalCLI(), args[0], service.AdminInput{Stdin: af.stdin, File: af.file}); err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, jsonGet{Key: "released", Value: args[0]}, func(w io.Writer) {
				render.Line(w, m, "released reservation %s", args[0])
			})
		},
	}
	af.bind(cmd)
	return cmd
}

// ── pin --print | --verify ───────────────────────────────────────────────────

func newPolicyPinCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var doPrint bool
	var verifyKey string
	cmd := &cobra.Command{
		Use:   "pin",
		Short: "Print the anchor (--print) or canary-verify the policy under a key (--verify)",
		Long: "--print re-emits the pinned anchor JSON (for diffing / re-publishing).\n" +
			"--verify <key> reports whether the on-disk policy.json verifies under a\n" +
			"SUPPLIED verify key (exit 0/8) — the passphrase-free canary: run it as a\n" +
			"one-off K8s Job against a candidate ConfigMap value BEFORE cutover so a\n" +
			"fat-finger becomes a canary, not a fleet-wide refusal (§4.6).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if doPrint == (verifyKey != "") {
				return domain.New(domain.CodeUsage+".bad_flags", "exactly one of --print or --verify <key> is required")
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()

			if doPrint {
				res, perr := svc.PolicyPinPrint(cmd.Context(), domain.LocalCLI())
				if perr != nil {
					return perr
				}
				return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
					_, _ = io.WriteString(w, res.AnchorJSON+"\n")
				})
			}
			res, perr := svc.PolicyPinVerify(cmd.Context(), domain.LocalCLI(), verifyKey)
			if perr != nil {
				return perr // exit 8 when it does not verify
			}
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "policy verifies under the supplied key")
			})
		},
	}
	cmd.Flags().BoolVar(&doPrint, "print", false, "re-emit the pinned anchor JSON")
	cmd.Flags().StringVar(&verifyKey, "verify", "", "canary: does the policy verify under this verify key?")
	return cmd
}

// ── change-admin-passphrase --stage | --commit ───────────────────────────────

func newPolicyChangeAdminCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var (
		af     adminPassphraseFlags
		nf     newAdminPassphraseFlags
		stage  bool
		commit bool
		anOut  string
	)
	cmd := &cobra.Command{
		Use:   "change-admin-passphrase",
		Short: "Stage/commit a zero-outage admin-passphrase rotation (admin passphrase)",
		Long: "Rotate the admin passphrase across a fleet without an outage (§4.6).\n\n" +
			"--stage: authenticate the CURRENT passphrase, derive the NEW key family, and\n" +
			"  print the new verify key (verify_key_next). The loader keeps verifying under\n" +
			"  the old key meanwhile — land verify_key_next into the ConfigMap, canary it\n" +
			"  with `policy pin --verify`, then commit.\n" +
			"--commit: re-derive from the staged salt, assert the new key matches, reseal\n" +
			"  the body under the new family, and promote verify_key_next → verify_key.\n\n" +
			"Current passphrase: --admin-passphrase-* / DAXIE_ADMIN_PASSPHRASE[_FILE].\n" +
			"New passphrase:     --new-admin-passphrase-* / DAXIE_NEW_ADMIN_PASSPHRASE[_FILE].",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if stage == commit {
				return domain.New(domain.CodeUsage+".bad_flags", "exactly one of --stage or --commit is required")
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.PolicyChangeAdminPassphrase(cmd.Context(), domain.LocalCLI(), stage, commit, anOut,
				service.AdminInput{Stdin: af.stdin, File: af.file},
				service.NewAdminInput{Stdin: nf.stdin, File: nf.file})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				if stage {
					render.Line(w, m, "staged rotation: verify_key_next = %s", res.VerifyKeyNext)
				} else {
					render.Line(w, m, "committed rotation: verify_key = %s", res.VerifyKey)
				}
			})
		},
	}
	cmd.Flags().BoolVar(&stage, "stage", false, "stage the rotation (print the new verify key)")
	cmd.Flags().BoolVar(&commit, "commit", false, "commit the staged rotation (reseal under the new key)")
	cmd.Flags().StringVar(&anOut, "anchor-out", "", "write the updated anchor to this path (read-only config)")
	af.bind(cmd)
	nf.bind(cmd)
	return cmd
}

// ── reset --force ────────────────────────────────────────────────────────────

func newPolicyResetCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var af adminPassphraseFlags
	var force bool
	var anOut string
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Reseal a fresh default policy, authenticating against the anchor (admin passphrase)",
		Long: "Recover a corrupted/tampered policy.json by resealing a fresh DEFAULT body\n" +
			"under the EXISTING key family. It authenticates against the ANCHOR (not the\n" +
			"file), so a prompt-compromised agent that trashed the policy cannot reset it\n" +
			"under a passphrase of its own choosing. There is NO --yes bypass; --force is\n" +
			"required to acknowledge the destructive reseal (§4.7 J12).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !force {
				return domain.New(domain.CodeUsage+".force_required",
					"`policy reset` is destructive; pass --force to reseal a fresh default policy")
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.PolicyResetForce(cmd.Context(), domain.LocalCLI(), anOut, service.AdminInput{Stdin: af.stdin, File: af.file})
			if err != nil {
				return err
			}
			return renderMutate(cmd, rs, res, "policy reset")
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "acknowledge the destructive reseal (required)")
	cmd.Flags().StringVar(&anOut, "anchor-out", "", "write the resealed anchor to this path (read-only config)")
	af.bind(cmd)
	return cmd
}

// ── shared helpers ───────────────────────────────────────────────────────────

// renderMutate renders a PolicyMutateResult (set/allow/deny/reset). When the config
// is read-only the anchor was NOT written — emit the anchor JSON so the operator
// lands it into the ConfigMap (the §4.6 K8s path).
func renderMutate(cmd *cobra.Command, rs *rootState, res service.PolicyMutateResult, label string) error {
	m := rs.flags.Mode()
	return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
		if res.Bootstrapped {
			render.Line(w, m, "%s: anchor bootstrapped (verify_key %s)", label, res.VerifyKey)
		}
		// §4.8 resolution echo (cli-spec: the resolved address is always echoed before
		// signing): a name pin (ENS/contact) surfaces WHAT 0x was sealed so the operator
		// authorizes the address, not the name. Printed BEFORE the applied line so it is
		// visible alongside the seal it sealed. Empty for raw-0x pins and --remove.
		if res.Pinned != "" {
			render.Line(w, m, "%s: %s %s -> %s (pinned, resolved_at %s)", label, res.Source, res.Name, res.Pinned, res.ResolvedAt)
		}
		render.Line(w, m, "%s applied (nonce %s, watermark %s)", label, utoa64(res.Nonce), utoa64(res.Watermark))
		if !res.AnchorWritten {
			// Read-only config: the operator must land the anchor out of band. Print it
			// to stdout so a pipe captures it.
			render.Line(w, m, "config is read-only; land this anchor into the ConfigMap (or use --anchor-out):")
			_, _ = io.WriteString(w, res.AnchorJSON+"\n")
		}
	})
}

// resolvePinRequest turns the allow/deny argument into a service request. A raw 0x
// address is pinned directly; an ENS name (M7) is passed through as Source:"ens" with
// NO Address — the service resolves it NOW and pins name+resolved-address+resolved-at
// (§4.8: store the resolved 0x, never a bare name; a later send re-resolves and the
// §4.3 stage-4 gate refuses on drift). A contact name is passed through as
// Source:"contact" — the service snapshots its current address as the pin. For
// --remove a name is carried so removal by name works without re-resolving.
func resolvePinRequest(arg, label string, remove bool, anchorOut string) (service.PolicyAllowRequest, error) {
	ref, err := domain.ParseAccountRef(arg)
	if err == nil && ref.Kind == domain.RefAddress {
		return service.PolicyAllowRequest{
			Source: "address", Address: ref.Addr.Hex(), Label: label, Remove: remove, AnchorOut: anchorOut,
		}, nil
	}
	// An ENS name (".eth"): the service resolves at allow-time (M7) and pins the
	// resolved address + name. For --remove the address is not needed (removal is by
	// source+name).
	if err == nil && ref.Kind == domain.RefENS {
		return service.PolicyAllowRequest{Source: "ens", Name: arg, Label: label, Remove: remove, AnchorOut: anchorOut}, nil
	}
	// Otherwise a contact name: the service snapshots its current address as the pin.
	return service.PolicyAllowRequest{Source: "contact", Name: arg, Label: label, Remove: remove, AnchorOut: anchorOut}, nil
}

// flagPtr returns a *string only when the named flag was CHANGED on the command
// line — so an unset flag is "leave unchanged" (nil) and an explicit empty string
// is honored. Mirrors the tri-state semantics the engine's Change expects.
func flagPtr(cmd *cobra.Command, name, val string) *string {
	if cmd.Flags().Changed(name) {
		return &val
	}
	return nil
}

// sealWord renders the seal status for `policy show`.
func sealWord(res service.PolicyShowResult) string {
	if !res.Active {
		return "inactive (opt-in)"
	}
	if res.Verified {
		return "verified"
	}
	return "HALTED"
}

// dashEmpty renders "" as "-" for the human table.
func dashEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
