package cli

import (
	"context"
	"io"
	"time"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// tx.go is the `daxie tx` command tree (cli-spec §`daxie tx`): send, status, wait,
// list. speedup/cancel live in txrbf.go. It is a thin host — it binds
// flags/env/stdin into a domain.TxRequest, opens the service, wires the §5.9
// stderr-progress EventSink, and renders the single result (one JSON object on
// stdout under --json; progress to stderr, never stdout). All signing-side logic
// (the §2.7 authorize/settle/abort kernel, §5.1 pipeline, gas, journal, policy)
// lives in service; this file physically cannot route around the policy chokepoint
// (the arch matrix forbids frontend→provider).
//
// M3 is ETH-only: --token is plumbed (M5) and the service rejects it cleanly with
// usage.unsupported; a `name.eth` --to is M7 (the service fails clean — the cli
// passes the raw --to string through and lets the contact/0x resolver in service
// handle it). Exit codes (§5.7) flow through the central mapError funnel: 0 ok, 2
// usage, 3 policy.denied, 5 funds.insufficient, 6 rpc.unreachable, 7 reverted, 8
// timeout (resumable, NOT failure), 9 tx.replaced/conflict, 10 not-found, 11
// state.lock_timeout, 12 integrity.
//
// The keystore passphrase the signer needs is resolved INSIDE the service via the
// §3.6 precedence (DAXIE_PASSPHRASE[_FILE] env / the host TTY prompt, both wired
// through openService's SecretIO) — SendTx takes no passphrase channel param, so
// the cli does not bind --passphrase-* on `tx send`; agents pass
// DAXIE_PASSPHRASE_FILE (the same env channel the M1 demos use).

func newTxCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tx",
		Short: "Send and track Ethereum transactions",
		Long: "Build, sign, broadcast, and track transactions. Gas is estimated by\n" +
			"default (EIP-1559); override per flag/env/config. --wait blocks for\n" +
			"confirmations and reports final status (including revert). Every signed tx\n" +
			"is recorded in a local journal (`tx list`).\n\n" +
			"Secrets (the keystore passphrase) are never flag values — use\n" +
			"--passphrase-stdin / --passphrase-file or DAXIE_PASSPHRASE[_FILE] (§3.6).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newTxSendCmd(ctx, rs),
		newTxStatusCmd(ctx, rs),
		newTxWaitCmd(ctx, rs),
		newTxListCmd(ctx, rs),
		newTxSpeedupCmd(ctx, rs),
		newTxCancelCmd(ctx, rs),
	)
	return cmd
}

// gasFlags is the shared gas-override flag group bound by `tx send` and the RBF
// commands. A secret is never a flag value, but a gas knob IS a flag value — these
// are public fee parameters, not credentials. Flag > env > config > estimated is
// resolved in service (§5.4); the cli only forwards what the operator set.
type gasFlags struct {
	gasLimit    string
	maxFee      string
	priorityFee string
	gasPrice    string
	speed       string
	legacy      bool
	nonce       uint64
}

func (g *gasFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&g.gasLimit, "gas-limit", "", "override the estimated gas limit (e.g. 21000)")
	fl.StringVar(&g.maxFee, "max-fee", "", "explicit EIP-1559 max fee per gas (e.g. 30gwei)")
	fl.StringVar(&g.priorityFee, "priority-fee", "", "explicit EIP-1559 max priority fee per gas (e.g. 1gwei)")
	fl.StringVar(&g.gasPrice, "gas-price", "", "legacy gas price (only with --legacy; e.g. 20gwei)")
	fl.StringVar(&g.speed, "speed", "", "fee preset: slow|normal|fast (default normal)")
	fl.BoolVar(&g.legacy, "legacy", false, "pre-1559 legacy tx (auto-enabled when the network config says legacy)")
	fl.Uint64Var(&g.nonce, "nonce", 0, "manual nonce (advanced; bypasses derivation)")
}

// apply copies the gas overrides onto a TxRequest, threading --nonce only when the
// operator actually set it (so an unset --nonce leaves Nonce nil → service derives
// it under the account lock, §5.6).
func (g *gasFlags) apply(cmd *cobra.Command, req *domain.TxRequest) {
	req.GasLimit = g.gasLimit
	req.MaxFee = g.maxFee
	req.PriorityFee = g.priorityFee
	req.GasPrice = g.gasPrice
	req.Speed = g.speed
	req.Legacy = g.legacy
	if cmd.Flags().Changed("nonce") {
		n := g.nonce
		req.Nonce = &n
	}
}

// waitFlags is the shared --wait/--confirmations/--timeout group.
type waitFlags struct {
	wait          bool
	confirmations uint64
	timeout       string
}

func (wf *waitFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.BoolVar(&wf.wait, "wait", false, "block until the tx reaches the confirmation target")
	fl.Uint64Var(&wf.confirmations, "confirmations", 0, "confirmation target (default: per-network)")
	fl.StringVar(&wf.timeout, "timeout", "", "bounded wait, e.g. 5m (default 10m)")
}

// toWaitOpts builds the domain.WaitOpts from the flags, threading --confirmations
// only when set (so the service applies the per-network default otherwise) and
// parsing --timeout into a domain.Duration.
func (wf *waitFlags) toWaitOpts(cmd *cobra.Command) (domain.WaitOpts, error) {
	w := domain.WaitOpts{Enabled: wf.wait}
	if cmd.Flags().Changed("confirmations") {
		c := wf.confirmations
		w.Confirmations = &c
	}
	if wf.timeout != "" {
		// --timeout is a flag string ("5m"); parse it with the stdlib (a frontend may
		// read time/parse, unlike the determinism-guarded core) and wrap into the
		// domain.Duration wire type the request expects.
		d, err := time.ParseDuration(wf.timeout)
		if err != nil {
			return domain.WaitOpts{}, domain.Newf(domain.CodeUsage+".bad_timeout", "invalid --timeout %q: %v", wf.timeout, err)
		}
		w.Timeout = domain.Duration{D: d}
	}
	return w, nil
}

func newTxSendCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var from, to, amount, token string
	var dryRun bool
	var gf gasFlags
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "send --to <addr|contact> --amount <value>",
		Short: "Build, sign, and broadcast a transaction",
		Long: "Send ETH (M3). --to accepts a raw 0x address or a contact name; --from\n" +
			"defaults to the configured default account. Gas is estimated unless\n" +
			"overridden. --wait blocks for confirmations. --dry-run builds + previews\n" +
			"without signing. --yes is required when non-interactive (no TTY).\n" +
			"(--token is M5; a name.eth --to is M7 — both fail clean, never faked.)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if to == "" {
				return domain.New(domain.CodeUsage+".missing_to", "--to is required")
			}
			if amount == "" {
				return domain.New(domain.CodeUsage+".missing_amount", "--amount is required")
			}
			w, err := wf.toWaitOpts(cmd)
			if err != nil {
				return err
			}

			req := domain.TxRequest{
				From:    resolveFrom(rs, from),
				To:      to,
				Amount:  amount,
				Token:   token, // M5: service rejects with usage.unsupported
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
				DryRun:  dryRun,
				Confirm: rs.flags.Yes, // --yes skips the TTY confirm (the agent escape hatch)
				Yes:     rs.flags.Yes,
				Wait:    w,
			}
			gf.apply(cmd, &req)

			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			m := rs.flags.Mode()
			// §5.9: send/wait progress → stderr (never stdout); under --json the one
			// result object is the only thing on stdout.
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.SendTx(cmd.Context(), domain.LocalCLI(), req, sink)
			// §5.3/§5.9: a timeout/reverted/replaced outcome still emits the one final
			// result object on stdout, then exits with the §5.7 code.
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "sending account ref (default: the configured default account)")
	cmd.Flags().StringVar(&to, "to", "", "recipient: a raw 0x address or a contact name (required)")
	cmd.Flags().StringVar(&amount, "amount", "", "amount to send, e.g. 0.5 or 0.5eth (required)")
	cmd.Flags().StringVar(&token, "token", "", "M5: ERC-20 token by alias or contract address")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "build + estimate + preview; do not sign or broadcast")
	gf.bind(cmd)
	wf.bind(cmd)
	return cmd
}

func newTxStatusCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "status <txhash>",
		Short: "Show a transaction's current status + confirmation count",
		Long:  "Fold the local journal record for a hash plus one receipt re-check.\nNo account lock is taken (the §5.6 deadlock-free read).",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.TxStatus(cmd.Context(), domain.LocalCLI(), domain.TxStatusRequest{
				Hash:    args[0],
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
			}, nil)
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.TxResult(w, m, res)
			})
		},
	}
}

func newTxWaitCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "wait <txhash>",
		Short: "Resume waiting on a known hash (e.g. after a timeout)",
		Long: "Run the §5.3 wait state machine on a hash: poll to the confirmation\n" +
			"target, emit per-block progress to stderr. confirmed→0, reverted→7,\n" +
			"replaced→9, timeout→8 (NOT a failure — resumable).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := wf.toWaitOpts(cmd)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.WaitTx(cmd.Context(), domain.LocalCLI(), domain.WaitRequest{
				Hash:          args[0],
				Confirmations: w.Confirmations,
				Timeout:       w.Timeout,
				Network:       rs.flags.Network,
				RPC:           rs.flags.RPC,
			}, sink)
			// §5.3/§5.9: timeout (exit 8, resumable) / reverted / replaced still emit
			// the one final result object on stdout before the exit code is funneled.
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	// wait is implicitly enabled (the command IS the wait); bind --confirmations/--timeout only.
	cmd.Flags().Uint64Var(&wf.confirmations, "confirmations", 0, "confirmation target (default: per-network)")
	cmd.Flags().StringVar(&wf.timeout, "timeout", "", "bounded wait, e.g. 10m (default 10m)")
	return cmd
}

func newTxListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var account string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Daxie-originated transactions from the local journal",
		Long:  "Read the local journal (latest-per-id, newest-first). With --account,\nfilter to that sender; otherwise the default account (§7.7).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ListTxs(cmd.Context(), domain.LocalCLI(), domain.TxListRequest{
				Account: resolveFrom(rs, account),
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.TxRows(w, m, res.Txs)
			})
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "filter to one sending account (default: the default account)")
	return cmd
}

// resolveFrom picks the sending account ref: the command's --from/--account flag
// if set, else the root-level --account/DAXIE_ACCOUNT default the frontend already
// resolved into rs.flags.Account. An empty result means "the configured default
// account" — the service resolves that (§7.7), not the cli.
func resolveFrom(rs *rootState, flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return rs.flags.Account
}

// renderTxOutcome is the shared (TxResult, error) → render+exit projection for
// every broadcasting/awaiting command (send, wait, speedup, cancel). It enforces
// the §5.3/§5.9 contract that a TERMINAL-BUT-POPULATED outcome — timeout (exit 8,
// resumable), reverted (exit 7), replaced (exit 9) — still emits exactly ONE final
// JSON object (or the human table) on STDOUT, and only THEN funnels the error so
// the central registry projects the right exit code. The discriminator is "did the
// service hand back a result it wants shown?" — a populated Hash (the tx exists
// on-chain / in the journal) means yes. A bare error with an empty result (a
// pre-broadcast failure: bad flag, policy denial, dial failure) skips stdout and
// goes straight to the error envelope on stderr.
//
// This is why the cli does NOT do the naive `if err != nil { return err }` on a
// wait path: a timeout MUST print {"status":"timeout","resume":"daxie tx wait 0x…"}
// on stdout for the agent to parse, while still exiting 8.
func renderTxOutcome(cmd *cobra.Command, m render.Mode, res domain.TxResult, err error) error {
	// A terminal-but-known outcome carries a hash (the tx reached the chain or the
	// journal), or it is a --dry-run preview the service wants shown (DryRun=true,
	// no hash since nothing broadcast). Render either as the single stdout object,
	// then return err for the exit code. A bare pre-broadcast error has an empty
	// result → skip stdout.
	if res.Hash != "" || res.DryRun {
		if rerr := render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
			render.TxResult(w, m, res)
			if res.Replaced != "" {
				render.Line(w, m, "replaces: %s", res.Replaced)
			}
		}); rerr != nil {
			return rerr
		}
	}
	return err
}
