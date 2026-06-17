package cli

import (
	"context"
	"io"
	"time"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// receive.go is the `daxie receive` command (cli-spec §`daxie receive`; design
// §5.8/§5.9). It is a thin host: it binds the flags into a domain.ReceiveRequest,
// opens the service, wires the STDOUT NDJSON EventSink (render.ReceiveStream —
// distinct from the STDERR progress sink send/wait use), blocks on svc.Receive,
// and exits via the terminal line's exit code. ALL detection logic (block scan,
// balance-delta with the actual-gas own-fee correction, log filters,
// confirmation/reorg, completion modes, carry-forward baseline) lives in
// service/receive*.go — the arch matrix forbids this frontend from importing a
// provider, so the engine physically cannot live here.
//
// The §5.8 stream contract this command upholds:
//   - the receiving ADDRESS is emitted UP FRONT (the first `listening` line) so a
//     counterparty can be handed it BEFORE the command blocks (block-until-paid);
//   - the stream is NDJSON on STDOUT under --json (the one sanctioned exception to
//     single-object-on-stdout) — every line `"v":1`, amounts base-unit decimal
//     strings — and short human lines on STDOUT otherwise;
//   - the TERMINAL line is `complete` (exit 0) or `timeout` (exit 8); `confirmed`
//     is per-transfer and NEVER terminal. A timeout is NOT a Go error (mirrors
//     `tx wait`): the service returns (result, nil) with result.Exit==8 and the
//     command surfaces that exit through a typed timeout error so the §5.7 funnel
//     projects the code. Only true failures (bad ref, rpc.unreachable,
//     keystore.read_only on --new) come back as a non-nil domain.Error.
//
// --new derives the wallet's next index (a keystore meta.json write → requires a
// WRITABLE keystore; a read-only Secret mount fails keystore.read_only, exit 10).
// The keystore passphrase the derive needs is resolved INSIDE the service via the
// §3.6 channels — DAXIE_PASSPHRASE[_FILE] env or the host TTY prompt (both wired
// through openService's SecretIO) — exactly like `tx send` (which also binds no
// --passphrase-* flag): the uniform Receive(ctx,Principal,Request,Sink) signature
// carries no secret channel, so agents pass DAXIE_PASSPHRASE_FILE (the M1 env
// channel) for the non-interactive --new write. The secret is never a flag value.

func newReceiveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var (
		account       string
		newAddr       bool
		wallet        string
		name          string
		amount        string
		exact         bool
		token         string
		nft           string
		contract      string
		tokenID       string
		confirmations uint64
		timeoutStr    string
		fromBlock     uint64
		qr            bool
	)
	cmd := &cobra.Command{
		Use:   "receive [--account <ref> | --new --wallet <w>] [--amount <v>] [--token <t> | --nft <c#id>]",
		Short: "Block until the account receives the expected asset (and it confirms)",
		Long: "Wait for inbound funds — the inbound counterpart that completes the\n" +
			"agent-to-agent payment loop: derive/resolve an address, hand it to the\n" +
			"counterparty, block until paid. The receiving address is emitted IMMEDIATELY\n" +
			"(before blocking). With --json the output is a line-delimited NDJSON event\n" +
			"stream on stdout (listening → detected → confirming → confirmed (per inbound\n" +
			"transfer) → complete); on timeout the terminal line is `timeout` (exit 8 —\n" +
			"not a failure; re-run to resume, detection is stateless). --new derives the\n" +
			"wallet's next index (requires a writable keystore). --confirmations defaults\n" +
			"to the per-network value; --timeout DEFAULTS TO NONE (unbounded invoice\n" +
			"wait). --amount is a cumulative minimum unless --exact (one single\n" +
			"attributable transfer equal to the amount). --qr also prints the address as\n" +
			"a terminal QR.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Mutual-exclusion + dependency checks the cli owns up front (usage exit 2);
			// the service re-validates (the MCP/HTTP surfaces never run these flag rules).
			if token != "" && nft != "" {
				return domain.New(domain.CodeUsage+".token_and_nft",
					"--token and --nft are mutually exclusive")
			}
			if exact && amount == "" {
				return domain.New(domain.CodeUsage+".exact_needs_amount",
					"--exact requires --amount (there is no single transfer to match)")
			}
			if newAddr && wallet == "" {
				return domain.New(domain.CodeUsage+".new_needs_wallet",
					"--new requires --wallet (the wallet to derive the fresh invoice index from)")
			}
			if newAddr && account != "" {
				return domain.New(domain.CodeUsage+".new_and_account",
					"--new derives a fresh address; do not also pass --account")
			}
			// The --nft alternative form: --contract + --token-id collapses into the
			// same <collection#tokenId> reference the service's NFT resolver consumes.
			nftRef, err := combineNFTRef(nft, contract, tokenID)
			if err != nil {
				return err
			}

			req := domain.ReceiveRequest{
				New:     newAddr,
				Wallet:  wallet,
				Name:    name,
				Amount:  amount,
				Exact:   exact,
				Token:   token,
				NFT:     nftRef,
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
				QR:      qr,
			}
			// --account is only meaningful without --new (the --new path derives a
			// fresh index instead of resolving an existing ref).
			if !newAddr {
				req.Account = resolveFrom(rs, account)
			}
			if cmd.Flags().Changed("confirmations") {
				c := confirmations
				req.Confirmations = &c
			}
			if cmd.Flags().Changed("from-block") {
				fb := fromBlock
				req.FromBlock = &fb
			}
			if timeoutStr != "" {
				// A frontend may parse time strings (the determinism guard binds the
				// core, not the cli). An unset --timeout leaves the unbounded default.
				d, perr := time.ParseDuration(timeoutStr)
				if perr != nil {
					return domain.Newf(domain.CodeUsage+".bad_timeout",
						"invalid --timeout %q: %v", timeoutStr, perr)
				}
				req.Timeout = domain.Duration{D: d}
			}

			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			m := rs.flags.Mode()
			// §5.9: receive's stream is the PRIMARY output on STDOUT (the address up
			// front, the terminal line carrying exit) — NOT the StderrProgress sink.
			out := cmd.OutOrStdout()
			sink := render.ReceiveStream(out, m.JSON)
			// --qr is a human-only decoration: render the receiving address as a
			// terminal QR right after the up-front `listening` line. Under --json it is
			// suppressed (a QR block would corrupt the NDJSON stream); the qrSink wraps
			// the stream sink and emits the QR once, from the listening event's address.
			if qr && !m.JSON {
				sink = qrSink(out, m, sink)
			}

			res, err := svc.Receive(cmd.Context(), domain.LocalCLI(), req, sink)
			return renderReceiveOutcome(res, err)
		},
	}

	fl := cmd.Flags()
	fl.StringVar(&account, "account", "", "existing receiving account ref (default: the configured default account)")
	fl.BoolVar(&newAddr, "new", false, "derive a fresh invoice address from --wallet (requires a writable keystore)")
	fl.StringVar(&wallet, "wallet", "", "the wallet to derive the fresh --new index from")
	fl.StringVar(&name, "name", "", "alias the fresh --new index in one step (e.g. invoice-1042)")
	fl.StringVar(&amount, "amount", "", "expected amount: ETH human (0.5) or token/1155 base units (100); omit for any-inbound")
	fl.BoolVar(&exact, "exact", false, "require ONE single attributable transfer exactly equal to --amount")
	fl.StringVar(&token, "token", "", "ERC-20 token by alias or 0x contract (mutually exclusive with --nft)")
	fl.StringVar(&nft, "nft", "", "the NFT: <collection#tokenId> (alias or 0x) or an NFT alias (mutually exclusive with --token)")
	fl.StringVar(&contract, "contract", "", "the NFT collection 0x contract (the --nft alternative form, with --token-id)")
	fl.StringVar(&tokenID, "token-id", "", "the NFT token id (with --contract; a decimal integer)")
	fl.Uint64Var(&confirmations, "confirmations", 0, "confirmation target (default: per-network)")
	fl.StringVar(&timeoutStr, "timeout", "", "bounded listen, e.g. 30m (default: none — unbounded invoice wait)")
	fl.Uint64Var(&fromBlock, "from-block", 0, "resume baseline: scan from this block (default: the head at listen start)")
	fl.BoolVar(&qr, "qr", false, "also render the receiving address as a terminal QR code")
	return cmd
}

// combineNFTRef collapses the --nft / (--contract + --token-id) reference forms
// into the single <collection#tokenId> string the service's NFT resolver
// consumes (the SAME forms `daxie nft` accepts). Exactly one form may be given;
// --nft alone, OR --contract + --token-id together. Returns "" when no NFT is
// requested (the ETH/token paths).
func combineNFTRef(nft, contract, tokenID string) (string, error) {
	if nft != "" {
		if contract != "" || tokenID != "" {
			return "", domain.New(domain.CodeUsage+".bad_nft_ref",
				"pass either --nft OR --contract/--token-id, not both")
		}
		return nft, nil
	}
	if contract == "" && tokenID == "" {
		return "", nil // no NFT requested
	}
	if contract == "" || tokenID == "" {
		return "", domain.New(domain.CodeUsage+".bad_nft_ref",
			"--contract and --token-id must be given together (or use --nft <collection#tokenId>)")
	}
	return contract + "#" + tokenID, nil
}

// renderReceiveOutcome funnels the (ReceiveResult, error) into the §5.7 exit code.
// A normal terminal outcome (complete OR timeout) is returned as (result, nil) by
// the service — the terminal NDJSON/human line is ALREADY emitted through the sink
// (the agent parses it from the stream), so this func only translates result.Exit
// into the process exit code:
//   - complete (exit 0) → nil error → exit 0;
//   - timeout (exit 8) → a typed receive.timeout domain.Error so the central
//     mapError funnel projects exit 8 WITHOUT printing a second envelope to stderr
//     that competes with the stream (mirrors `tx wait` timeout: the resume info is
//     on stdout, not stderr).
//
// A true failure (err != nil) funnels straight through unchanged (its own §5.7
// code on the error envelope).
func renderReceiveOutcome(res domain.ReceiveResult, err error) error {
	if err != nil {
		return err
	}
	if res.Exit == int(domain.ExitTimeoutPending) {
		// Quiet timeout: the timeout NDJSON/human line (with the resume string) is
		// already on stdout. Return a typed error carrying ONLY the exit code; its
		// message is terse because the actionable detail (resume) lives on the
		// stream the agent already parsed.
		return domain.New("receive.timeout", "listen timed out; resume from the stream's last line")
	}
	return nil
}

// qrSink wraps the receive EventSink so the receiving address is rendered as a
// terminal QR (human mode only) immediately after the up-front `listening` line.
// It is a no-op decoration: it forwards EVERY event to the inner sink unchanged
// and, on the first `listening`, additionally writes the QR block for that line's
// address. Subsequent events pass straight through.
func qrSink(out io.Writer, m render.Mode, inner domain.EventSink) domain.EventSink {
	printed := false
	return func(ev domain.Event) {
		if inner != nil {
			inner(ev)
		}
		if !printed && ev.Kind == domain.EvListening {
			printed = true
			render.QR(out, m, ev.Address.Hex())
		}
	}
}
