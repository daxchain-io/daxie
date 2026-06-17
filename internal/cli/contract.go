package cli

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// contract.go is the `daxie contract` command tree (cli-spec §`daxie contract`, design
// §2.5/§4.2/§4.3/§5.1/§5.11/§7.8). It is the broadest-reach surface: the contract
// registry (add/list/show/remove), the PURE read/build paths (call/logs/encode/decode),
// and `contract send` — the calldata-bearing signing path.
//
// Thin host: it binds flags into the domain request structs, reads the --abi file /
// --abi-stdin bytes (a frontend I/O concern), opens the service, wires the §5.9 stderr
// progress sink for the broadcasting send, and renders the single result. ALL signing-
// side logic lives in service — the §4.2 ClassifyCalldata (which keeps a `contract send`
// from bypassing the typed approval ceremonies), the §4.3 stage-5b unknown-calldata
// gate, the §5.1 authorize/settle kernel. The arch matrix + the M10 per-file guard
// forbid this file from reaching a provider, so it physically cannot route around the
// policy chokepoint.
//
// Exit codes (§5.7): 0 ok; 2 usage (bad ABI/sig/arg/calldata/address, ambiguous ABI
// source, --unlimited without --yes — the deliberate-ack-needs-confirm guard, mirroring
// `token approve`); 3 policy.denied (a recognized spend-equivalent gated like the typed
// path — incl. an unlimited approval signed without --unlimited → unlimited_unacked — OR
// the stage-5b contract_call deny for an unrecognized selector); 6 rpc.unreachable; 7
// tx.reverted (an eth_call revert / a reverted send --wait); 10 ref.not_found (unknown
// alias) / read-only mount. NO exit 3 is reachable from call/logs/encode/decode — they
// never touch policy (§5.11).

// abiSourceFlags is the shared ABI-source flag group: --abi (file path), --abi-stdin,
// --sig. The frontend reads the file/stdin bytes and hands them to core as
// ABISource.ABIJSON; --sig is passed through verbatim. Precedence (registered alias's
// stored ABI > --abi/--abi-stdin > --sig) is enforced in core.
type abiSourceFlags struct {
	abiFile  string
	abiStdin bool
	sig      string
}

func (a *abiSourceFlags) bind(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&a.abiFile, "abi", "", "path to a contract ABI JSON file")
	fl.BoolVar(&a.abiStdin, "abi-stdin", false, "read the contract ABI JSON from stdin")
	fl.StringVar(&a.sig, "sig", "", "inline signature, e.g. \"earned(address)(uint256)\"")
}

// toABISource reads the file/stdin bytes (the I/O the frontend owns) and builds the
// domain.ABISource. --abi and --abi-stdin are mutually exclusive. The alias is filled by
// the caller (it is the first positional when registered); encode/decode pass it through
// ABISource.Alias so core resolves a registered ABI.
func (a *abiSourceFlags) toABISource(cmd *cobra.Command, alias string) (domain.ABISource, error) {
	src := domain.ABISource{Alias: alias, Sig: strings.TrimSpace(a.sig)}
	switch {
	case a.abiStdin && a.abiFile != "":
		return domain.ABISource{}, domain.New(domain.CodeUsage+".ambiguous_abi",
			"pass exactly one of --abi or --abi-stdin")
	case a.abiStdin:
		b, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return domain.ABISource{}, domain.Wrap(domain.CodeUsage+".bad_abi", "cannot read the ABI from stdin", err)
		}
		src.ABIJSON = string(b)
	case a.abiFile != "":
		b, err := os.ReadFile(a.abiFile) // #nosec G304 -- operator-supplied ABI path, read-only
		if err != nil {
			return domain.ABISource{}, domain.Wrap(domain.CodeUsage+".bad_abi", "cannot read the ABI file "+a.abiFile, err)
		}
		src.ABIJSON = string(b)
	}
	return src, nil
}

func newContractCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contract",
		Short: "Call, send to, and inspect arbitrary contracts (ABI-driven)",
		Long: "Interact with any contract by its ABI. Register a contract (`contract add`)\n" +
			"to bind an alias to an address + an inline ABI, or pass --abi/--abi-stdin/--sig\n" +
			"ad hoc. `call`/`logs`/`encode`/`decode` are PURE reads — they never sign and never\n" +
			"touch policy. `send` is the broadest-reach signing path: its calldata is\n" +
			"CLASSIFIED before signing, so a contract send carrying an ERC-20 approve hits the\n" +
			"SAME spender-allowlist + --unlimited --yes ceremony as `token approve`, and an\n" +
			"unrecognized selector is denied by default (admit it with `policy contract allow`).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newContractAddCmd(ctx, rs),
		newContractListCmd(ctx, rs),
		newContractShowCmd(ctx, rs),
		newContractRemoveCmd(ctx, rs),
		newContractCallCmd(ctx, rs),
		newContractSendCmd(ctx, rs),
		newContractLogsCmd(ctx, rs),
		newContractEncodeCmd(ctx, rs),
		newContractDecodeCmd(ctx, rs),
	)
	return cmd
}

// ── registry: add / list / show / remove ──────────────────────────────────────

func newContractAddCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var as abiSourceFlags
	cmd := &cobra.Command{
		Use:   "add <alias> <0xaddr> (--abi <file> | --abi-stdin)",
		Short: "Register a contract alias → address + inline ABI (validated)",
		Long: "Bind an alias to a contract address AND its ABI as ONE anti-spoofing unit\n" +
			"(they can never drift). The ABI is validated before storing (an invalid ABI is\n" +
			"rejected, never stored). Resolution is registry-only; the stored ABI is a\n" +
			"display/encode convenience and can never change a send's destination.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if as.sig != "" {
				return domain.New(domain.CodeUsage+".bad_abi", "`contract add` needs a full ABI (--abi/--abi-stdin), not --sig")
			}
			src, err := as.toABISource(cmd, "")
			if err != nil {
				return err
			}
			if strings.TrimSpace(src.ABIJSON) == "" {
				return domain.New(domain.CodeUsage+".no_abi", "an ABI is required: pass --abi <file> or --abi-stdin")
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContractAdd(cmd.Context(), domain.LocalCLI(), domain.ContractAddRequest{
				Alias:   args[0],
				Address: args[1],
				ABIJSON: src.ABIJSON,
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "added contract %s -> %s on %s", res.Alias, res.Address, res.Network)
			})
		},
	}
	as.bind(cmd)
	return cmd
}

func newContractListCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered contracts for the network (alias-sorted)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContractList(cmd.Context(), domain.LocalCLI(), domain.ContractListRequest{Network: rs.flags.Network})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) { render.ContractList(w, m, res) })
		},
	}
}

func newContractShowCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "show <alias>",
		Short: "Show a registered contract's address + ABI summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContractShow(cmd.Context(), domain.LocalCLI(), domain.ContractShowRequest{Alias: args[0], Network: rs.flags.Network})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) { render.ContractRow(w, m, res) })
		},
	}
}

func newContractRemoveCmd(ctx context.Context, rs *rootState) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <alias>",
		Short: "Remove a registered contract alias",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := confirmDestructive(cmd, rs, args[0], "remove contract"); err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContractRemove(cmd.Context(), domain.LocalCLI(), domain.ContractRemoveRequest{Alias: args[0], Network: rs.flags.Network})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.Line(w, m, "removed contract %s", res.Alias)
			})
		},
	}
}

// ── pure reads: call / logs / encode / decode ─────────────────────────────────

func newContractCallCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var as abiSourceFlags
	var from, block string
	cmd := &cobra.Command{
		Use:   "call <alias|0x|ens> [method] [args...] [--sig S | --abi F | --abi-stdin]",
		Short: "Read a contract via eth_call (pure; never signs, never policy)",
		Long: "Call a view/pure function and decode its return values. The ABI comes from a\n" +
			"registered alias, --abi/--abi-stdin, or an inline --sig (which must declare the\n" +
			"return types, e.g. \"earned(address)(uint256)\"). --from sets an optional\n" +
			"msg.sender (not a signer); --block reads at a number (default latest). A read\n" +
			"path: no signing, no policy, no exit 3.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contract := args[0]
			method, callArgs := splitMethodArgs(args[1:], as.sig)
			src, err := as.toABISource(cmd, "")
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContractCall(cmd.Context(), domain.LocalCLI(), domain.ContractCallRequest{
				Contract: contract,
				Method:   method,
				Args:     callArgs,
				ABI:      src,
				From:     from,
				Block:    block,
				Network:  rs.flags.Network,
				RPC:      rs.flags.RPC,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) { render.ContractCallResult(w, m, res) })
		},
	}
	as.bind(cmd)
	cmd.Flags().StringVar(&from, "from", "", "optional msg.sender (address/ENS/account ref); NOT a signer")
	cmd.Flags().StringVar(&block, "block", "", "block number to read at (default: latest)")
	return cmd
}

func newContractLogsCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var as abiSourceFlags
	var fromBlock, toBlock string
	var argFilters []string
	cmd := &cobra.Command{
		Use:   "logs <alias|0x|ens> [event] [--sig S | --abi F] [--arg name=value ...]",
		Short: "Read + decode contract event logs via eth_getLogs (pure)",
		Long: "Fetch and decode an event's logs over a block range. --arg name=value filters\n" +
			"on an INDEXED arg (a filter on a non-indexed arg is a usage error). The range\n" +
			"defaults to [0, latest] and is chunked by the receive.max-log-range splitter.\n" +
			"A read path: no signing, no policy.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contract := args[0]
			event, _ := splitMethodArgs(args[1:], as.sig)
			src, err := as.toABISource(cmd, "")
			if err != nil {
				return err
			}
			filters, err := parseArgFilters(argFilters)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.ContractLogs(cmd.Context(), domain.LocalCLI(), domain.ContractLogsRequest{
				Contract:  contract,
				Event:     event,
				ABI:       src,
				Args:      filters,
				FromBlock: fromBlock,
				ToBlock:   toBlock,
				Network:   rs.flags.Network,
				RPC:       rs.flags.RPC,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) { render.ContractLogs(w, m, res) })
		},
	}
	as.bind(cmd)
	cmd.Flags().StringSliceVar(&argFilters, "arg", nil, "indexed-arg filter name=value (repeatable)")
	cmd.Flags().StringVar(&fromBlock, "from-block", "", "start block (default: 0)")
	cmd.Flags().StringVar(&toBlock, "to-block", "", "end block (default: latest)")
	return cmd
}

func newContractEncodeCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var as abiSourceFlags
	cmd := &cobra.Command{
		Use:   "encode <alias|0x> [method] [args...] [--sig S | --abi F]",
		Short: "Build 0x calldata for a method (pure; no chain, no policy)",
		Long: "Encode selector||abi(args) → 0x calldata for relayers/meta-tx/debugging. A pure\n" +
			"function: no chain, no signing, no policy. (Classifying a hex string encode\n" +
			"merely emits would gate nothing.)",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contract := args[0]
			method, encArgs := splitMethodArgs(args[1:], as.sig)
			// encode resolves a registered alias's ABI via ABISource.Alias.
			src, err := as.toABISource(cmd, aliasIfRegistrable(contract))
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.EncodeCalldata(cmd.Context(), domain.LocalCLI(), domain.EncodeRequest{
				Method:  method,
				Args:    encArgs,
				ABI:     src,
				Network: rs.flags.Network,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) { render.EncodeResult(w, m, res) })
		},
	}
	as.bind(cmd)
	return cmd
}

func newContractDecodeCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var as abiSourceFlags
	var alias string
	cmd := &cobra.Command{
		Use:   "decode 0x<calldata> (--sig S | --abi F | --contract <alias>)",
		Short: "Decode 0x calldata to method + values (pure; no chain, no policy)",
		Long: "Decode raw 0x calldata against an ABI (--sig/--abi or a registered --contract).\n" +
			"It reads the leading 4-byte selector, resolves the method, and decodes the args.\n" +
			"A pure function: no chain, no signing, no policy.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src, err := as.toABISource(cmd, alias)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := svc.DecodeCalldata(cmd.Context(), domain.LocalCLI(), domain.DecodeRequest{
				Calldata: args[0],
				ABI:      src,
				Network:  rs.flags.Network,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) { render.DecodeResult(w, m, res) })
		},
	}
	as.bind(cmd)
	cmd.Flags().StringVar(&alias, "contract", "", "a registered contract alias whose stored ABI decodes the calldata")
	return cmd
}

// ── the signing path: send ────────────────────────────────────────────────────

func newContractSendCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var as abiSourceFlags
	var from, value string
	var dryRun, unlimited bool
	var gf gasFlags
	var wf waitFlags
	cmd := &cobra.Command{
		Use:   "send <alias|0x|ens> [method] [args...] [--value V] [--abi/--sig] [gas/wait flags]",
		Short: "Build, sign, and broadcast an arbitrary contract call",
		Long: "Build calldata for a method, sign it, and broadcast it. The contract is the tx\n" +
			"DESTINATION and the policy destination (resolved + echoed before signing). The\n" +
			"calldata is CLASSIFIED before signing (§4.2): a recognized ERC-20/721/1155/permit\n" +
			"selector is gated EXACTLY like the typed path (spender allowlist + --unlimited\n" +
			"--yes ceremony + fail-closed) — a `contract send` carrying approve(attacker, MAX)\n" +
			"cannot bypass `token approve`. When the calldata encodes an UNLIMITED approval\n" +
			"(MAX amount / setApprovalForAll(true) / a permit sentinel), it requires the\n" +
			"DELIBERATE --unlimited acknowledgement (which itself requires --yes), identical to\n" +
			"`token approve --unlimited`; --yes alone never signs an unlimited approval. An\n" +
			"unrecognized selector to a non-allowlisted contract is DENIED by default (admit the\n" +
			"(network,contract,selector) triple with `policy contract allow`). --value is\n" +
			"msg.value and counts vs spend limits. --dry-run shows the classification verdict\n" +
			"without signing. --yes is required non-interactive.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			contract := args[0]
			method, sendArgs := splitMethodArgs(args[1:], as.sig)
			src, err := as.toABISource(cmd, "")
			if err != nil {
				return err
			}
			// The unlimited acknowledgement ceremony (§4.2): the DELIBERATE --unlimited ack
			// requires the explicit --yes, EXACTLY as on the typed `token approve --unlimited`
			// path (token.go). Refuse early with a clear usage error (exit 2) so an agent
			// learns the requirement without burning a signing attempt. (The service +
			// policy enforce the ack itself again — defense in depth.)
			if unlimited && !rs.flags.Yes {
				return domain.New(domain.CodeUsage+".unlimited_unacked",
					"--unlimited acknowledges an infinite allowance; re-run with --yes to acknowledge")
			}
			w, err := wf.toWaitOpts(cmd)
			if err != nil {
				return err
			}
			req := domain.ContractSendRequest{
				Contract:     contract,
				Method:       method,
				Args:         sendArgs,
				ABI:          src,
				Value:        value,
				From:         resolveFrom(rs, from),
				Network:      rs.flags.Network,
				RPC:          rs.flags.RPC,
				DryRun:       dryRun,
				Yes:          rs.flags.Yes, // TTY-skip only (json:"-")
				AckUnlimited: unlimited,    // the DELIBERATE unlimited acknowledgement (--unlimited, gated on --yes above)
				Wait:         w,
			}
			applyGasToContractSend(cmd, &gf, &req)

			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()
			m := rs.flags.Mode()
			sink := render.StderrProgress(cmd.ErrOrStderr(), m.JSON)
			res, err := svc.ContractSend(cmd.Context(), domain.LocalCLI(), req, sink)
			return renderTxOutcome(cmd, m, res, err)
		},
	}
	as.bind(cmd)
	cmd.Flags().StringVar(&from, "from", "", "sending account ref (default: the configured default account)")
	cmd.Flags().StringVar(&value, "value", "", "msg.value to send, e.g. 0.5 or 0.5eth (counts vs spend limits)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "build + classify + preview; do not sign or broadcast")
	cmd.Flags().BoolVar(&unlimited, "unlimited", false, "acknowledge an UNLIMITED approval in the calldata (requires --yes); --yes alone never signs one")
	gf.bind(cmd)
	wf.bind(cmd)
	return cmd
}

// ── helpers ───────────────────────────────────────────────────────────────────

// splitMethodArgs splits the trailing positionals into the method name + its args. When
// --sig carries the method name, ALL trailing positionals are args (the first is not the
// method). Otherwise the first positional is the method name and the rest are args.
func splitMethodArgs(rest []string, sig string) (method string, args []string) {
	if strings.TrimSpace(sig) != "" {
		// --sig carries the name; every positional is an arg.
		return "", rest
	}
	if len(rest) == 0 {
		return "", nil
	}
	return rest[0], rest[1:]
}

// parseArgFilters parses the repeated --arg name=value into domain.LogFilter[]. A flag
// without an '=' is a usage error.
func parseArgFilters(raw []string) ([]domain.LogFilter, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]domain.LogFilter, 0, len(raw))
	for _, kv := range raw {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			return nil, domain.Newf(domain.CodeUsage+".bad_arg", "--arg must be name=value, got %q", kv)
		}
		out = append(out, domain.LogFilter{Name: strings.TrimSpace(kv[:i]), Value: strings.TrimSpace(kv[i+1:])})
	}
	return out, nil
}

// aliasIfRegistrable returns the ref as a candidate registry alias for encode (which has
// no contract destination — only the ABI matters). A raw 0x is not an alias; core's
// Resolve treats a non-grammar name as a clean miss, so passing the ref through as the
// alias is harmless (an unregistered name falls through to --abi/--sig).
func aliasIfRegistrable(ref string) string {
	if strings.HasPrefix(ref, "0x") || strings.HasPrefix(ref, "0X") {
		return ""
	}
	return ref
}

// applyGasToContractSend copies the gas overrides onto a ContractSendRequest, threading
// --nonce only when the operator set it (so an unset --nonce leaves Nonce nil → service
// derives it under the account lock, §5.6). The contract-send gas surface is IDENTICAL
// to tx send's.
func applyGasToContractSend(cmd *cobra.Command, g *gasFlags, req *domain.ContractSendRequest) {
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
