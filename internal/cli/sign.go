package cli

import (
	"context"
	"encoding/hex"
	"io"
	"os"
	"strings"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// sign.go is the `daxie sign` command tree (cli-spec §`daxie sign`, design §2.7/
// §4.2): `sign message` (EIP-191 personal_sign) and `sign typed` (EIP-712 typed
// data). It is a thin host — it parses the payload (a positional/--stdin message or
// a --data file / --data-stdin JSON document) into a domain request, opens the
// service, and renders the one SigResult. ALL signing-side logic lives in the core:
//   - EIP-191 ALWAYS applies the \x19Ethereum Signed Message:\n<len> prefix (the
//     core does this, over the raw bytes OR the 32-byte --no-hash digest). Raw
//     unprefixed eth_sign is NEVER exposed (§4.2 row 2).
//   - EIP-712 routes through the §2.7 authorizeSignature gate BEFORE the key is
//     touched: a recognized spend-equivalent (EIP-2612 / DAI / Permit2) is
//     policy-checked at SIGNATURE time exactly like an on-chain approval; an
//     unrecognized typed message hits the §4.3 stage-5 typed-data gate. The cli
//     cannot route around it (the arch matrix forbids frontend→provider).
//
// The keystore passphrase the signer needs is resolved INSIDE the service via the
// §3.6 precedence (DAXIE_PASSPHRASE[_FILE] / the host TTY prompt, both wired through
// openService's SecretIO) — the sign use cases take no passphrase channel param, so
// this file does not bind --passphrase-* (agents pass DAXIE_PASSPHRASE_FILE, the
// same env channel every other signing demo uses).
//
// The MESSAGE PAYLOAD and the TYPED-DATA JSON are NOT secrets — they are read by the
// frontend (a positional arg / --stdin / a --data file / --data-stdin), exactly as
// `tx send --to` is a frontend-read value. Only credentials flow through SecretIO.

func newSignCmd(ctx context.Context, rs *rootState) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign off-chain messages (EIP-191 personal_sign, EIP-712 typed data)",
		Long: "Prove control of an address without a transaction: EIP-191 personal\n" +
			"messages and EIP-712 typed data (Sign-In-With-Ethereum, off-chain orders,\n" +
			"permits). Signing requires the keystore passphrase like any signing op.\n\n" +
			"A recognized spend-equivalent EIP-712 (EIP-2612 Permit / DAI / Permit2) is\n" +
			"policy-checked at SIGNATURE time exactly like an on-chain approval — a signed\n" +
			"permit moves funds with no transaction. Unknown typed data is deny-by-default\n" +
			"once a policy is active (`policy typed allow` opens a specific domain).\n\n" +
			"Secrets (the keystore passphrase) are never flag values — use\n" +
			"--passphrase-stdin / --passphrase-file or DAXIE_PASSPHRASE[_FILE] (§3.6).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(
		newSignMessageCmd(ctx, rs),
		newSignTypedCmd(ctx, rs),
	)
	return cmd
}

// ── sign message (EIP-191) ────────────────────────────────────────────────────

func newSignMessageCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var account string
	var fromStdin, noHash bool
	cmd := &cobra.Command{
		Use:   "message [text]",
		Short: "Sign an EIP-191 personal message",
		Long: "Sign a message with EIP-191 personal_sign. The message is a positional\n" +
			"argument or read from stdin with --stdin. The \\x19Ethereum Signed Message\n" +
			"prefix is ALWAYS applied (the signature is unusable as a tx/typed forgery);\n" +
			"raw unprefixed signing is never offered.\n\n" +
			"--no-hash: the message is a pre-hashed 0x 32-byte digest; the EIP-191 prefix\n" +
			"is still applied over those 32 bytes (cli-spec --no-hash).",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			payload, err := readMessagePayload(cmd, args, fromStdin, noHash)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.SignMessage(cmd.Context(), domain.LocalCLI(), domain.SignMessageRequest{
				Account: resolveFrom(rs, account),
				Message: payload,
				NoHash:  noHash,
				Network: rs.flags.Network,
				RPC:     rs.flags.RPC,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.SigResultHuman(w, m, res)
			})
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "signing account ref (default: the configured default account)")
	cmd.Flags().StringVar(&account, "from", "", "alias for --account")
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "read the message from stdin instead of a positional argument")
	cmd.Flags().BoolVar(&noHash, "no-hash", false, "the message is a pre-hashed 0x 32-byte digest (the EIP-191 prefix is still applied)")
	return cmd
}

// ── sign typed (EIP-712) ──────────────────────────────────────────────────────

func newSignTypedCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var account, dataFile string
	var dataStdin, unlimited bool
	cmd := &cobra.Command{
		Use:   "typed --data <file> | --data-stdin",
		Short: "Sign an EIP-712 typed-data document",
		Long: "Sign an EIP-712 typed-data document read from a JSON file (--data) or stdin\n" +
			"(--data-stdin). The document is classified BEFORE the key is touched: a\n" +
			"recognized spend-equivalent permit (EIP-2612 / DAI / Permit2) is policy-checked\n" +
			"like an on-chain approval (spender allowlist + the --unlimited --yes ceremony +\n" +
			"fail-closed + chain-mismatch deny); an unrecognized message hits the stage-5\n" +
			"typed-data gate (deny-by-default once a policy is active).\n\n" +
			"--unlimited: acknowledge that a recognized permit grants an UNLIMITED allowance\n" +
			"(must be paired with --yes), the same ceremony `token approve --unlimited` uses.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The --unlimited acknowledgement requires --yes, exactly like
			// `token approve --unlimited` (the §4.3 stage-6 ceremony). Refuse at the
			// frontend (exit 2) so the key is never touched without the ack pair.
			if unlimited && !rs.flags.Yes {
				return domain.New(domain.CodeUsage+".unlimited_requires_yes",
					"--unlimited acknowledges an UNLIMITED permit allowance; pass --yes to confirm")
			}
			typed, err := readTypedPayload(cmd, dataFile, dataStdin)
			if err != nil {
				return err
			}
			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, err := svc.SignTyped(cmd.Context(), domain.LocalCLI(), domain.SignTypedRequest{
				Account:      resolveFrom(rs, account),
				Typed:        typed,
				Network:      rs.flags.Network,
				RPC:          rs.flags.RPC,
				AckUnlimited: unlimited && rs.flags.Yes,
			})
			if err != nil {
				return err
			}
			m := rs.flags.Mode()
			return render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
				render.SigResultHuman(w, m, res)
			})
		},
	}
	cmd.Flags().StringVar(&account, "account", "", "signing account ref (default: the configured default account)")
	cmd.Flags().StringVar(&account, "from", "", "alias for --account")
	cmd.Flags().StringVar(&dataFile, "data", "", "path to the EIP-712 typed-data JSON document")
	cmd.Flags().BoolVar(&dataStdin, "data-stdin", false, "read the EIP-712 typed-data JSON from stdin")
	cmd.Flags().BoolVar(&unlimited, "unlimited", false, "acknowledge an UNLIMITED permit allowance (requires --yes)")
	return cmd
}

// ── shared payload readers (frontend; the message/JSON are not secrets) ─────────

// readMessagePayload resolves the EIP-191 message bytes from a positional arg or
// --stdin. Exactly one source must be present. Under --no-hash the value is a 0x
// 32-byte digest (decoded HERE so the core receives raw bytes and applies the
// EIP-191 prefix uniformly — the "prefix always applied" invariant lives in one
// place, §3 of the plan); a malformed digest is sign.bad_message (exit 2).
func readMessagePayload(cmd *cobra.Command, args []string, fromStdin, noHash bool) ([]byte, error) {
	hasArg := len(args) == 1
	if hasArg == fromStdin {
		return nil, domain.New(domain.CodeSignBadMessage,
			"provide the message as a single positional argument OR --stdin, not both/neither")
	}
	var raw []byte
	if fromStdin {
		b, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, domain.Wrap(domain.CodeSignBadMessage, "cannot read the message from stdin", err)
		}
		// A trailing newline from `echo` is part of the typed payload only when the
		// caller meant it; for parity with `echo -n` pipelines we keep bytes verbatim
		// for the raw path. (The cli-spec uses `echo -n` in its example.)
		raw = b
	} else {
		raw = []byte(args[0])
	}
	if noHash {
		return decodeDigest32(string(raw), domain.CodeSignBadMessage)
	}
	return raw, nil
}

// readTypedPayload resolves the EIP-712 JSON document from --data <file> or
// --data-stdin. Exactly one source must be present; a missing/unreadable file is
// sign.bad_typed (exit 2). The bytes are NOT validated here (the core parses +
// classifies them) — the frontend only fetches them.
func readTypedPayload(cmd *cobra.Command, dataFile string, dataStdin bool) ([]byte, error) {
	if (dataFile != "") == dataStdin {
		return nil, domain.New(domain.CodeSignBadTyped,
			"provide the typed-data document via --data <file> OR --data-stdin, not both/neither")
	}
	if dataStdin {
		b, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, domain.Wrap(domain.CodeSignBadTyped, "cannot read the typed-data document from stdin", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(dataFile) // #nosec G304 -- operator-supplied document path, read-only
	if err != nil {
		return nil, domain.Wrap(domain.CodeSignBadTyped, "cannot read the typed-data document file", err)
	}
	return b, nil
}

// decodeDigest32 parses a 0x-prefixed 32-byte hex digest. It is the single decode
// point for the --no-hash path (sign + verify), so the validation message and the
// 32-byte requirement are identical on both sides. badCode selects the caller's
// usage code (sign.bad_message vs verify.bad_signature).
func decodeDigest32(s, badCode string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil, domain.New(badCode, "--no-hash expects a 0x-prefixed 32-byte hex digest")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, domain.Wrap(badCode, "--no-hash digest is not valid hex", err)
	}
	if len(b) != 32 {
		return nil, domain.Newf(badCode, "--no-hash digest must be exactly 32 bytes, got %d", len(b))
	}
	return b, nil
}
