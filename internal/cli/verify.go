package cli

import (
	"context"
	"io"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// verify.go is the `daxie verify` command (cli-spec §`daxie verify`, design §4.2):
// recover the signer from a signature over an EIP-191 message or an EIP-712 typed
// document and assert it equals a claimed address (a 0x literal OR an ENS name,
// resolved per-invocation). It is a thin host — it parses the payload + signature +
// claimed address into a domain.VerifyRequest, opens the service, and renders the
// one VerifyResult. The ecrecover + digest reconstruction + ENS resolution all live
// in the core.
//
// Exactly one of --message / --typed (or their -stdin forms) selects the scheme.
// --signature is the 0x 65-byte signature; --address is the claimed signer. A
// recovered≠claimed mismatch renders the populated result on STDOUT (so an agent can
// read the address that actually signed) and THEN funnels verify.mismatch → exit 2
// (a validation outcome, NOT exit 4 — exit 4 is reserved for a wrong keystore
// passphrase; conflating them would make an agent confuse "your passphrase is wrong"
// with "this signature doesn't verify").

func newVerifyCmd(ctx context.Context, rs *rootState) *cobra.Command {
	var (
		message, typedFile, signature, address string
		messageStdin, typedStdin, noHash       bool
	)
	cmd := &cobra.Command{
		Use:   "verify --signature <0x...> --address <0x|name.eth> (--message <text> | --typed <file>)",
		Short: "Verify an EIP-191 / EIP-712 signature against a claimed signer",
		Long: "Recover the signer from a signature and assert it equals the claimed address\n" +
			"(a 0x address or an ENS name, resolved per-invocation). The EIP-191 path\n" +
			"rebuilds the \\x19 personal-sign digest; the EIP-712 path rebuilds the typed\n" +
			"document digest. Exit 0 when the recovered address matches; exit 2\n" +
			"(verify.mismatch) when it does not (the recovered address is printed).\n\n" +
			"Exactly one of --message / --message-stdin / --typed / --typed-stdin selects\n" +
			"the scheme. --no-hash (EIP-191 only): the message is a pre-hashed 0x 32-byte\n" +
			"digest over which the EIP-191 prefix is reconstructed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if signature == "" {
				return domain.New(domain.CodeUsage+".missing_signature", "--signature is required")
			}
			if address == "" {
				return domain.New(domain.CodeUsage+".missing_address", "--address is required (the claimed signer)")
			}

			req := domain.VerifyRequest{
				NoHash:    noHash,
				Signature: signature,
				Address:   address,
				Network:   rs.flags.Network,
				RPC:       rs.flags.RPC,
			}
			if err := fillVerifyPayload(cmd, &req, message, messageStdin, typedFile, typedStdin, noHash); err != nil {
				return err
			}

			svc, closeFn, err := openService(ctx, rs)
			if err != nil {
				return err
			}
			defer closeFn()

			res, verr := svc.Verify(cmd.Context(), domain.LocalCLI(), req)
			// §5.3-style terminal-but-populated projection: a mismatch returns a
			// populated VerifyResult AND the verify.mismatch error. Render the result
			// (so the agent sees the recovered address) BEFORE funneling the error for
			// the exit code. A pre-verify error (bad sig/payload, unresolvable ENS) has
			// an empty result and skips stdout.
			m := rs.flags.Mode()
			if res.Recovered != "" {
				if rerr := render.Result(cmd.OutOrStdout(), m, res, func(w io.Writer) {
					render.VerifyResultHuman(w, m, res)
				}); rerr != nil {
					return rerr
				}
			}
			return verr
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&message, "message", "", "the EIP-191 message text to verify")
	fl.BoolVar(&messageStdin, "message-stdin", false, "read the EIP-191 message from stdin")
	fl.StringVar(&typedFile, "typed", "", "path to the EIP-712 typed-data JSON document to verify")
	fl.BoolVar(&typedStdin, "typed-stdin", false, "read the EIP-712 typed-data JSON from stdin")
	fl.StringVar(&signature, "signature", "", "the 0x 65-byte signature (required)")
	fl.StringVar(&address, "address", "", "the claimed signer: a 0x address or an ENS name (required)")
	fl.BoolVar(&noHash, "no-hash", false, "EIP-191 only: the message is a pre-hashed 0x 32-byte digest")
	return cmd
}

// fillVerifyPayload sets exactly one of req.Message / req.Typed from the scheme
// flags. Exactly one source must be present across both schemes. The EIP-191 paths
// (--message / --message-stdin) honor --no-hash by decoding a 0x 32-byte digest in
// the frontend (the single decode point shared with `sign message`); the EIP-712
// paths (--typed / --typed-stdin) carry the raw JSON. --no-hash with --typed is a
// usage error (the digest form is EIP-191 only).
func fillVerifyPayload(cmd *cobra.Command, req *domain.VerifyRequest, message string, messageStdin bool, typedFile string, typedStdin, noHash bool) error {
	sources := 0
	msgSelected := cmd.Flags().Changed("message") || messageStdin
	if msgSelected {
		sources++
	}
	if typedFile != "" || typedStdin {
		sources++
	}
	if sources != 1 {
		return domain.New(domain.CodeUsage+".bad_scheme",
			"provide exactly one of --message / --message-stdin / --typed / --typed-stdin")
	}

	if typedFile != "" || typedStdin {
		if noHash {
			return domain.New(domain.CodeUsage+".bad_flags", "--no-hash applies to --message only (EIP-191), not --typed")
		}
		typed, err := readTypedPayload(cmd, typedFile, typedStdin)
		if err != nil {
			return err
		}
		req.Typed = typed
		return nil
	}

	// EIP-191 message path.
	var raw []byte
	if messageStdin {
		b, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return domain.Wrap(domain.CodeSignBadMessage, "cannot read the message from stdin", err)
		}
		raw = b
	} else {
		raw = []byte(message)
	}
	if noHash {
		d, err := decodeDigest32(string(raw), domain.CodeVerifyBadSig)
		if err != nil {
			return err
		}
		req.Message = d
		return nil
	}
	req.Message = raw
	return nil
}
