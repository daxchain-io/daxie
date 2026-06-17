package render

import (
	"io"

	"github.com/daxchain-io/daxie/internal/domain"
)

// sign.go holds the human renderers for the M9 `daxie sign` / `daxie verify`
// surface (cli-spec §`daxie sign`/§`daxie verify`). It formats only — the --json
// form is the domain struct (domain.SigResult / domain.VerifyResult) marshaled by
// Result; these funcs are the human-mode branch. Every helper honors Mode.Quiet
// via render.Line for the non-essential context while always printing the one
// essential value (the signature hex for sign, the validity word for verify).
//
// No float anywhere (§2.5): a signature, a digest, and an address are all hex
// strings on the domain result; we print them verbatim.

// SigResultHuman writes the human view of a sign op. The 0x signature is the one
// essential output (printed even under --quiet, like a tx hash) so a script reading
// stdout always captures it; signer/digest/scheme are non-essential context lines.
func SigResultHuman(w io.Writer, m Mode, r domain.SigResult) {
	if r.Signature != "" {
		_, _ = io.WriteString(w, r.Signature+"\n")
	}
	Line(w, m, "signer: %s", r.Signer)
	Line(w, m, "digest: %s", r.Digest)
	Line(w, m, "scheme: %s", r.Scheme)
}

// VerifyResultHuman writes the human view of a verify op. The VALIDITY word
// ("valid"/"invalid") is the essential output (printed even under --quiet); the
// claimed signer, the recovered address, the digest, and the scheme are context.
// A mismatch still renders this view (the command body emits it BEFORE returning
// the verify.mismatch error so the agent can read the recovered address), exactly
// like the tx-outcome path emits a populated-but-terminal result before the exit
// code is funneled.
func VerifyResultHuman(w io.Writer, m Mode, r domain.VerifyResult) {
	word := "invalid"
	if r.Valid {
		word = "valid"
	}
	_, _ = io.WriteString(w, word+"\n")
	Line(w, m, "signer:    %s", r.Signer)
	Line(w, m, "recovered: %s", r.Recovered)
	Line(w, m, "digest:    %s", r.Digest)
	Line(w, m, "scheme:    %s", r.Scheme)
}
