package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/daxchain-io/daxie/internal/service"
	"golang.org/x/term"
)

// openService composes the core for a command that needs it. The cli frontend is
// the host that supplies the real wall clock AND the §3.6 secret-acquisition host
// primitives (frontends may read time.Now / os / the TTY; the core may not —
// §2.3). It returns the service and a cleanup func the caller defers. service.Open
// is lazy for a fresh keystore (it provisions nothing) but runs change-passphrase
// crash recovery + the derivation-watermark check at Open (M1, §3.8).
//
// NOTE: the frontend hands the core PLAIN host primitives (os.Stdin, os.LookupEnv,
// an isTTY func). It never imports the secret provider — the arch matrix forbids
// frontend→secret; the core owns the secret.Request assembly. The isTTY closure
// is built here from os + golang.org/x/term (external, permitted) directly, so no
// frontend→provider edge is created.
func openService(ctx context.Context, rs *rootState) (*service.Service, func(), error) {
	opts := rs.flags.ServiceOptions()
	opts.Clock = time.Now // the ONE real clock injection; the core reads it via s.Now()

	// §7.7 default-account precedence is flag>env (the meta.json layer is keys').
	// The frontend resolves the flag>env part here so the core never reads os.
	opts.Account = rs.flags.Account
	if opts.Account == "" {
		if v, ok := os.LookupEnv("DAXIE_ACCOUNT"); ok {
			opts.Account = v
		}
	}

	opts.Secret = service.SecretIO{
		Stdin:     os.Stdin,
		LookupEnv: os.LookupEnv,
		IsTTY:     func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		// The prompt is a host TTY primitive built here from os + x/term (external,
		// permitted) — the frontend never imports internal/secret (the arch matrix
		// forbids frontend→provider). The core threads this into secret.Acquire's
		// prompt branch + the §3.3 first-init double-entry. Hidden input; label on
		// stderr so stdout stays clean for piping.
		Prompt: ttyPrompt,
	}

	svc, err := service.Open(ctx, opts)
	if err != nil {
		return nil, func() {}, err
	}
	return svc, func() { _ = svc.Close() }, nil
}

// ttyPrompt reads one secret from the terminal with echo disabled (the host TTY
// primitive the core threads through SecretIO.Prompt). The label is written to
// stderr so stdout stays clean for piping; ReadPassword consumes the user's
// Enter, and we emit the newline ourselves. Mirrors the secret package's default
// terminal reader but lives in the frontend so the core never owns a real TTY
// read and the arch matrix's frontend→secret prohibition is respected.
func ttyPrompt(label string) ([]byte, error) {
	fmt.Fprint(os.Stderr, label)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return pw, nil
}
