package service

import (
	"context"
	"io"
	"time"

	"github.com/daxchain-io/daxie/internal/config"
)

// Options is what Open consumes. The cli frontend builds it from its own global
// flags and hands it in. It carries the resolved path/network flag subset
// DIRECTLY (not a nested config.FlagValues) so the frontend never has to import
// internal/config — the arch matrix forbids any frontend→provider edge, and
// config is a provider. Open translates these fields into config.FlagValues
// internally (config is the only package that touches Viper, §2.2 rule 5).
//
// The design (§2.4) calls the composition input config.Options; the plan's
// signature contract makes the service-owned Options the wire-able shape so the
// frontend stays config-free. M0 keeps it minimal; later milestones grow it with
// provider wiring knobs.
type Options struct {
	// Path/network flag subset (the five resolved-outside-Viper vars, §7.3).
	// Empty strings mean "use the platform/env default".
	Config   string // --config (file or dir)
	Keystore string // --keystore
	StateDir string // --state-dir
	Network  string // --network (default-network override; the per-process default chain)

	// RPC is the §2.8/§7.5 per-invocation endpoint override (--rpc / DAXIE_RPC).
	// Empty means "use the selected network's default-rpc". It selects an ENDPOINT,
	// never a network: --rpc naming a network fails ref.not_found (strict
	// separation). The cli frontend fills it from --rpc>DAXIE_RPC; the core threads
	// it into each ChainRequest so a command can read a different endpoint per call
	// without reconfiguring the default (no failover in v1, just one default +
	// override).
	RPC string // --rpc (endpoint override); "" = the network's default-rpc

	// Clock is the single injected time source (§2.3 determinism guard). The
	// core never calls time.Now directly; it reads wall time only through this
	// function. A nil Clock is replaced inside Open with a determinism-safe
	// fallback (zero clock) — production hosts (cli) always inject time.Now.
	Clock func() time.Time

	// Account is the §7.7 default-account override flowing in from the frontend
	// (--from/--account flag, else DAXIE_ACCOUNT env). Empty means "fall through
	// to meta.json default_account". The core never reads the environment itself
	// (§2.3); the cli frontend resolves the flag>env layers and hands the result
	// here, and keys.Store supplies the meta.json default beneath it.
	Account string

	// Secret carries the HOST primitives the §3.6 secret resolver needs but the
	// determinism-guarded core may not touch directly: stdin, the env lookup, and
	// the TTY check. The cli frontend (which may use os, §2.3) fills these; the
	// core threads them into secret.Acquire so it never imports os. A zero value
	// is the "no secret input available" case (read-only commands, tests that
	// pass secrets explicitly).
	Secret SecretIO

	// Sleep is the injected scheduling seam (§2.3): the determinism guard bans
	// time.After/Sleep/NewTimer as call expressions inside internal/service, so the
	// M3 tx pipeline's broadcast backoff + the §5.3 wait-loop poll interval block
	// through THIS function instead — exactly as wall time flows through Clock. The
	// cli frontend injects a real ctx-aware sleeper (time.After + ctx.Done); a nil
	// Sleep falls back to an immediate, no-delay return (so tests run fast and the
	// guard stays green by construction). It MUST honor ctx cancellation.
	Sleep func(ctx context.Context, d time.Duration) error
}

// SecretIO bundles the host-supplied primitives the §3.6 acquisition resolver
// consumes. Keeping them as plain func/io types (not a *secret.Request) means the
// cli frontend can fill them WITHOUT importing the secret provider (the arch
// matrix forbids frontend→secret); the core builds the secret.Request and calls
// secret.Acquire. All three are nil-safe: a nil Stdin disables the --*-stdin
// channel, a nil LookupEnv falls back to no-env, a nil IsTTY disables prompting.
type SecretIO struct {
	// Stdin is the reader the --*-stdin channel reads from (os.Stdin in
	// production; a buffer in tests).
	Stdin io.Reader
	// LookupEnv resolves an env var (os.LookupEnv in production; injected in
	// tests). The core never calls os.LookupEnv itself (§2.3).
	LookupEnv func(string) (string, bool)
	// IsTTY reports whether interactive prompting is possible (term.IsTerminal in
	// production). When false and no other source exists, the resolver returns a
	// deterministic passphrase-required error rather than hanging (§3.6).
	IsTTY func() bool
	// Prompt reads one secret from the terminal with echo disabled, given the
	// prompt label (secret.TTYPrompt in production; a stub in tests). It is the
	// host primitive the §3.6 prompt branch + the §3.3 first-init double-entry use;
	// keeping it here (not hard-coded in the resolver) means the core never owns a
	// real TTY read and the interactive paths are testable. Nil falls back to the
	// secret package's default terminal reader.
	Prompt func(label string) ([]byte, error)
}

// configFlags projects the path/network subset into the config package's input
// shape. This is the ONLY translation point; it keeps config.FlagValues an
// internal detail of the service↔config edge.
func (o Options) configFlags() config.FlagValues {
	return config.FlagValues{
		Config:   o.Config,
		Keystore: o.Keystore,
		StateDir: o.StateDir,
		Network:  o.Network,
	}
}
