// Package service is THE daxie core: the composition root and every use case.
//
// In M0 the core wires only the M0-available pieces (the resolved config + the
// injected clock) and implements the one M0 use case, Convert. Provider fields
// (signer/chains/policy/journal/registry/ens/erc) are declared by later
// milestones; M0 leaves them absent.
//
// Determinism is structural (§2.3): this package must not import os, net, or
// crypto/rand, and must not call the time.Now family. It takes wall time only
// through the injected clock (set in Open). The internal/determinism_test.go AST
// guard enforces this as a failing test, not a convention.
package service

import (
	"context"
	"time"

	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/keys"
)

// Service is the composed daxie core. ONE per process for the CLI and the stdio
// MCP server; ONE per daemon for the v1.1 HTTP server (§2.4). It is safe for
// concurrent use once the sign path lands (M1+); the M0 surface (Convert,
// config get/set/list) is read-mostly/stateless.
type Service struct {
	cfg   *config.Config
	paths config.Paths

	// clock is the ONE injected time source (§2.3 AST guard). M0 use cases are
	// pure and do not read it, but it is wired here so later milestones (journal
	// timestamps, wait deadlines) inherit a deterministic seam with zero
	// structural change.
	clock func() time.Time

	// keys is the keystore provider (M1, §3): wallets, accounts, the verifier,
	// the change-passphrase protocol, the domain.Signer adapter. It is opened
	// LAZILY-but-eagerly here: keys.Open provisions nothing for a fresh install
	// (Initialized()==false) and runs change-passphrase crash recovery + the
	// derivation-watermark check under the index.lock, so a corrupt or
	// mid-rotation keystore fails fast at Open (§3.8). It is nil only if keys.Open
	// itself errors, which Open surfaces.
	keys *keys.Store

	// signer is the domain.Signer adapter over keys (§3.12), constructed once in
	// Open. M1 builds it (so the seam is real and tested) even though no M1
	// command signs; M3 (tx) is the first caller.
	signer domain.Signer

	// account is the §7.7 default-account override (--from/--account>DAXIE_ACCOUNT),
	// resolved by the frontend and threaded so use cases that take an active
	// account fall through flag>env>meta.json.
	account string

	// secretIO holds the host primitives secret.Acquire needs (stdin, env lookup,
	// TTY check). The core uses them to resolve passphrases/mnemonics/keys WITHOUT
	// importing os (§2.3); the cli frontend fills them in Options.Secret.
	secretIO SecretIO

	// Later milestones add: chains ChainProvider; policy *policy.Engine;
	// journal *journal.Journal; tokens/nfts/contacts *registry.*; ens
	// *ens.Resolver; erc erc.Ops; fees FeeStrategy. They are absent before their
	// milestone by design.
}

// Open composes the service from resolved options.
//
// It is LAZY (§7.3): an empty environment must still allow Convert, version,
// and config list. Open does NOT create directories and does NOT dial anything
// in M0 — directory creation happens only when a command actually writes config
// (and then maps a read-only mount to config.read_only, never an opaque mkdir
// error). The config load here is path resolution + an optional config.toml
// read merged over the compiled-in presets; a missing default file is the
// legitimate fresh-install case.
func Open(ctx context.Context, opts Options) (*Service, error) {
	clock := opts.Clock
	if clock == nil {
		// The real clock is the HOST's responsibility (the cli frontend injects
		// it — frontends may read wall time; the core may not, §2.3). When a
		// caller omits it, we fall back to a fixed-zero clock rather than calling
		// time.Now here: doing so would trip the determinism guard, and no M0 use
		// case reads the clock anyway. Production callers (cmd/daxie → cli) always
		// supply a real clock, so this fallback is reached only by tests and by
		// the pure use cases that ignore time entirely.
		clock = zeroClock
	}

	cfg, paths, err := config.Load(opts.configFlags())
	if err != nil {
		return nil, err
	}

	// Open the keystore provider. keys.Open is lazy for a fresh install (it
	// provisions nothing and reports Initialized()==false) but runs the §3.8
	// change-passphrase crash recovery and the §3.3 derivation-watermark check
	// under the exclusive index.lock, so a mid-rotation or restore-coupled
	// keystore fails fast HERE (keystore.derivation_watermark → exit 11) rather
	// than mid-command. The light KDF is honored only when the manifest was
	// created light (§3.4); the gate is read via the injected env lookup so the
	// core never touches os (§2.3).
	light := false
	if opts.Secret.LookupEnv != nil {
		if v, ok := opts.Secret.LookupEnv("DAXIE_KDF_LIGHT"); ok && v != "" && v != "0" {
			light = true
		}
	}
	ks, err := keys.Open(ctx, keys.Options{
		Dir:   paths.Keystore,
		Clock: clock,
		Light: light,
	})
	if err != nil {
		return nil, err
	}

	return &Service{
		cfg:      cfg,
		paths:    paths,
		clock:    clock,
		keys:     ks,
		signer:   ks.Signer(),
		account:  opts.Account,
		secretIO: opts.Secret,
	}, nil
}

// Close flushes durable state and releases file locks. M1 closes the keystore
// (releasing any held index.lock). It is idempotent and never errors fatally;
// wiring it from the start means SIGTERM-driven shutdown (§2.4) needs no later
// change.
func (s *Service) Close() error {
	if s.keys != nil {
		return s.keys.Close()
	}
	return nil
}

// Now returns the service's notion of wall time through the injected clock. It
// exists so later use cases read time via one method (never time.Now), keeping
// the §2.3 guard trivially satisfied. M0 use cases do not call it.
func (s *Service) Now() time.Time {
	return s.clock()
}

// zeroClock is the determinism-safe fallback when no clock is injected. It does
// not read the wall clock (which would violate §2.3); production hosts always
// inject a real clock, and M0 use cases never read it. It returns the zero
// time.Time so the field is always callable.
func zeroClock() time.Time { return time.Time{} }
