package service

import (
	"context"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
	"github.com/daxchain-io/daxie/internal/keys"
	"github.com/daxchain-io/daxie/internal/secret"
)

// keysAccountInfo aliases the keys provider's AccountInfo so the account.go
// mapping helpers can name it without importing keys themselves (keys is imported
// once here — the one keys-typed seam). keys.AccountInfo is the §3.1 resolved
// account view: Ref, Address, Kind ("hd"|"standalone"), Wallet, Index, Alias,
// Path, CreatedAt.
type keysAccountInfo = keys.AccountInfo

// keys.go is the secret-acquisition + signer seam the M1 wallet/account/keystore
// use cases share. It is the ONE place the core builds a secret.Request and calls
// secret.Acquire (§3.6), so every use case acquires passphrases/mnemonics/raw
// keys through one audited path. The core never touches os (§2.3): the stdin
// reader, env lookup, and TTY check arrive from the frontend via Options.Secret
// (SecretIO) and are threaded into secret.Acquire here.
//
// Every secret this file resolves is a *secret.Bytes the CALLER must Zero() on
// defer — the use cases do exactly that. No secret is ever logged, journaled, or
// placed in an error (§3.10): a resolution failure surfaces the secret's source
// path/var names but never its bytes.

// secretSpec names the flag/env channels for one acquisition, plus the prompt
// label and whether stdin is already claimed by a positional payload. It is the
// frontend-agnostic description the cli fills with the §3.6 names so the core
// assembles the secret.Request without the frontend importing secret.
type secretSpec struct {
	StdinFlag   bool   // the --*-stdin flag was set
	FilePath    string // the --*-file value ("" when unset)
	EnvFileVar  string // the *_FILE env var name, e.g. "DAXIE_PASSPHRASE_FILE"
	EnvVar      string // the direct env var name, e.g. "DAXIE_PASSPHRASE"
	PromptLabel string // shown at a TTY
	StdinTaken  bool   // stdin already consumed by a command payload
}

// acquire resolves one secret through the §3.6 precedence using the host
// primitives the frontend injected. It enforces the §7.9 permission rule on any
// file source by wiring fsx.CheckPerms into the request (so a world-readable
// passphrase file fails keystore.perms_insecure, exit 12). The returned
// *secret.Bytes is owned by the caller, which MUST Zero() it.
func (s *Service) acquire(spec secretSpec) (*secret.Bytes, secret.Source, error) {
	req := secret.Request{
		StdinFlag:   spec.StdinFlag,
		FilePath:    spec.FilePath,
		EnvFileVar:  spec.EnvFileVar,
		EnvVar:      spec.EnvVar,
		PromptLabel: spec.PromptLabel,
		StdinTaken:  spec.StdinTaken,
		// fsx.CheckPerms is the one unified §7.9 perm rule; injecting it keeps
		// secret a pure leaf (it never imports fsx) while still enforcing perms
		// on the file/env-file channels before reading.
		CheckFile: fsx.CheckPerms,
		// Prompt is the host TTY reader threaded from the frontend (nil in tests
		// that do not exercise the prompt branch → secret's default terminal read).
		Prompt: s.secretIO.Prompt,
	}
	return secret.Acquire(req, s.secretIO.Stdin, s.secretIO.LookupEnv, s.secretIO.IsTTY)
}

// acquireOptional is acquire for a secret that may legitimately be absent (the
// BIP-39 25th word). A missing source yields an empty *secret.Bytes (Len()==0)
// rather than the passphrase-required error: keys treats an empty/nil 25th word
// as "no passphrase". A stdin conflict or an unreadable file is still a hard
// error. It distinguishes "absent" from "error" by branching on the source: only
// the explicit channels (stdin flag, file path, env) can supply it; with none
// present it returns empty without prompting (an interactive prompt for the 25th
// word is the create/TTY path, handled by a non-empty PromptLabel + a TTY).
func (s *Service) acquireOptional(spec secretSpec) (*secret.Bytes, secret.Source, error) {
	if !specHasExplicit(spec, s.secretIO.LookupEnv) {
		// No source for an OPTIONAL secret → empty (no prompt, no error).
		return secret.New(nil), secret.SourceNone, nil
	}
	return s.acquire(spec)
}

// specHasExplicit reports whether spec names a concrete, non-interactive secret
// source: a stdin flag, a file path, or a present (non-empty for *_FILE) env var.
// A bare TTY is NOT explicit — it is the interactive path, handled by the prompt
// branches in acquireFirstInitConfirm / secret.Acquire. lookupEnv may be nil.
func specHasExplicit(spec secretSpec, lookupEnv func(string) (string, bool)) bool {
	if spec.StdinFlag || spec.FilePath != "" {
		return true
	}
	if lookupEnv == nil {
		return false
	}
	if spec.EnvVar != "" {
		if _, ok := lookupEnv(spec.EnvVar); ok {
			return true
		}
	}
	if spec.EnvFileVar != "" {
		if v, ok := lookupEnv(spec.EnvFileVar); ok && v != "" {
			return true
		}
	}
	return false
}

// passphraseSpec is the §3.6 keystore-passphrase channel set. It is the most
// common acquisition (every mutating wallet/account op verifies the keystore
// passphrase first, §3.3).
func passphraseSpec(stdinTaken bool) secretSpec {
	return secretSpec{
		StdinFlag:   false, // set by the caller from its --passphrase-stdin flag
		EnvFileVar:  "DAXIE_PASSPHRASE_FILE",
		EnvVar:      "DAXIE_PASSPHRASE",
		PromptLabel: "Keystore passphrase: ",
		StdinTaken:  stdinTaken,
	}
}

// ensureInitialized verifies the keystore passphrase, OR (on the very first use,
// when the verifier does not yet exist) confirms it by double-entry before keys
// writes the verifier (§3.3). It centralizes the create/import/import-standalone
// init flow so every keystore-writing entry point gets identical first-init
// protection.
//
//   - Already initialized: pass is verified; the confirm channel is ignored
//     (keys ignores a non-nil confirm post-init), so callers need not supply one.
//   - First init: the confirm is REQUIRED — resolved from the confirm channel
//     (--passphrase-confirm-* / DAXIE_PASSPHRASE_CONFIRM[_FILE] / TTY double-
//     entry). Its absence with no TTY is keystore.confirm_required (exit 4),
//     never a hang.
//
// confirmStdin/confirmFile carry the command's confirm-channel flag selection;
// the env channels are always consulted by the resolver. pass is the already-
// resolved keystore passphrase (the caller owns + zeroes it).
func (s *Service) ensureInitialized(ctx context.Context, pass *secret.Bytes, confirmStdin bool, confirmFile string, stdinTaken bool) (fingerprint string, err error) {
	if s.keys.Initialized() {
		return s.keys.EnsureInitialized(ctx, pass, nil)
	}
	// First init: the confirm is mandatory (§3.3). It is resolved one of two ways:
	//
	//   - an EXPLICIT non-interactive channel (--passphrase-confirm-stdin|file or
	//     DAXIE_PASSPHRASE_CONFIRM[_FILE]) — acquireOptional picks it up; or
	//   - INTERACTIVELY at a TTY — a real SECOND prompt (the double-entry the design
	//     promises). acquireOptional alone would return empty without prompting for a
	//     bare TTY, so we route the no-explicit-channel TTY case through the prompting
	//     acquire (its PromptLabel + the TTY land on secret.Acquire's prompt branch).
	//
	// With NO explicit channel AND no TTY, acquireOptional returns an empty confirm,
	// and keys' EnsureInitialized returns keystore.confirm_required (exit 4) —
	// fail-closed, never a hang and never a silent commit to a typo'd passphrase.
	spec := confirmSpec(confirmStdin, confirmFile, stdinTaken)
	confirm, _, aerr := s.acquireFirstInitConfirm(spec)
	if aerr != nil {
		return "", aerr
	}
	defer confirm.Zero()
	return s.keys.EnsureInitialized(ctx, pass, confirm)
}

// acquireFirstInitConfirm resolves the first-init confirmation (§3.3). When an
// explicit confirm channel is present it behaves like acquireOptional. When NO
// explicit channel is present it diverges by interactivity: at a TTY it issues a
// real second prompt (the interactive double-entry), and with no TTY it returns
// an empty confirm so keys' EnsureInitialized fails closed with
// keystore.confirm_required rather than hanging on a prompt.
func (s *Service) acquireFirstInitConfirm(spec secretSpec) (*secret.Bytes, secret.Source, error) {
	if specHasExplicit(spec, s.secretIO.LookupEnv) {
		return s.acquire(spec)
	}
	// No explicit channel. Prompt only when interactive; otherwise return empty and
	// let EnsureInitialized emit confirm_required (fail-closed).
	if s.secretIO.IsTTY != nil && s.secretIO.IsTTY() {
		// s.acquire → secret.Acquire: with no stdin-flag/file/env source present and
		// a live TTY, it falls through to the hidden-input prompt branch (the second
		// entry). The first entry was the keystore-passphrase prompt the caller
		// already resolved.
		return s.acquire(spec)
	}
	return secret.New(nil), secret.SourceNone, nil
}

// serviceUnlocker is the core-owned domain.Unlocker (§2.6, §3.12). It holds a
// *secret.Bytes the service resolved and zeroes on defer; Passphrase returns the
// borrowed bytes for the signer's single signing call. The signer must NOT retain
// the slice (the contract on domain.Unlocker). This is the §11 D1 reconciliation
// realized: the interface lives in domain (leaf-free), the secret container lives
// in a layer permitted to hold it (service).
//
// M1 ships it so the seam is real and compile-checked; M3 (tx) is the first
// caller that actually signs.
type serviceUnlocker struct {
	pass *secret.Bytes
}

// Passphrase returns the borrowed passphrase bytes. A nil container yields
// (nil, nil) — the no-passphrase backend shape a future KMS signer also returns.
func (u serviceUnlocker) Passphrase(_ context.Context) ([]byte, error) {
	return u.pass.Reveal(), nil
}

// compile-time assertion that the core-owned unlocker satisfies the seam.
var _ domain.Unlocker = serviceUnlocker{}

// Signer exposes the domain.Signer adapter over the keystore (§3.12). M3+ (tx,
// sign) call it; it is wired in Open so the seam is live from M1. It is nil only
// if keys.Open failed (which Open surfaces, so a live Service always has one).
func (s *Service) Signer() domain.Signer { return s.signer }
