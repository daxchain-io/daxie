package service

import (
	"context"
	"crypto/subtle"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
)

// keystore.go holds the M1 keystore-maintenance use cases (cli-spec §keystore):
// change-passphrase (the §3.8 atomic two-phase re-encryption) and info. Both are
// CLI-only administration — there is NO MCP tool for them (§3.9/§6.1), so they
// take the uniform shape but M11 wires no adapter.

// KeystoreChangePassphraseInput carries the old + new passphrase channels. The
// old passphrase uses the standard --passphrase-* channel; the new one its own
// --new-passphrase-* channel + DAXIE_NEW_PASSPHRASE[_FILE] (§3.8). Both are
// freshly resolved and zeroed; a serve-cached unlock never satisfies the old one.
type KeystoreChangePassphraseInput struct {
	OldStdin bool
	OldFile  string

	NewStdin bool
	NewFile  string

	// NewConfirm* feed the new-passphrase double-entry (so a rotation cannot land
	// on a typo'd new passphrase — the same first-init protection, applied to the
	// rotation target). Optional when a --new-passphrase-stdin|file source is
	// explicit; required (interactively) otherwise.
	NewConfirmStdin bool
	NewConfirmFile  string
}

// KeystoreChangePassphrase re-encrypts every file under the keystore passphrase
// (verifier + wallet blobs + standalone keys) under a new passphrase, atomically
// (§3.8): a crash leaves either the all-old or all-new keystore, never a mix.
// keys.Open ran forward/backward recovery at Open, so a prior crashed rotation is
// already healed before this runs.
func (s *Service) KeystoreChangePassphrase(ctx context.Context, p domain.Principal, _ domain.KeystoreChangePassphraseRequest, in KeystoreChangePassphraseInput, emit domain.EventSink) (domain.KeystoreChangePassphraseResult, error) {
	oldPass, _, err := s.acquire(passphraseSpecWith(in.OldStdin, in.OldFile, false))
	if err != nil {
		return domain.KeystoreChangePassphraseResult{}, err
	}
	defer oldPass.Zero()

	stdinTaken := in.OldStdin
	newPass, _, err := s.acquire(secretSpec{
		StdinFlag:   in.NewStdin,
		FilePath:    in.NewFile,
		EnvFileVar:  "DAXIE_NEW_PASSPHRASE_FILE",
		EnvVar:      "DAXIE_NEW_PASSPHRASE",
		PromptLabel: "New keystore passphrase: ",
		StdinTaken:  stdinTaken,
	})
	if err != nil {
		return domain.KeystoreChangePassphraseResult{}, err
	}
	defer newPass.Zero()
	if in.NewStdin {
		stdinTaken = true
	}

	// New-passphrase confirm is MANDATORY — exactly like first-init (§3.3/§3.8
	// step 2). A typo on the new passphrase would silently re-encrypt the ENTIRE
	// keystore (verifier + every wallet blob + every standalone key) onto an
	// unreproducible value — permanent lockout, and the OLD passphrase stops
	// working after commit. So this fails CLOSED:
	//
	//   - explicit confirm channel (--new-passphrase-confirm-* / DAXIE_NEW_*_CONFIRM[_FILE])
	//     → resolve + compare;
	//   - no explicit channel, at a TTY → a real second prompt (double-entry);
	//   - no explicit channel, no TTY → keystore.confirm_required (exit 4),
	//     NEVER a silent rotation and never a hang.
	//
	// The comparison is constant-time (crypto/subtle) — a timing leak on the user's
	// own re-entry is harmless, but the keystore secret deserves the discipline.
	confirm, cerr := s.acquireRotationConfirm(in, stdinTaken)
	if cerr != nil {
		return domain.KeystoreChangePassphraseResult{}, cerr
	}
	defer confirm.Zero()
	if subtle.ConstantTimeCompare(newPass.Reveal(), confirm.Reveal()) != 1 {
		return domain.KeystoreChangePassphraseResult{}, domain.New(
			"keystore.confirm_required",
			"new passphrase and its confirmation do not match",
		)
	}

	rotated, fingerprint, err := s.keys.ChangePassphrase(ctx, oldPass, newPass)
	if err != nil {
		return domain.KeystoreChangePassphraseResult{}, err
	}
	if emit != nil {
		emit(domain.Event{Kind: domain.EvComplete, Detail: "keystore re-encrypted", Stream: "stderr"})
	}
	return domain.KeystoreChangePassphraseResult{
		RotatedFiles:     rotated,
		PassphraseFinger: fingerprint,
	}, nil
}

// KeystoreInfo reports the keystore path, format version, KDF template, and
// wallet/account counts (§10.2). Read-only; no unlock and no request payload (an
// info read takes no inputs — like M0's ConfigList), so it omits the Request slot
// of the uniform shape rather than inventing an empty domain type. Principal is
// still threaded for attribution parity.
func (s *Service) KeystoreInfo(ctx context.Context, p domain.Principal) (domain.KeystoreInfoResult, error) {
	info, err := s.keys.Info(ctx)
	if err != nil {
		return domain.KeystoreInfoResult{}, err
	}
	return domain.KeystoreInfoResult{
		Path:        info.Path,
		Format:      info.Format,
		Wallets:     info.Wallets,
		Accounts:    info.Accounts,
		HDAccounts:  info.HDAccounts,
		Initialized: info.Initialized,
		KDF:         info.KDF,
		ScryptN:     info.ScryptN,
	}, nil
}

// acquireRotationConfirm resolves the MANDATORY new-passphrase confirmation
// (§3.8 step 2), mirroring the first-init fail-closed contract:
//
//   - an explicit confirm channel present → acquire it (caller owns + zeroes);
//   - no explicit channel, at a TTY → a real second prompt (interactive
//     double-entry the second time, since the new passphrase's own prompt was the
//     first entry);
//   - no explicit channel, no TTY → keystore.confirm_required (exit 4), so a
//     non-interactive rotation that forgot a confirm channel can NEVER silently
//     re-encrypt the keystore onto an unconfirmed (possibly typo'd) passphrase.
//
// The returned *secret.Bytes is always non-nil; the caller defers Zero() on it.
func (s *Service) acquireRotationConfirm(in KeystoreChangePassphraseInput, stdinTaken bool) (confirm *secret.Bytes, err error) {
	spec := secretSpec{
		StdinFlag:   in.NewConfirmStdin,
		FilePath:    in.NewConfirmFile,
		EnvFileVar:  "DAXIE_NEW_PASSPHRASE_CONFIRM_FILE",
		EnvVar:      "DAXIE_NEW_PASSPHRASE_CONFIRM",
		PromptLabel: "Confirm new keystore passphrase: ",
		StdinTaken:  stdinTaken,
	}
	if specHasExplicit(spec, s.secretIO.LookupEnv) {
		c, _, cerr := s.acquire(spec)
		return c, cerr
	}
	if s.secretIO.IsTTY != nil && s.secretIO.IsTTY() {
		c, _, cerr := s.acquire(spec) // falls through to the hidden-input prompt
		return c, cerr
	}
	// No explicit channel and no TTY: fail closed. Mirror EnsureInitialized's
	// contract so a typo can never re-encrypt the keystore.
	return nil, domain.New(
		"keystore.confirm_required",
		"changing the keystore passphrase requires confirming the new passphrase: "+
			"supply --new-passphrase-confirm-stdin|file or DAXIE_NEW_PASSPHRASE_CONFIRM[_FILE] "+
			"(or run interactively for double-entry); refusing to rotate without a confirmation",
	)
}
