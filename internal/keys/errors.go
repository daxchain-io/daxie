package keys

import "github.com/daxchain-io/daxie/internal/domain"

// Canonical error-code strings keys emits (§5.7). They are the exact dotted codes
// the domain registry (internal/domain/error.go) maps to exit numbers; keys names
// them locally so call sites are greppable and the package does not depend on a
// domain const that may be added in a sibling group. The integers below are the
// §5.7 projections those strings resolve to via domain.ExitOf:
//
//	keystore.bad_passphrase           -> 4  (AUTH)
//	keystore.confirm_required         -> 4  (AUTH; first-init double-entry mismatch)
//	keystore.passphrase_stale         -> 4  (AUTH; rotated under a running cache)
//	keystore.read_only                -> 10 (NOT_FOUND/READONLY)
//	keystore.perms_insecure           -> 12 (INTEGRITY)
//	keystore.derivation_watermark     -> 11 (STATE; restore-coupling tripwire)
//	ref.not_found                     -> 10
//	ref.ambiguous                     -> 2
//	usage.*                           -> 2
//	state.lock_timeout / state.corrupt-> 11
const (
	// CodeKeystoreBadPassphrase is a wrong/undecryptable keystore passphrase
	// (verifier or any secret-file MAC failure).
	CodeKeystoreBadPassphrase = "keystore.bad_passphrase" // #nosec G101 -- a canonical error-code string, not a credential
	// CodeKeystoreConfirmRequired is a first-init confirmation that did not match
	// (or is absent non-interactively) before the verifier is written (§3.3).
	CodeKeystoreConfirmRequired = "keystore.confirm_required"
	// CodeKeystorePassphraseStale signals a passphrase rotated out from under a
	// cached unlock (§3.8) — a distinct AUTH so the caller restarts with the new
	// source rather than retrying the stale one.
	CodeKeystorePassphraseStale = "keystore.passphrase_stale"
	// CodeKeystoreReadOnly is a write to a read-only keystore (K8s Secret mount).
	CodeKeystoreReadOnly = "keystore.read_only"
	// CodeKeystorePermsInsecure is an insecure-permission tripwire on a secret /
	// metadata file (world/group bits, or a foreign-group DACL on Windows).
	CodeKeystorePermsInsecure = "keystore.perms_insecure"
	// CodeKeystoreDerivationWatermark is the restore-coupling fail-closed: a
	// meta.json next_index below a materialized index (§3.3).
	CodeKeystoreDerivationWatermark = "keystore.derivation_watermark"

	// CodeRefNotFound is an unknown wallet/index/alias/standalone, or a bare
	// wallet name in a signing position (a wallet is not a signing identity).
	CodeRefNotFound = "ref.not_found"
	// CodeRefAmbiguous is a reference that resolves two ways (§3.2).
	CodeRefAmbiguous = "ref.ambiguous"

	// CodeUsageNameCollision is a wallet/standalone name that collides with an
	// existing keystore object (the one-namespace rule, §3.1).
	CodeUsageNameCollision = "usage.name_collision"
	// CodeUsageInvalidName is a name/alias that fails the §3.1 grammar.
	CodeUsageInvalidName = "usage.invalid_name"
	// CodeUsageBadKey is a malformed / out-of-range raw private key on import.
	CodeUsageBadKey = "usage.bad_key"
	// CodeUsageBadMnemonic is a checksum-invalid or malformed BIP-39 mnemonic.
	CodeUsageBadMnemonic = "usage.bad_mnemonic"
	// CodeUsageBadIndex is an out-of-range / reserved HD index on derive.
	CodeUsageBadIndex = "usage.bad_index"
	// CodeUsageReadOnlyContext is a destination/read-only ref used in a signing
	// position (RefAddress/RefENS), or a signing op on a read-only ref.
	CodeUsageReadOnlyContext = "usage.read_only_ref"
	// CodeUsageWords is an invalid --words value.
	CodeUsageWords = "usage.words"

	// CodeStateLockTimeout / CodeStateCorrupt mirror the domain state.* codes.
	CodeStateLockTimeout = "state.lock_timeout"
	CodeStateCorrupt     = "state.corrupt"
)

// errKeys builds a typed *domain.Error from a code + message. The exit number is
// derived from the code by the domain registry, so keys never hard-codes an
// integer. Secret material MUST NOT be passed in (§3.10: errors carry no secrets).
func errKeys(code, msg string) error { return domain.New(code, msg) }

// errKeysf is errKeys with a fmt.Sprintf'd message. Callers must never format a
// secret into it.
func errKeysf(code, format string, args ...any) error { return domain.Newf(code, format, args...) }

// errWrap wraps a cause with a typed code, preserving it for errors.Is/As while
// the canonical code drives the exit. The cause string must not contain secrets;
// crypto failures from geth (e.g. ErrDecrypt) are non-secret.
func errWrap(code, msg string, cause error) error { return domain.Wrap(code, msg, cause) }
