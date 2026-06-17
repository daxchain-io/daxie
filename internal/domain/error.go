package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Error is daxie's one error taxonomy. The dotted Code string is canonical and
// survives every transport (CLI exit code, MCP tool-error envelope, v1.1 HTTP);
// Exit is the CLI projection of that code (§5.7). Error() returns the JSON
// envelope so the MCP frontend (M11) can pack it byte-identically to the CLI
// --json error.
//
// No float field appears here (§2.5). Data carries structured detail (§5.7
// "data":{…}).
type Error struct {
	Code      string         `json:"code"`           // canonical dotted, e.g. "policy.denied.day_limit"
	Exit      ExitCode       `json:"exit"`           // 0..12
	Msg       string         `json:"message"`        // human one-liner
	Retryable bool           `json:"retryable"`      // agent hint: safe to retry as-is
	Data      map[string]any `json:"data,omitempty"` // structured detail

	wrapped error // unexported; surfaced via Unwrap()
}

// envelope is the on-the-wire shape: {"error":{…}}. It is its own type (not the
// Error tags above) so Error() emits the nested object the CLI --json contract
// and the MCP tool-error contract both expect (§5.7).
type envelope struct {
	Err envelopeBody `json:"error"`
}

type envelopeBody struct {
	Code      string         `json:"code"`
	Exit      ExitCode       `json:"exit"`
	Msg       string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Data      map[string]any `json:"data,omitempty"`
}

// Error returns the canonical JSON envelope. This is what the CLI writes to
// stderr under --json and what the MCP frontend embeds in its tool-error result,
// so the two are byte-identical (J13).
func (e *Error) Error() string {
	b, err := json.Marshal(envelope{Err: envelopeBody{
		Code:      e.Code,
		Exit:      e.Exit,
		Msg:       e.Msg,
		Retryable: e.Retryable,
		Data:      e.Data,
	}})
	if err != nil {
		// Marshal of these fields cannot realistically fail; fall back to a
		// plain string so Error() is always non-empty.
		return e.Code + ": " + e.Msg
	}
	return string(b)
}

// Unwrap returns the wrapped cause, if any, so errors.Is/As traverse the chain.
func (e *Error) Unwrap() error { return e.wrapped }

// New constructs an Error and derives Exit from Code via the registry (ExitOf).
func New(code, msg string) *Error {
	return &Error{Code: code, Exit: ExitOf(code), Msg: msg, Retryable: retryableFor(code)}
}

// Newf is New with a fmt.Sprintf'd message.
func Newf(code, msg string, args ...any) *Error {
	return New(code, fmt.Sprintf(msg, args...))
}

// Wrap constructs an Error around a cause, preserving it for Unwrap/errors.Is.
// Exit is derived from Code.
func Wrap(code, msg string, cause error) *Error {
	e := New(code, msg)
	e.wrapped = cause
	return e
}

// WithData attaches (or merges into) the structured data map and returns e for
// fluent use. A nil receiver is returned unchanged.
func WithData(e *Error, data map[string]any) *Error {
	if e == nil {
		return nil
	}
	if e.Data == nil {
		e.Data = make(map[string]any, len(data))
	}
	for k, v := range data {
		e.Data[k] = v
	}
	return e
}

// AsError extracts a *domain.Error from anywhere in err's chain (an errors.As
// wrapper). If none is found it synthesizes a generic {code:"internal", exit:1}
// carrying the original message and wrapping err, so every command can exit
// through the registry even on a raw Go error. A nil err yields nil.
//
// cli/render.go calls this so the typed-error -> exit funnel is total.
func AsError(err error) *Error {
	if err == nil {
		return nil
	}
	var de *Error
	if errors.As(err, &de) {
		return de
	}
	return &Error{
		Code:      CodeInternal,
		Exit:      ExitInternal,
		Msg:       err.Error(),
		Retryable: false,
		wrapped:   err,
	}
}

// ───────────────────────── the registry (ExitOf) ─────────────────────────────

// Canonical code constants the M0 surface emits. The full taxonomy (tx.*,
// funds.*, rpc.*, keystore.*, policy.*, state.*) is encoded in ExitOf below —
// it is the M0 deliverable per §2.1/§5.7 — but only these are produced by an M0
// command. The rest are emitted by M1+ subsystems.
const (
	CodeInternal                = "internal"
	CodeUsage                   = "usage"                     // family prefix; specific: usage.<reason>
	CodeRefAmbiguous            = "ref.ambiguous"             // exit 2
	CodeRefNotFound             = "ref.not_found"             // exit 10
	CodeConfigReadOnly          = "config.read_only"          // exit 10
	CodeConfigNotFound          = "config.not_found"          // exit 10 (named file missing)
	CodeConfigInvalid           = "config.invalid"            // exit 2 (bad type at load)
	CodeConfigSchemaUnsupported = "config.schema_unsupported" // exit 2 (newer major)
	CodeSecretUnresolved        = "secret.unresolved"         // exit 2 (bad/missing secret ref)
	CodeStateLockTimeout        = "state.lock_timeout"        // exit 11 (lock contention)
	// CodeKeystoreReadOnly is a write attempt against a read-only keystore (§3.3).
	CodeKeystoreReadOnly = "keystore.read_only" // exit 10
	// CodeKeystorePermsInsecure is an insecure keystore/secret file-perm tripwire (§3.11).
	CodeKeystorePermsInsecure = "keystore.perms_insecure" // exit 12
	// CodeKeystoreDerivationWatermark is the §3.3 fail-closed tripwire: a meta.json
	// next_index that sits BELOW a materialized HD index — the restore-coupling /
	// state-corruption guard that refuses to reuse a derivation slot. State class.
	CodeKeystoreDerivationWatermark = "keystore.derivation_watermark" // exit 11

	// ── M4 policy codes (§4.9). The exit mapping is via the prefix rule already in
	// codeExit ("policy.denied" → 3; the seal/auth/state/rollback family → 8); these
	// consts give the canonical sub-code SPELLINGS one home so the cli/service/policy
	// never string-literal them inconsistently. tx_limit / day_limit / pin_drift are
	// canonical; spend_limit / ens_pin are WITHDRAWN aliases (D7) — agents branch on
	// the canonical strings.
	// (CodePolicyDenied + CodePolicyDeniedGasCap are declared in tx_requests.go,
	// which M3 authored; the rest of the §4.9 canonical sub-codes are added here.)
	CodePolicyDeniedTxLimit     = "policy.denied.tx_limit"     // per-tx ETH limit
	CodePolicyDeniedDayLimit    = "policy.denied.day_limit"    // rolling-24h ETH limit (retryable + retry_after)
	CodePolicyDeniedAllowlist   = "policy.denied.allowlist"    // denylisted / not allowlisted
	CodePolicyDeniedNoAllowlist = "policy.denied.no_allowlist" // limits set, no allowlist, token/approval
	CodePolicyDeniedPinDrift    = "policy.denied.pin_drift"    // ENS/contact drift from the allow-time pin
	CodePolicyDeniedTypedData   = "policy.denied.typed_data"   // unknown typed data / chain mismatch
	CodePolicyDeniedUnlimited   = "policy.denied.unlimited_unacked"
	CodePolicyDeniedContract    = "policy.denied.contract_call" // §4.3 stage-5b unknown-calldata gate
	// The exit-8 family (seal/auth/state/rollback). Mapped in codeExit already.
	CodePolicySealViolation = "policy.seal_violation" // exit 8 — seal failed / anchor missing / unknown fields
	CodePolicyRollback      = "policy.rollback"       // exit 8 — body.nonce < anchor watermark
	CodePolicyAdminAuth     = "policy.admin_auth"     // exit 8 — wrong admin passphrase (derived key ≠ anchor)
	CodePolicyStateError    = "policy.state_error"    // exit 8 — counters unreadable/unlockable/unwritable
)

// codeExit is the (prefix -> exit) registry, highest-specificity wins. The key
// is a canonical dotted prefix; a code matches the LONGEST key that is either
// equal to it or a dotted-prefix of it (so "policy.denied.day_limit" matches the
// "policy.denied" key, not "policy"). An unmatched code maps to ExitInternal.
//
// This table IS the §5.7 registry. cli/render.go projects every error through
// ExitOf.
var codeExit = map[string]ExitCode{
	// 1 — INTERNAL
	"internal": ExitInternal,

	// 2 — USAGE
	"usage":         ExitUsage,
	"ref.ambiguous": ExitUsage,
	// config load/parse problems are operator-input errors (usage class).
	"config.invalid":            ExitUsage,
	"config.schema_unsupported": ExitUsage,
	"secret.unresolved":         ExitUsage,

	// 3 — POLICY_DENIED (covers all policy.denied.* via the prefix rule)
	"policy.denied": ExitPolicyDenied,

	// 4 — AUTH (the "wrong/MISSING/unusable keystore passphrase" class, §5.7 row 4)
	"keystore.bad_passphrase":        ExitAuth,
	"keystore.confirm_required":      ExitAuth,
	"keystore.passphrase_stale":      ExitAuth,
	"keystore.passphrase_required":   ExitAuth, // §3.6 row 6: missing passphrase, no TTY — distinct exit, never a prompt hang
	"keystore.passphrase_file_error": ExitAuth, // passphrase file present but unreadable — unusable passphrase
	"keystore.prompt_failed":         ExitAuth, // TTY prompt failed — passphrase could not be acquired

	// 5 — INSUFFICIENT_FUNDS
	"funds.insufficient": ExitInsufficientFunds,

	// 6 — NETWORK
	"rpc.unreachable": ExitNetwork,

	// rpc.unsupported is the Subscribe-on-HTTP sentinel (§2.6). It is not a
	// user-facing M2 path, but mapping it under usage (exit 2) keeps it honest if it
	// ever surfaces to a command, rather than falling through to internal.
	"rpc.unsupported": ExitUsage,

	// 7 — REVERTED
	"tx.reverted": ExitReverted,

	// 8 — TIMEOUT_PENDING / SEAL
	"tx.wait_timeout":       ExitTimeoutPending,
	"receive.timeout":       ExitTimeoutPending,
	"policy.seal_violation": ExitTimeoutPending,
	"policy.rollback":       ExitTimeoutPending,
	"policy.admin_auth":     ExitTimeoutPending,
	"policy.state_error":    ExitTimeoutPending,

	// 9 — TX_CONFLICT
	"tx.replaced":                ExitTxConflict,
	"tx.replacement_underpriced": ExitTxConflict,
	"tx.already_mined":           ExitTxConflict,
	"tx.nonce_gap":               ExitTxConflict,

	// 10 — NOT_FOUND / READONLY
	"ref.not_found":      ExitNotFound,
	"config.read_only":   ExitNotFound,
	"config.not_found":   ExitNotFound,
	"keystore.read_only": ExitNotFound,

	// 11 — STATE
	"state.lock_timeout": ExitState,
	"state.corrupt":      ExitState,
	// derivation watermark below a materialized index: a restore-coupling /
	// state-corruption tripwire that fails closed rather than reuse an HD slot (§3.3).
	"keystore.derivation_watermark": ExitState,

	// 12 — INTEGRITY (tamper/misconfig tripwires, §5.7 row 12)
	"rpc.chain_id_mismatch":            ExitIntegrity,
	"tx.integrity.reservation_missing": ExitIntegrity,
	"keystore.perms_insecure":          ExitIntegrity, // insecure keystore/secret file perms — a misconfig tripwire, not a daxie bug
}

// ExitOf maps a canonical code to its exit number using the longest-dotted-prefix
// rule. "policy.denied.day_limit" -> 3 (via "policy.denied"); an unknown code ->
// ExitInternal. This is the single registry the whole CLI surface funnels
// through.
func ExitOf(code string) ExitCode {
	if code == "" {
		return ExitInternal
	}
	// Exact match short-circuit.
	if ex, ok := codeExit[code]; ok {
		return ex
	}
	// Walk the dotted prefixes from longest to shortest: "a.b.c" -> "a.b" -> "a".
	for {
		i := strings.LastIndexByte(code, '.')
		if i < 0 {
			break
		}
		code = code[:i]
		if ex, ok := codeExit[code]; ok {
			return ex
		}
	}
	return ExitInternal
}

// retryableDefaults marks the codes whose default Retryable hint is true (the
// "wait/retry later" classes the agent send-loop branches on). Explicit
// per-error overrides are still possible by setting Error.Retryable directly.
var retryableDefaults = map[string]bool{
	"rpc.unreachable":            true, // retry later
	"tx.wait_timeout":            true, // keep waiting / re-poll
	"receive.timeout":            true,
	"tx.replaced":                true, // re-quote / replace
	"tx.replacement_underpriced": true,
	"tx.nonce_gap":               true,
	"state.lock_timeout":         true, // contention; retry
	// M4 policy denials whose default hint is "retry later" (§4.9):
	//   - day_limit: the rolling-24h window ages out; the engine returns retry_after
	//     so an agent SCHEDULES instead of polling.
	//   - gas_cap: the fee market moves; a later base fee may clear the cap.
	// Every other policy.denied.* defaults false (retrying without operator action is
	// pointless) — they inherit the family's false via retryableFor's prefix walk.
	"policy.denied.day_limit": true,
	"policy.denied.gas_cap":   true,
}

// retryableFor returns the default Retryable hint for a code, using the same
// longest-prefix walk as ExitOf so a sub-code inherits its family's default.
func retryableFor(code string) bool {
	if code == "" {
		return false
	}
	if r, ok := retryableDefaults[code]; ok {
		return r
	}
	for {
		i := strings.LastIndexByte(code, '.')
		if i < 0 {
			return false
		}
		code = code[:i]
		if r, ok := retryableDefaults[code]; ok {
			return r
		}
	}
}
