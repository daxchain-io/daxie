package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

// TestExitOfRegistry is the exhaustive code->exit table. Every representative
// code from §5.7 must map to its documented exit number, AND a sub-code under a
// family prefix must inherit via the longest-prefix rule.
func TestExitOfRegistry(t *testing.T) {
	cases := []struct {
		code string
		want ExitCode
	}{
		// 1 INTERNAL
		{"internal", ExitInternal},
		{"internal.panic", ExitInternal}, // prefix-inherits

		// 2 USAGE
		{"usage", ExitUsage},
		{"usage.confirmation_required", ExitUsage},
		{"usage.bad_address", ExitUsage},
		{"ref.ambiguous", ExitUsage},
		{"config.invalid", ExitUsage},
		{"config.schema_unsupported", ExitUsage},
		{"secret.unresolved", ExitUsage},

		// 3 POLICY_DENIED (family prefix covers all sub-codes)
		{"policy.denied", ExitPolicyDenied},
		{"policy.denied.tx_limit", ExitPolicyDenied},
		{"policy.denied.day_limit", ExitPolicyDenied},
		{"policy.denied.allowlist", ExitPolicyDenied},
		{"policy.denied.gas_cap", ExitPolicyDenied},
		{"policy.denied.pin_drift", ExitPolicyDenied},
		{"policy.denied.no_allowlist", ExitPolicyDenied},
		{"policy.denied.typed_data", ExitPolicyDenied},
		{"policy.denied.unlimited_unacked", ExitPolicyDenied},
		{"policy.denied.contract_call", ExitPolicyDenied},

		// 4 AUTH
		{"keystore.bad_passphrase", ExitAuth},
		{"keystore.confirm_required", ExitAuth},
		{"keystore.passphrase_stale", ExitAuth},

		// 5 INSUFFICIENT_FUNDS
		{"funds.insufficient", ExitInsufficientFunds},

		// 6 NETWORK
		{"rpc.unreachable", ExitNetwork},

		// 7 REVERTED
		{"tx.reverted", ExitReverted},

		// 8 TIMEOUT_PENDING / SEAL
		{"tx.wait_timeout", ExitTimeoutPending},
		{"receive.timeout", ExitTimeoutPending},
		{"policy.seal_violation", ExitTimeoutPending},
		{"policy.rollback", ExitTimeoutPending},
		{"policy.admin_auth", ExitTimeoutPending},
		{"policy.state_error", ExitTimeoutPending},

		// 9 TX_CONFLICT
		{"tx.replaced", ExitTxConflict},
		{"tx.replacement_underpriced", ExitTxConflict},
		{"tx.already_mined", ExitTxConflict},
		{"tx.nonce_gap", ExitTxConflict},

		// 10 NOT_FOUND / READONLY
		{"ref.not_found", ExitNotFound},
		{"config.read_only", ExitNotFound},
		{"config.not_found", ExitNotFound},
		{"keystore.read_only", ExitNotFound},

		// 11 STATE
		{"state.lock_timeout", ExitState},
		{"state.corrupt", ExitState},

		// 12 INTEGRITY
		{"rpc.chain_id_mismatch", ExitIntegrity},
		{"tx.integrity.reservation_missing", ExitIntegrity},
		{"tx.integrity.reservation_missing.extra", ExitIntegrity}, // deeper prefix-inherits
	}
	for _, c := range cases {
		if got := ExitOf(c.code); got != c.want {
			t.Errorf("ExitOf(%q) = %d (%s), want %d (%s)", c.code, got, got, c.want, c.want)
		}
	}
}

// TestExitOfEmittedCodes is the exhaustive guard for codes ACTUALLY produced by
// non-test code: every code string literally passed to domain.New/Newf/Wrap in
// the M0 surface must resolve (directly or via family prefix) to its §5.7 exit
// number — and crucially NOT to ExitInternal. A deliberately-emitted error that
// fell through to ExitInternal would tell an agent "daxie bug" for a real,
// branchable condition (§5.7: exit 1 is reserved for "Daxie bug / unexpected
// panic"). Whenever a new code is emitted in production code it must be added
// here AND registered in codeExit, or this test goes red — closing the gap where
// an unregistered emitted code silently became exit 1.
//
// Keep this list in sync with the grep:
//
//	grep -rnE '(New|Newf|Wrap)\(' --include='*.go' internal cmd | grep -v _test.go
func TestExitOfEmittedCodes(t *testing.T) {
	cases := []struct {
		code string
		want ExitCode
	}{
		// internal (the only legitimately exit-1 emitted code) and its synthesized
		// AsError fallback.
		{"internal", ExitInternal},

		// usage family (exit 2): direct codes and CodeUsage+"<suffix>" forms.
		{"usage.cli", ExitUsage},
		{"usage.canceled", ExitUsage},
		{"usage.stdin_read", ExitUsage},
		{"usage.stdin_conflict", ExitUsage},
		{"usage.completion.unknown_shell", ExitUsage},
		{"usage.convert.unit_conflict", ExitUsage},
		{"usage.convert.missing_unit", ExitUsage},
		{"usage.convert.missing_to", ExitUsage},
		{"usage.convert.bad_unit", ExitUsage},
		{"usage.convert.bad_amount", ExitUsage},
		{"usage.policy_key", ExitUsage},
		{"usage.bad_value", ExitUsage},
		{"usage.empty_account_ref", ExitUsage},
		{"usage.bad_account_ref", ExitUsage},
		{"usage.bad_address", ExitUsage},
		{"usage.bad_ens", ExitUsage},
		{"ref.ambiguous", ExitUsage},

		// keystore — the formerly-misrouted codes (§5.7 row 4 AUTH / row 12 INTEGRITY).
		{"keystore.passphrase_required", ExitAuth},
		{"keystore.passphrase_file_error", ExitAuth},
		{"keystore.prompt_failed", ExitAuth},
		{"keystore.perms_insecure", ExitIntegrity},

		// config family.
		{"config.invalid", ExitUsage},
		{"config.schema_unsupported", ExitUsage},
		{"config.not_found", ExitNotFound},
		{"config.read_only", ExitNotFound},

		// secret / ref / state.
		{"secret.unresolved", ExitUsage},
		{"ref.not_found", ExitNotFound},
		{"state.lock_timeout", ExitState},
	}
	for _, c := range cases {
		if got := ExitOf(c.code); got != c.want {
			t.Errorf("ExitOf(%q) = %d (%s), want %d (%s)", c.code, got, got, c.want, c.want)
		}
		// No deliberately-emitted code (other than "internal" itself) may resolve
		// to ExitInternal — that would mislabel a real condition as a daxie bug.
		if c.code != "internal" && ExitOf(c.code) == ExitInternal {
			t.Errorf("emitted code %q maps to ExitInternal(1); a deliberate error must have a distinct §5.7 exit, not the daxie-bug code", c.code)
		}
	}
}

// TestExitOfUnknownAndEmpty: unmapped codes and "" fall back to ExitInternal.
func TestExitOfUnknownAndEmpty(t *testing.T) {
	for _, code := range []string{"", "totally.unknown.code", "nope", "tx", "policy", "config"} {
		// Note: "tx", "policy", "config" are bare families with no bare-prefix
		// entry, so they too fall back to internal (only specific sub-prefixes
		// are registered).
		if got := ExitOf(code); got != ExitInternal {
			t.Errorf("ExitOf(%q) = %d, want ExitInternal(1)", code, got)
		}
	}
}

// TestExitOfPrefixSpecificity proves the LONGEST matching prefix wins: a code
// under tx.integrity must not stop at a shorter tx.* match (there is none, but
// the walk must reach the registered tx.integrity.reservation_missing key for
// the exact string and tx.* deeper codes resolve correctly).
func TestExitOfPrefixSpecificity(t *testing.T) {
	// policy.denied (3) is more specific than any bare "policy" (unregistered);
	// policy.seal_violation (8) must NOT be captured by policy.denied.
	if ExitOf("policy.seal_violation") != ExitTimeoutPending {
		t.Fatalf("policy.seal_violation must be exit 8, not 3")
	}
	if ExitOf("policy.denied.anything.deep") != ExitPolicyDenied {
		t.Fatalf("policy.denied.* must be exit 3")
	}
}

// TestNewDerivesExit: New/Newf/Wrap derive Exit from Code via the registry.
func TestNewDerivesExit(t *testing.T) {
	if e := New("ref.not_found", "x"); e.Exit != ExitNotFound {
		t.Errorf("New ref.not_found exit = %d, want 10", e.Exit)
	}
	if e := Newf("policy.denied.day_limit", "over by %d", 5); e.Exit != ExitPolicyDenied {
		t.Errorf("Newf policy.denied.day_limit exit = %d, want 3", e.Exit)
	}
	if e := Wrap("rpc.unreachable", "dial", errors.New("conn refused")); e.Exit != ExitNetwork {
		t.Errorf("Wrap rpc.unreachable exit = %d, want 6", e.Exit)
	}
}

// TestRetryableDefaults: retryable hint inherits per family, false otherwise.
func TestRetryableDefaults(t *testing.T) {
	cases := []struct {
		code string
		want bool
	}{
		{"rpc.unreachable", true},
		{"tx.wait_timeout", true},
		{"tx.replaced", true},
		{"state.lock_timeout", true},
		{"usage.bad_address", false},
		{"policy.denied.day_limit", false},
		{"ref.not_found", false},
		{"internal", false},
	}
	for _, c := range cases {
		if got := New(c.code, "m").Retryable; got != c.want {
			t.Errorf("New(%q).Retryable = %v, want %v", c.code, got, c.want)
		}
	}
}

// TestErrorEnvelope: Error() emits the {"error":{…}} envelope with stable keys.
func TestErrorEnvelope(t *testing.T) {
	e := WithData(New("policy.denied.day_limit", "daily cap exceeded"), map[string]any{"cap": "1eth"})
	e.Retryable = true
	var got struct {
		Err struct {
			Code      string         `json:"code"`
			Exit      int            `json:"exit"`
			Msg       string         `json:"message"`
			Retryable bool           `json:"retryable"`
			Data      map[string]any `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(e.Error()), &got); err != nil {
		t.Fatalf("Error() is not valid JSON: %v\n%s", err, e.Error())
	}
	if got.Err.Code != "policy.denied.day_limit" || got.Err.Exit != 3 || got.Err.Msg != "daily cap exceeded" {
		t.Errorf("envelope fields wrong: %+v", got.Err)
	}
	if !got.Err.Retryable {
		t.Errorf("retryable not carried")
	}
	if got.Err.Data["cap"] != "1eth" {
		t.Errorf("data not carried: %+v", got.Err.Data)
	}
}

// TestErrorOmitsEmptyData: an Error with no data omits the data key.
func TestErrorOmitsEmptyData(t *testing.T) {
	e := New("ref.not_found", "no such key")
	if got := e.Error(); !json.Valid([]byte(got)) {
		t.Fatalf("not valid JSON: %s", got)
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal([]byte(e.Error()), &m)
	var inner map[string]json.RawMessage
	_ = json.Unmarshal(m["error"], &inner)
	if _, ok := inner["data"]; ok {
		t.Errorf("empty data should be omitted, got: %s", e.Error())
	}
}

// TestUnwrapAndAs: Unwrap returns the cause; AsError extracts through wrapping;
// errors.As finds the *Error; a raw error synthesizes internal.
func TestUnwrapAndAs(t *testing.T) {
	cause := errors.New("boom")
	e := Wrap("rpc.unreachable", "dial failed", cause)
	if !errors.Is(e, cause) {
		t.Errorf("errors.Is should find the wrapped cause")
	}

	// Wrap our Error in a fmt chain and recover it.
	chained := fmt.Errorf("context: %w", e)
	got := AsError(chained)
	if got.Code != "rpc.unreachable" {
		t.Errorf("AsError lost the domain code: %q", got.Code)
	}

	// A raw error becomes internal/exit 1.
	syn := AsError(errors.New("plain"))
	if syn.Code != CodeInternal || syn.Exit != ExitInternal {
		t.Errorf("AsError(raw) = {%q,%d}, want {internal,1}", syn.Code, syn.Exit)
	}
	if !errors.Is(syn, syn.wrapped) {
		t.Errorf("synthesized internal should wrap the original")
	}

	// nil in, nil out.
	if AsError(nil) != nil {
		t.Errorf("AsError(nil) must be nil")
	}
}

// TestWithDataNil: WithData on a nil error is a no-op returning nil.
func TestWithDataNil(t *testing.T) {
	if WithData(nil, map[string]any{"x": 1}) != nil {
		t.Errorf("WithData(nil,…) must return nil")
	}
}
