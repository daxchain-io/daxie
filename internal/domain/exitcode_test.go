package domain

import "testing"

// TestExitCodeNames asserts every assigned code 0..12 renders to the §5.7 Name
// column and that out-of-range codes use the EXIT(n) fallback.
func TestExitCodeNames(t *testing.T) {
	cases := []struct {
		code ExitCode
		want string
	}{
		{ExitOK, "OK"},
		{ExitInternal, "INTERNAL"},
		{ExitUsage, "USAGE"},
		{ExitPolicyDenied, "POLICY_DENIED"},
		{ExitAuth, "AUTH"},
		{ExitInsufficientFunds, "INSUFFICIENT_FUNDS"},
		{ExitNetwork, "NETWORK"},
		{ExitReverted, "REVERTED"},
		{ExitTimeoutPending, "TIMEOUT_PENDING"},
		{ExitTxConflict, "TX_CONFLICT"},
		{ExitNotFound, "NOT_FOUND"},
		{ExitState, "STATE"},
		{ExitIntegrity, "INTEGRITY"},
		{ExitCode(13), "EXIT(13)"},
		{ExitCode(64), "EXIT(64)"},
		{ExitCode(-1), "EXIT(-1)"},
	}
	for _, c := range cases {
		if got := c.code.String(); got != c.want {
			t.Errorf("ExitCode(%d).String() = %q, want %q", c.code, got, c.want)
		}
	}
}

// TestExitCodeNumbersStable pins the integer values: a change here is a wire
// break (§5.7 is "stable, binding").
func TestExitCodeNumbersStable(t *testing.T) {
	want := map[string]ExitCode{
		"OK": 0, "INTERNAL": 1, "USAGE": 2, "POLICY_DENIED": 3, "AUTH": 4,
		"INSUFFICIENT_FUNDS": 5, "NETWORK": 6, "REVERTED": 7, "TIMEOUT_PENDING": 8,
		"TX_CONFLICT": 9, "NOT_FOUND": 10, "STATE": 11, "INTEGRITY": 12,
	}
	got := map[string]ExitCode{
		ExitOK.String(): ExitOK, ExitInternal.String(): ExitInternal,
		ExitUsage.String(): ExitUsage, ExitPolicyDenied.String(): ExitPolicyDenied,
		ExitAuth.String(): ExitAuth, ExitInsufficientFunds.String(): ExitInsufficientFunds,
		ExitNetwork.String(): ExitNetwork, ExitReverted.String(): ExitReverted,
		ExitTimeoutPending.String(): ExitTimeoutPending, ExitTxConflict.String(): ExitTxConflict,
		ExitNotFound.String(): ExitNotFound, ExitState.String(): ExitState,
		ExitIntegrity.String(): ExitIntegrity,
	}
	for name, n := range want {
		if got[name] != n {
			t.Errorf("exit %q = %d, want %d", name, got[name], n)
		}
	}
}

func TestItoa(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"}, {7, "7"}, {13, "13"}, {-1, "-1"}, {-42, "-42"},
		{2147483647, "2147483647"}, {-2147483648, "-2147483648"},
	}
	for _, c := range cases {
		if got := itoa(c.in); got != c.want {
			t.Errorf("itoa(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
