package domain

import (
	"encoding/json"
	"testing"
)

// sign_requests_test.go pins the M9 sign/verify wire shapes (the JSON tags both the
// --json frontend and the future MCP schema bind against) + the §5.7 exit mapping of
// the four sign/verify codes. No float anywhere (§2.5): every field is a string.

func TestSigResultWireShape(t *testing.T) {
	r := SigResult{
		Signature: "0xsig",
		Signer:    "0xabc",
		Digest:    "0xdig",
		Scheme:    "eip191",
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"signature", "signer", "digest", "scheme"} {
		if _, ok := m[k]; !ok {
			t.Errorf("SigResult JSON missing key %q (got %s)", k, b)
		}
	}
	if len(m) != 4 {
		t.Errorf("SigResult JSON has %d keys, want 4 (%s)", len(m), b)
	}
}

func TestVerifyResultWireShape(t *testing.T) {
	r := VerifyResult{
		Valid:     false,
		Signer:    "0xclaimed",
		Recovered: "0xother",
		Digest:    "0xdig",
		Scheme:    "eip712",
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"valid", "signer", "recovered", "digest", "scheme"} {
		if _, ok := m[k]; !ok {
			t.Errorf("VerifyResult JSON missing key %q (got %s)", k, b)
		}
	}
	// valid is a bool, not a string (the only non-string field, by design).
	if _, ok := m["valid"].(bool); !ok {
		t.Errorf("VerifyResult.valid must marshal as a JSON bool (got %s)", b)
	}
}

func TestSignVerifyExitCodes(t *testing.T) {
	cases := []struct {
		code string
		want ExitCode
	}{
		{CodeSignBadMessage, ExitUsage},
		{CodeSignBadTyped, ExitUsage},
		{CodeVerifyBadSig, ExitUsage},
		{CodeVerifyMismatch, ExitUsage},
		// A mismatch must NEVER land on the auth band (that is the keystore passphrase
		// class) — guard the exact non-collision the agent contract depends on.
		{CodeVerifyMismatch, ExitUsage},
	}
	for _, tc := range cases {
		if got := ExitOf(tc.code); got != tc.want {
			t.Errorf("ExitOf(%q) = %d, want %d", tc.code, got, tc.want)
		}
	}
	if ExitOf(CodeVerifyMismatch) == ExitAuth {
		t.Fatal("verify.mismatch must not map to ExitAuth — agents must not confuse it with a bad passphrase")
	}
}
