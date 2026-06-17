package cli

import (
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// verify_test.go drives `daxie verify` through the real Execute funnel: the flag
// wiring + the §5.7 exit codes on the paths that fail BEFORE any ecrecover (missing
// --signature/--address, the scheme mutual-exclusion, --no-hash + --typed). The
// recover-and-compare happy/mismatch paths run against anvil in the integration
// tests.

func TestVerifyBindsFlags(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "verify", "--help")
	if code != 0 {
		t.Fatalf("verify --help exit = %d, want 0", code)
	}
	for _, fl := range []string{"--message", "--message-stdin", "--typed", "--typed-stdin", "--signature", "--address", "--no-hash"} {
		if !strings.Contains(out, fl) {
			t.Errorf("verify --help missing flag %q:\n%s", fl, out)
		}
	}
}

func TestVerifyMissingSignatureExit2(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "verify", "--message", "hello", "--address", "0x000000000000000000000000000000000000bEEF")
	if code != int(domain.ExitUsage) {
		t.Fatalf("verify without --signature exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "signature") {
		t.Errorf("error should mention the missing --signature:\n%s", stderr)
	}
}

func TestVerifyMissingAddressExit2(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "verify", "--message", "hello", "--signature", "0xabcd")
	if code != int(domain.ExitUsage) {
		t.Fatalf("verify without --address exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "address") {
		t.Errorf("error should mention the missing --address:\n%s", stderr)
	}
}

// Neither --message nor --typed is a usage error (no scheme selected).
func TestVerifyNoSchemeExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "verify", "--signature", "0xabcd", "--address", "0x000000000000000000000000000000000000bEEF")
	if code != int(domain.ExitUsage) {
		t.Fatalf("verify (no scheme) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// Both --message and --typed is a usage error (two schemes selected).
func TestVerifyBothSchemesExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "verify", "--message", "hello", "--typed", "/tmp/x.json",
		"--signature", "0xabcd", "--address", "0x000000000000000000000000000000000000bEEF")
	if code != int(domain.ExitUsage) {
		t.Fatalf("verify --message + --typed exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// --no-hash with --typed is a usage error (the digest form is EIP-191 only).
func TestVerifyNoHashWithTypedExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "verify", "--typed", "/tmp/x.json", "--no-hash",
		"--signature", "0xabcd", "--address", "0x000000000000000000000000000000000000bEEF")
	if code != int(domain.ExitUsage) {
		t.Fatalf("verify --typed --no-hash exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// --no-hash with a malformed digest is rejected (verify.bad_signature) before any
// recover.
func TestVerifyNoHashBadDigestExit2(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "verify", "--message", "0xdeadbeef", "--no-hash",
		"--signature", "0xabcd", "--address", "0x000000000000000000000000000000000000bEEF")
	if code != int(domain.ExitUsage) {
		t.Fatalf("verify --no-hash <bad digest> exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "verify.bad_signature") {
		t.Errorf("want verify.bad_signature:\n%s", stderr)
	}
}
