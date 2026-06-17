package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// sign_test.go drives the `daxie sign` command tree through the real Execute funnel
// (execCLI → newRootCmd → mapError): the flag→request wiring + the §5.7 exit codes on
// the paths that fail BEFORE any signing (mutually-exclusive sources, the --no-hash
// validation, the --unlimited --yes ceremony). The chain/keystore-touching happy
// paths (EIP-191 sign + verify roundtrip, the EIP-2612 permit gate) are covered by
// the anvil integration tests.

func TestSignHelpListsSubcommands(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "sign", "--help")
	if code != 0 {
		t.Fatalf("sign --help exit = %d, want 0", code)
	}
	for _, sub := range []string{"message", "typed"} {
		if !strings.Contains(out, sub) {
			t.Errorf("sign --help missing subcommand %q:\n%s", sub, out)
		}
	}
}

func TestSignMessageBindsFlags(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "sign", "message", "--help")
	if code != 0 {
		t.Fatalf("sign message --help exit = %d, want 0", code)
	}
	for _, fl := range []string{"--account", "--from", "--stdin", "--no-hash"} {
		if !strings.Contains(out, fl) {
			t.Errorf("sign message --help missing flag %q:\n%s", fl, out)
		}
	}
}

func TestSignTypedBindsFlags(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "sign", "typed", "--help")
	if code != 0 {
		t.Fatalf("sign typed --help exit = %d, want 0", code)
	}
	for _, fl := range []string{"--account", "--data", "--data-stdin", "--unlimited"} {
		if !strings.Contains(out, fl) {
			t.Errorf("sign typed --help missing flag %q:\n%s", fl, out)
		}
	}
}

// A message provided BOTH as a positional arg AND --stdin is a usage error, caught
// in the frontend before any signing.
func TestSignMessageArgAndStdinExit2(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "sign", "message", "hello", "--stdin")
	if code != int(domain.ExitUsage) {
		t.Fatalf("sign message <arg> --stdin exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "sign.bad_message") {
		t.Errorf("error code should be sign.bad_message:\n%s", stderr)
	}
}

// A message with neither a positional arg nor --stdin is a usage error.
func TestSignMessageNoSourceExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "sign", "message")
	if code != int(domain.ExitUsage) {
		t.Fatalf("sign message (no source) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// --no-hash with a non-0x / wrong-length digest is rejected in the frontend (the
// single decode point) with sign.bad_message → exit 2, before any signing.
func TestSignMessageNoHashBadDigestExit2(t *testing.T) {
	isolateEnv(t)
	t.Run("not 0x", func(t *testing.T) {
		_, stderr, code := execCLI(t, "sign", "message", "deadbeef", "--no-hash")
		if code != int(domain.ExitUsage) {
			t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
		}
		if !strings.Contains(stderr, "sign.bad_message") {
			t.Errorf("want sign.bad_message:\n%s", stderr)
		}
	})
	t.Run("wrong length", func(t *testing.T) {
		// 0x + 8 hex = 4 bytes, not 32.
		_, _, code := execCLI(t, "sign", "message", "0xdeadbeef", "--no-hash")
		if code != int(domain.ExitUsage) {
			t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
		}
	})
}

// sign typed with neither --data nor --data-stdin is a usage error.
func TestSignTypedNoSourceExit2(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "sign", "typed")
	if code != int(domain.ExitUsage) {
		t.Fatalf("sign typed (no source) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "sign.bad_typed") {
		t.Errorf("want sign.bad_typed:\n%s", stderr)
	}
}

// sign typed with BOTH --data and --data-stdin is a usage error.
func TestSignTypedBothSourcesExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "sign", "typed", "--data", "/tmp/x.json", "--data-stdin")
	if code != int(domain.ExitUsage) {
		t.Fatalf("sign typed --data + --data-stdin exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// sign typed --data <missing-file> is sign.bad_typed → exit 2 (the frontend reads
// the document; an unreadable path is a usage-class input error).
func TestSignTypedMissingFileExit2(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "sign", "typed", "--data", "/no/such/typed.json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("sign typed --data <missing> exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "sign.bad_typed") {
		t.Errorf("want sign.bad_typed:\n%s", stderr)
	}
}

// sign typed --unlimited WITHOUT --yes is refused at the cli (the §4.3 stage-6
// ceremony) — exit 2, BEFORE the document is even read.
func TestSignTypedUnlimitedWithoutYesExit2(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "sign", "typed", "--data-stdin", "--unlimited")
	if code != int(domain.ExitUsage) {
		t.Fatalf("sign typed --unlimited without --yes exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "unlimited") {
		t.Errorf("error should mention the unlimited acknowledgement:\n%s", stderr)
	}
}

// ── policy typed allow|remove (M9 admin surface) ──────────────────────────────

func TestPolicyTypedHelpListsSubcommands(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "policy", "typed", "--help")
	if code != 0 {
		t.Fatalf("policy typed --help exit = %d, want 0", code)
	}
	for _, sub := range []string{"allow", "remove"} {
		if !strings.Contains(out, sub) {
			t.Errorf("policy typed --help missing subcommand %q:\n%s", sub, out)
		}
	}
}

// policy typed allow REQUIRES --chain-id (>0) / --contract (0x) / --primary-type,
// caught in the frontend BEFORE the admin passphrase is acquired or anything sealed.
func TestPolicyTypedAllowMissingFlagsExit2(t *testing.T) {
	isolateEnv(t)
	cases := [][]string{
		{"policy", "typed", "allow", "--contract", "0x000000000000000000000000000000000000bEEF", "--primary-type", "Order"},                    // no chain-id
		{"policy", "typed", "allow", "--chain-id", "1", "--primary-type", "Order"},                                                             // no contract
		{"policy", "typed", "allow", "--chain-id", "1", "--contract", "0x000000000000000000000000000000000000bEEF"},                            // no primary-type
		{"policy", "typed", "allow", "--chain-id", "1", "--contract", "not-an-address", "--primary-type", "Order"},                             // bad contract
		{"policy", "typed", "allow", "--chain-id", "0", "--contract", "0x000000000000000000000000000000000000bEEF", "--primary-type", "Order"}, // chain-id 0
	}
	for _, args := range cases {
		_, stderr, code := execCLI(t, args...)
		if code != int(domain.ExitUsage) {
			t.Errorf("%v exit = %d, want %d (USAGE); stderr=%s", args, code, domain.ExitUsage, stderr)
		}
		if !strings.Contains(stderr, "bad_typed_allow") {
			t.Errorf("%v error code should be usage.bad_typed_allow:\n%s", args, stderr)
		}
	}
}

// The admin-passphrase channel is bound on policy typed allow|remove and is DISTINCT
// from the keystore passphrase channel (§3.7), exactly like every other mutation.
func TestPolicyTypedAdminFlagsBound(t *testing.T) {
	isolateEnv(t)
	rs := &rootState{}
	root := newRootCmd(context.Background(), rs)
	for _, sub := range []string{"allow", "remove"} {
		cmd, _, err := root.Find([]string{"policy", "typed", sub})
		if err != nil {
			t.Fatalf("find policy typed %s: %v", sub, err)
		}
		if cmd.Flags().Lookup("admin-passphrase-file") == nil {
			t.Errorf("policy typed %s missing --admin-passphrase-file", sub)
		}
		if cmd.Flags().Lookup("passphrase-stdin") != nil {
			t.Errorf("policy typed %s leaks the keystore --passphrase-stdin", sub)
		}
		for _, fl := range []string{"chain-id", "contract", "primary-type"} {
			if cmd.Flags().Lookup(fl) == nil {
				t.Errorf("policy typed %s missing --%s", sub, fl)
			}
		}
	}
}

// readMessagePayload reads --stdin verbatim (no trimming) so the EIP-191 payload is
// exactly what the caller piped. A unit test of the payload reader via the cobra
// InOrStdin seam (no service needed).
func TestReadMessagePayloadStdinVerbatim(t *testing.T) {
	root := newRootCmd(context.Background(), &rootState{})
	// Find the `sign message` command to borrow its InOrStdin seam.
	signCmd, _, err := root.Find([]string{"sign", "message"})
	if err != nil {
		t.Fatalf("locating sign message command: %v", err)
	}
	signCmd.SetIn(bytes.NewBufferString("payload-bytes"))
	got, err := readMessagePayload(signCmd, nil, true, false)
	if err != nil {
		t.Fatalf("readMessagePayload(stdin): %v", err)
	}
	if string(got) != "payload-bytes" {
		t.Errorf("stdin payload = %q, want %q (verbatim)", got, "payload-bytes")
	}
}
