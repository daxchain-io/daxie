package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// policy_test.go pins the `daxie policy` thin-host boundary: the command structure,
// flag→request plumbing, the §5.7 exit-code mapping, and the §4.6 Viper carve-out.
// The seal/anchor/limit BEHAVIOR is unit-tested in internal/policy and exercised
// end-to-end (with the admin passphrase + anvil) in service/tx_integration_test.go
// and docs/demos/m04.sh — these cli tests deliberately avoid the scrypt-heavy
// mutation path and assert the surface the frontend owns.

// Pre-bootstrap: `policy show` reports inactive (opt-in), exit 0, valid --json. No
// anchor, no scrypt — fast.
func TestPolicyShowPreBootstrap(t *testing.T) {
	isolateEnv(t)

	t.Run("human", func(t *testing.T) {
		out, _, code := execCLI(t, "policy", "show")
		if code != int(domain.ExitOK) {
			t.Fatalf("exit = %d, want 0", code)
		}
		if !strings.Contains(out, "inactive") {
			t.Errorf("pre-bootstrap show should report inactive (opt-in):\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out, _, code := execCLI(t, "policy", "show", "--json")
		if code != int(domain.ExitOK) {
			t.Fatalf("exit = %d, want 0", code)
		}
		var res struct {
			Active bool `json:"active"`
		}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("policy show --json not valid JSON: %v (%q)", err, out)
		}
		if res.Active {
			t.Error("pre-bootstrap policy show reports active=true, want false (opt-in)")
		}
	})
}

// `policy verify` with no anchor is a no-op success (opt-in) — exit 0, no passphrase.
func TestPolicyVerifyPreBootstrap(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "policy", "verify")
	if code != int(domain.ExitOK) {
		t.Fatalf("policy verify (no anchor) exit = %d, want 0 (opt-in)", code)
	}
}

// `policy pin --print` with no anchor is a seal violation (exit 8): there is no
// trust root to print, and the fail-closed direction is exit 8, not a fake empty.
func TestPolicyPinPrintNoAnchorExit8(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "policy", "pin", "--print")
	if code != int(domain.ExitTimeoutPending) { // exit 8 family (seal/auth/state)
		t.Fatalf("policy pin --print (no anchor) exit = %d, want 8 (seal_violation)", code)
	}
}

// `policy pin` with neither --print nor --verify is a usage error (exit 2).
func TestPolicyPinNeitherFlagExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "policy", "pin")
	if code != int(domain.ExitUsage) {
		t.Fatalf("policy pin (no flag) exit = %d, want 2 (USAGE)", code)
	}
}

// `policy check` requires --from and --to → exit 2 when missing.
func TestPolicyCheckMissingFlagsExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "policy", "check", "--amount", "1eth")
	if code != int(domain.ExitUsage) {
		t.Fatalf("policy check (no --from/--to) exit = %d, want 2 (USAGE)", code)
	}
}

// `policy check` with a bad --from address is a usage error (exit 2).
func TestPolicyCheckBadAddressExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "policy", "check", "--from", "not-an-address", "--to",
		"0x52908400098527886E0F7030069857D2E4169EE7", "--amount", "1eth")
	if code != int(domain.ExitUsage) {
		t.Fatalf("policy check (bad --from) exit = %d, want 2 (USAGE)", code)
	}
}

// `policy reset` without --force is a usage error (exit 2) — NO --yes bypass, and
// --force is required to acknowledge the destructive reseal (§4.7 J12).
func TestPolicyResetRequiresForceExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "policy", "reset")
	if code != int(domain.ExitUsage) {
		t.Fatalf("policy reset (no --force) exit = %d, want 2 (USAGE)", code)
	}
}

// `policy change-admin-passphrase` requires exactly one of --stage/--commit → exit 2.
func TestPolicyChangeAdminRequiresPhaseExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "policy", "change-admin-passphrase")
	if code != int(domain.ExitUsage) {
		t.Fatalf("change-admin-passphrase (no --stage/--commit) exit = %d, want 2", code)
	}
	_, _, code = execCLI(t, "policy", "change-admin-passphrase", "--stage", "--commit")
	if code != int(domain.ExitUsage) {
		t.Fatalf("change-admin-passphrase (both phases) exit = %d, want 2", code)
	}
}

// `policy allow` of a bare ENS/contact name (no resolver in M4) fails clean (exit 2),
// never a silent unpinned name (the §4.8 invariant: pins are resolved 0x, never names).
func TestPolicyAllowNameUnsupportedExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "policy", "allow", "vitalik.eth")
	if code != int(domain.ExitUsage) {
		t.Fatalf("policy allow <ens> (M4) exit = %d, want 2 (unsupported)", code)
	}
}

// The §4.6 Viper carve-out at the cli layer: `config set policy.*` is rejected
// (exit 2) and `config get policy.*` is not a key (exit 10) — no flag/env can reach
// the anchor through config. (The config-package regression lives in
// internal/config/anchor_test.go; this pins the cli funnel.)
func TestPolicyConfigCarveOut(t *testing.T) {
	isolateEnv(t)
	if _, _, code := execCLI(t, "config", "set", "policy.verify_key", "ed25519:x"); code != int(domain.ExitUsage) {
		t.Errorf("config set policy.verify_key exit = %d, want 2 (USAGE)", code)
	}
	// `config get policy.*` is rejected as a usage error (the policy subtree is never
	// a config key; getset.go returns usage.policy_key, exit 2) — the carve-out is
	// "policy is not config", not "unknown key".
	if _, _, code := execCLI(t, "config", "get", "policy.verify_key"); code != int(domain.ExitUsage) {
		t.Errorf("config get policy.verify_key exit = %d, want 2 (USAGE)", code)
	}
}

// The admin-passphrase channel flags are bound on every mutation and are DISTINCT
// from the keystore passphrase flags (§3.7). A pure structural check: the flags
// exist and parse.
func TestPolicyAdminFlagsBound(t *testing.T) {
	isolateEnv(t)
	rs := &rootState{}
	root := newRootCmd(context.Background(), rs)
	for _, sub := range []string{"set", "allow", "deny", "reset", "change-admin-passphrase"} {
		cmd, _, err := root.Find([]string{"policy", sub})
		if err != nil {
			t.Fatalf("find policy %s: %v", sub, err)
		}
		if cmd.Flags().Lookup("admin-passphrase-stdin") == nil {
			t.Errorf("policy %s missing --admin-passphrase-stdin", sub)
		}
		if cmd.Flags().Lookup("admin-passphrase-file") == nil {
			t.Errorf("policy %s missing --admin-passphrase-file", sub)
		}
		// The admin channel must NOT collide with the keystore passphrase channel.
		if cmd.Flags().Lookup("passphrase-stdin") != nil {
			t.Errorf("policy %s leaks the keystore --passphrase-stdin (admin must be distinct)", sub)
		}
	}
	// The rotation target channel is bound only on change-admin-passphrase.
	cmd, _, _ := root.Find([]string{"policy", "change-admin-passphrase"})
	if cmd.Flags().Lookup("new-admin-passphrase-file") == nil {
		t.Error("change-admin-passphrase missing --new-admin-passphrase-file")
	}
}
