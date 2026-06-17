package cli

import (
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// token_test.go drives the `daxie token` command tree through the real Execute
// funnel (execCLI → newRootCmd → mapError): the flag→request wiring + the §5.7 exit
// codes on the paths that fail BEFORE any dial (missing flags, the --unlimited --yes
// ceremony, mutually-exclusive flags, arg counts). The chain-touching happy paths
// (add/balance/approve/allowance/revoke against a deployed ERC-20) are covered by the
// integration tests against anvil.

func TestTokenHelpListsSubcommands(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "token", "--help")
	if code != 0 {
		t.Fatalf("token --help exit = %d, want 0", code)
	}
	for _, sub := range []string{"info", "add", "rename", "list", "remove", "approve", "allowance", "revoke"} {
		if !strings.Contains(out, sub) {
			t.Errorf("token --help missing subcommand %q:\n%s", sub, out)
		}
	}
}

func TestTokenInfoArgCount(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "token", "info")
	if code != int(domain.ExitUsage) {
		t.Fatalf("token info (no arg) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestTokenAddArgCount(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "token", "add")
	if code != int(domain.ExitUsage) {
		t.Fatalf("token add (no arg) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestTokenRenameArgCount(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "token", "rename", "onlyone")
	if code != int(domain.ExitUsage) {
		t.Fatalf("token rename (1 arg) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// approve REQUIRES --spender — caught before any dial.
func TestTokenApproveMissingSpender(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "token", "approve", "usdc", "--amount", "100", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("approve without --spender exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "spender") {
		t.Errorf("error should mention the missing --spender:\n%s", stderr)
	}
}

// approve with neither --amount nor --unlimited is a usage error.
func TestTokenApproveMissingAmount(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "token", "approve", "usdc", "--spender", "0x000000000000000000000000000000000000bEEF")
	if code != int(domain.ExitUsage) {
		t.Fatalf("approve without --amount/--unlimited exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// approve --unlimited WITHOUT --yes is refused at the cli (the §4.2 ceremony) — exit 2,
// BEFORE any dial.
func TestTokenApproveUnlimitedWithoutYes(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "token", "approve", "usdc", "--spender", "0x000000000000000000000000000000000000bEEF", "--unlimited", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("--unlimited without --yes exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "unlimited") {
		t.Errorf("error should mention the unlimited acknowledgement:\n%s", stderr)
	}
}

// approve --unlimited AND --amount together is a usage error (mutually exclusive).
func TestTokenApproveUnlimitedAndAmount(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "token", "approve", "usdc",
		"--spender", "0x000000000000000000000000000000000000bEEF", "--unlimited", "--amount", "5", "--yes")
	if code != int(domain.ExitUsage) {
		t.Fatalf("--unlimited + --amount exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// revoke REQUIRES --spender.
func TestTokenRevokeMissingSpender(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "token", "revoke", "usdc")
	if code != int(domain.ExitUsage) {
		t.Fatalf("revoke without --spender exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// allowance REQUIRES --spender.
func TestTokenAllowanceMissingSpender(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "token", "allowance", "usdc")
	if code != int(domain.ExitUsage) {
		t.Fatalf("allowance without --spender exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// approve binds the shared wait flags (so the #19 exit codes flow through the same
// machine as tx send): assert the flags exist on the command surface.
func TestTokenApproveBindsWaitFlags(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "token", "approve", "--help")
	if code != 0 {
		t.Fatalf("token approve --help exit = %d, want 0", code)
	}
	for _, fl := range []string{"--spender", "--amount", "--unlimited", "--wait", "--confirmations", "--timeout"} {
		if !strings.Contains(out, fl) {
			t.Errorf("token approve --help missing flag %q:\n%s", fl, out)
		}
	}
}
