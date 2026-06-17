package cli

import (
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// gas_test.go pins the `daxie gas` command surface: it parses, exposes the
// documented flags, and rejects an unknown flag with the §5.7 usage code. The
// live three-speed quote against a real chain is exercised in the integration
// test + the m03.sh demo (it needs an RPC endpoint); these unit tests pin the
// thin-host boundary only.

func TestGasHelpFlags(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "gas", "--help")
	if code != int(domain.ExitOK) {
		t.Fatalf("gas --help exit = %d, want 0", code)
	}
	for _, fl := range []string{"--speed", "--legacy"} {
		if !strings.Contains(out, fl) {
			t.Errorf("gas --help missing flag %q:\n%s", fl, out)
		}
	}
}

func TestGasUnknownFlag(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "gas", "--frobnicate")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestGasNoArgs(t *testing.T) {
	isolateEnv(t)
	// `gas` takes no positional args.
	_, _, code := execCLI(t, "gas", "extra-arg")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE) for an unexpected positional arg", code, domain.ExitUsage)
	}
}
