package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// The balance command's chain-touching path needs a live endpoint (covered by the
// service integration tests against anvil). These CLI tests exercise the paths
// that fail BEFORE any dial — the M5/M7 not-yet-active flags and the missing-account
// case — so they assert the command wiring + §5.7 exit codes without a network.

func TestBalanceTokenRejectedExit2(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "balance", "0x000000000000000000000000000000000000dEaD", "--token", "USDC", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(stderr), &env); err != nil {
		t.Fatalf("error envelope not JSON: %v (%q)", err, stderr)
	}
	if env.Error.Code != domain.CodeUsageUnsupported {
		t.Errorf("code = %q, want %q", env.Error.Code, domain.CodeUsageUnsupported)
	}
}

func TestBalanceAllRejectedExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "balance", "0x000000000000000000000000000000000000dEaD", "--all")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestBalanceENSRejectedExit2(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "balance", "vitalik.eth", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, domain.CodeUsageUnsupported) {
		t.Errorf("expected usage.unsupported for an ENS arg:\n%s", stderr)
	}
}

func TestBalanceNoAccountNoDefaultExit2(t *testing.T) {
	isolateEnv(t)
	// No arg, no default account configured → a usage error, never a dial.
	_, _, code := execCLI(t, "balance")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestBalanceTooManyArgsExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "balance", "a", "b")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}
