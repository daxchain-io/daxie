package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

func TestRpcList(t *testing.T) {
	isolateEnv(t)

	t.Run("human", func(t *testing.T) {
		out, _, code := execCLI(t, "rpc", "list")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if !strings.Contains(out, "mainnet-public") {
			t.Errorf("rpc list missing mainnet-public:\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out, _, code := execCLI(t, "rpc", "list", "--json")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		var res struct {
			RPCs []struct {
				Name    string `json:"name"`
				Network string `json:"network"`
			} `json:"rpcs"`
		}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("not valid JSON: %v (%q)", err, out)
		}
		if len(res.RPCs) == 0 {
			t.Error("rpc list --json empty")
		}
	})
}

func TestRpcAddThenShowMasked(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "rpc", "add", "mainnet-alchemy",
		"--network", "mainnet",
		"--url", "https://eth-mainnet.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}")
	if code != 0 {
		t.Fatalf("rpc add exit = %d, want 0", code)
	}
	out, _, code := execCLI(t, "rpc", "show", "mainnet-alchemy", "--json")
	if code != 0 {
		t.Fatalf("rpc show exit = %d, want 0", code)
	}
	// The secret reference is shown as the reference, never resolved.
	if !strings.Contains(out, "${env:ALCHEMY_API_KEY}") {
		t.Errorf("rpc show should preserve the ${env:} reference:\n%s", out)
	}
}

func TestRpcAddMissingNetworkExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "rpc", "add", "x", "--url", "https://x.example.com")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestRpcAddUnknownNetworkExit10(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "rpc", "add", "x", "--network", "ghost", "--url", "https://x.example.com")
	if code != int(domain.ExitNotFound) {
		t.Fatalf("exit = %d, want %d (NOT_FOUND)", code, domain.ExitNotFound)
	}
}

func TestRpcAddStrictSecretExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "rpc", "add", "leaky",
		"--network", "mainnet",
		"--url", "https://eth.example.com/v2/abcdef0123456789abcdef0123456789",
		"--strict-secrets")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE, literal secret)", code, domain.ExitUsage)
	}
}

func TestRpcAddHeaderParsing(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "rpc", "add", "mainnet-infura",
		"--network", "mainnet",
		"--url", "https://mainnet.infura.io/v3/${env:INFURA_PROJECT_ID}",
		"--header", "Authorization: Bearer ${file:~/.config/daxie/secrets/jwt}")
	if code != 0 {
		t.Fatalf("rpc add with header exit = %d, want 0", code)
	}
	out, _, code := execCLI(t, "rpc", "show", "mainnet-infura", "--json")
	if code != 0 {
		t.Fatalf("rpc show exit = %d, want 0", code)
	}
	if !strings.Contains(out, "\"has_headers\": true") {
		t.Errorf("endpoint should report has_headers=true:\n%s", out)
	}
}

func TestRpcAddBadHeaderExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "rpc", "add", "x",
		"--network", "mainnet",
		"--url", "https://x.example.com",
		"--header", "NoColonHere")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE, bad header)", code, domain.ExitUsage)
	}
}

func TestRpcUseThenDefault(t *testing.T) {
	isolateEnv(t)
	// A 127.0.0.1:1 URL is refused instantly, so add-time chain-ID verification
	// downgrades to a warning (exit 0) without a real network round trip — the
	// `rpc add → rpc use` flow under test does not depend on a reachable node.
	if _, _, code := execCLI(t, "rpc", "add", "mainnet-alt", "--network", "mainnet", "--url", "http://127.0.0.1:1"); code != 0 {
		t.Fatalf("rpc add exit = %d, want 0", code)
	}
	if _, _, code := execCLI(t, "rpc", "use", "mainnet-alt"); code != 0 {
		t.Fatalf("rpc use exit = %d, want 0", code)
	}
	out, _, code := execCLI(t, "network", "show", "mainnet", "--json")
	if code != 0 {
		t.Fatalf("network show exit = %d, want 0", code)
	}
	if !strings.Contains(out, "\"default_rpc\": \"mainnet-alt\"") {
		t.Errorf("mainnet default-rpc not updated:\n%s", out)
	}
}

func TestRpcRenameBuiltinExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "rpc", "rename", "mainnet-public", "mainnet-fallback")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE, builtin immutable)", code, domain.ExitUsage)
	}
}

func TestRpcRemoveUserEndpoint(t *testing.T) {
	isolateEnv(t)
	// 127.0.0.1:1 is refused instantly: add-time verification downgrades to a
	// warning (exit 0) with no real round trip (this test exercises remove, not
	// connectivity).
	if _, _, code := execCLI(t, "rpc", "add", "mainnet-alt", "--network", "mainnet", "--url", "http://127.0.0.1:1"); code != 0 {
		t.Fatalf("rpc add exit = %d, want 0", code)
	}
	_, _, code := execCLI(t, "rpc", "remove", "mainnet-alt", "--yes")
	if code != 0 {
		t.Fatalf("rpc remove exit = %d, want 0", code)
	}
}

func TestRpcRemoveBuiltinExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "rpc", "remove", "sepolia-public", "--yes")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE, builtin immutable)", code, domain.ExitUsage)
	}
}
