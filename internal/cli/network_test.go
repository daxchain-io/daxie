package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

func TestNetworkList(t *testing.T) {
	isolateEnv(t)

	t.Run("human", func(t *testing.T) {
		out, _, code := execCLI(t, "network", "list")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if !strings.Contains(out, "mainnet") || !strings.Contains(out, "sepolia") {
			t.Errorf("network list missing built-ins:\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out, _, code := execCLI(t, "network", "list", "--json")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		var res struct {
			Networks []struct {
				Name    string `json:"name"`
				ChainID uint64 `json:"chain_id"`
				Builtin bool   `json:"builtin"`
			} `json:"networks"`
		}
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("not valid JSON: %v (%q)", err, out)
		}
		var mainnet bool
		for _, n := range res.Networks {
			if n.Name == "mainnet" {
				mainnet = true
				if n.ChainID != 1 || !n.Builtin {
					t.Errorf("mainnet row wrong: %+v", n)
				}
			}
		}
		if !mainnet {
			t.Error("mainnet missing from --json output")
		}
	})
}

func TestNetworkShowUnknownExit10(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "network", "show", "nope")
	if code != int(domain.ExitNotFound) {
		t.Fatalf("exit = %d, want %d (NOT_FOUND)", code, domain.ExitNotFound)
	}
}

func TestNetworkAddThenShow(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "network", "add", "base", "--chain-id", "8453", "--rpc-url", "https://mainnet.base.org")
	if code != 0 {
		t.Fatalf("network add exit = %d, want 0", code)
	}
	out, _, code := execCLI(t, "network", "show", "base", "--json")
	if code != 0 {
		t.Fatalf("network show exit = %d, want 0", code)
	}
	var res struct {
		Network struct {
			ChainID    uint64 `json:"chain_id"`
			DefaultRPC string `json:"default_rpc"`
		} `json:"network"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not valid JSON: %v (%q)", err, out)
	}
	if res.Network.ChainID != 8453 {
		t.Errorf("base chain-id = %d, want 8453", res.Network.ChainID)
	}
	if res.Network.DefaultRPC != "base-default" {
		t.Errorf("base default-rpc = %q, want base-default", res.Network.DefaultRPC)
	}
}

func TestNetworkAddMissingChainIDExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "network", "add", "base")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestNetworkAddDuplicateExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "network", "add", "mainnet", "--chain-id", "1")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestNetworkUseThenDefault(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "network", "use", "sepolia")
	if code != 0 {
		t.Fatalf("network use exit = %d, want 0", code)
	}
	out, _, code := execCLI(t, "network", "show", "sepolia", "--json")
	if code != 0 {
		t.Fatalf("network show exit = %d, want 0", code)
	}
	if !strings.Contains(out, "\"default\": true") {
		t.Errorf("sepolia not marked default:\n%s", out)
	}
}

func TestNetworkRemoveBuiltinExit2(t *testing.T) {
	isolateEnv(t)
	// --yes to skip the confirmation ceremony (non-interactive).
	_, _, code := execCLI(t, "network", "remove", "mainnet", "--yes")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE, builtin immutable)", code, domain.ExitUsage)
	}
}
