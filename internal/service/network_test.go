package service

import (
	"context"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// openMutable opens an env-isolated service whose config dir is writable, for the
// network/rpc config-mutating use cases. Each call writes/reads the same temp
// config.toml that isolate() seeds.
func openMutable(t *testing.T) *Service {
	t.Helper()
	isolate(t)
	return openSameDir(t)
}

// openSameDir re-opens the service against the CURRENT (already-isolated) env, so a
// test can observe a config.toml mutation written by a previous Open (config is
// loaded once at Open; a fresh Open re-reads the file).
func openSameDir(t *testing.T) *Service {
	t.Helper()
	svc, err := Open(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func TestNetworkList_BuiltinsPresent(t *testing.T) {
	svc := openMutable(t)
	res, err := svc.NetworkList(context.Background(), domain.LocalCLI(), domain.NetworkListRequest{})
	if err != nil {
		t.Fatalf("NetworkList: %v", err)
	}
	var sawMainnet, sawSepolia bool
	for _, n := range res.Networks {
		switch n.Name {
		case "mainnet":
			sawMainnet = true
			if !n.Builtin {
				t.Error("mainnet not marked builtin")
			}
			if n.ChainID != 1 {
				t.Errorf("mainnet chain-id = %d, want 1", n.ChainID)
			}
		case "sepolia":
			sawSepolia = true
			if n.ChainID != 11155111 {
				t.Errorf("sepolia chain-id = %d, want 11155111", n.ChainID)
			}
		}
	}
	if !sawMainnet || !sawSepolia {
		t.Fatalf("built-in networks missing: mainnet=%v sepolia=%v", sawMainnet, sawSepolia)
	}
}

func TestNetworkShow_Unknown(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.NetworkShow(context.Background(), domain.LocalCLI(), domain.NetworkShowRequest{Name: "nope"})
	de := domain.AsError(err)
	if de.Exit != domain.ExitNotFound {
		t.Fatalf("exit = %d, want %d (NOT_FOUND)", de.Exit, domain.ExitNotFound)
	}
}

func TestNetworkAdd_ThenShow(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.NetworkAdd(context.Background(), domain.LocalCLI(), domain.NetworkAddRequest{
		Name:    "base",
		ChainID: 8453,
		RPCURL:  "https://mainnet.base.org",
	})
	if err != nil {
		t.Fatalf("NetworkAdd: %v", err)
	}
	// Re-open so the freshly-written config.toml is loaded.
	svc2 := openSameDir(t)
	res, err := svc2.NetworkShow(context.Background(), domain.LocalCLI(), domain.NetworkShowRequest{Name: "base"})
	if err != nil {
		t.Fatalf("NetworkShow(base): %v", err)
	}
	if res.Network.ChainID != 8453 {
		t.Errorf("base chain-id = %d, want 8453", res.Network.ChainID)
	}
	if res.Network.DefaultRPC != "base-default" {
		t.Errorf("base default-rpc = %q, want base-default", res.Network.DefaultRPC)
	}
}

func TestNetworkAdd_DuplicateRejected(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.NetworkAdd(context.Background(), domain.LocalCLI(), domain.NetworkAddRequest{
		Name: "mainnet", ChainID: 1,
	})
	assertCode(t, err, domain.CodeUsageNetworkExists)
}

func TestNetworkAdd_ZeroChainIDRejected(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.NetworkAdd(context.Background(), domain.LocalCLI(), domain.NetworkAddRequest{
		Name: "weird", ChainID: 0,
	})
	de := domain.AsError(err)
	if de.Exit != domain.ExitUsage {
		t.Fatalf("exit = %d, want %d (USAGE)", de.Exit, domain.ExitUsage)
	}
}

func TestNetworkUse_Unknown(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.NetworkUse(context.Background(), domain.LocalCLI(), domain.NetworkUseRequest{Name: "nope"})
	de := domain.AsError(err)
	if de.Exit != domain.ExitNotFound {
		t.Fatalf("exit = %d, want %d (NOT_FOUND)", de.Exit, domain.ExitNotFound)
	}
}

func TestNetworkUse_SetsDefault(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.NetworkUse(context.Background(), domain.LocalCLI(), domain.NetworkUseRequest{Name: "sepolia"})
	if err != nil {
		t.Fatalf("NetworkUse(sepolia): %v", err)
	}
	svc2 := openSameDir(t)
	res, err := svc2.NetworkShow(context.Background(), domain.LocalCLI(), domain.NetworkShowRequest{Name: "sepolia"})
	if err != nil {
		t.Fatalf("NetworkShow: %v", err)
	}
	if !res.Network.Default {
		t.Error("sepolia not marked default after NetworkUse")
	}
}

func TestNetworkRemove_BuiltinRefused(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.NetworkRemove(context.Background(), domain.LocalCLI(), domain.NetworkRemoveRequest{Name: "mainnet"})
	assertCode(t, err, domain.CodeUsageBuiltinImmutable)
}

func TestNetworkRemove_InUseRefusedWithoutForce(t *testing.T) {
	svc := openMutable(t)
	// Add a network WITH an endpoint, then try to remove without --force.
	if _, err := svc.NetworkAdd(context.Background(), domain.LocalCLI(), domain.NetworkAddRequest{
		Name: "base", ChainID: 8453, RPCURL: "https://mainnet.base.org",
	}); err != nil {
		t.Fatalf("NetworkAdd: %v", err)
	}
	svc2 := openSameDir(t)
	_, err := svc2.NetworkRemove(context.Background(), domain.LocalCLI(), domain.NetworkRemoveRequest{Name: "base"})
	assertCode(t, err, domain.CodeUsageNetworkInUse)

	// With --force it removes.
	svc3 := openSameDir(t)
	if _, err := svc3.NetworkRemove(context.Background(), domain.LocalCLI(), domain.NetworkRemoveRequest{Name: "base", Force: true}); err != nil {
		t.Fatalf("NetworkRemove(force): %v", err)
	}
}
