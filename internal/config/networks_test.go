package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// newCfgDir wires a temp config dir into the env and returns its Paths.
func newCfgDir(t *testing.T) (string, Paths) {
	t.Helper()
	dir := t.TempDir()
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, err := ResolvePaths(FlagValues{Config: dir})
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	return dir, p
}

func loadCfg(t *testing.T, dir string) *Config {
	t.Helper()
	cfg, _, err := Load(FlagValues{Config: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// TestBuiltinPresetsResolve: a fresh (empty) config exposes the built-in mainnet +
// sepolia networks and their public default endpoints, so balance works out of the
// box (§7.4). Networks and endpoints are SEPARATE objects.
func TestBuiltinPresetsResolve(t *testing.T) {
	dir, _ := newCfgDir(t)
	cfg := loadCfg(t, dir)

	mn, err := cfg.ShowNetwork("mainnet")
	if err != nil {
		t.Fatalf("ShowNetwork mainnet: %v", err)
	}
	if mn.ChainID != 1 || !mn.Builtin || mn.DefaultRPC != "mainnet-public" {
		t.Errorf("mainnet view = %+v", mn)
	}
	if !mn.Default {
		t.Errorf("mainnet should be the default network out of the box")
	}
	sp, err := cfg.ShowNetwork("sepolia")
	if err != nil || sp.ChainID != 11155111 {
		t.Errorf("sepolia view = %+v err=%v", sp, err)
	}

	ep, err := cfg.ShowEndpoint("mainnet-public")
	if err != nil {
		t.Fatalf("ShowEndpoint mainnet-public: %v", err)
	}
	if ep.Network != "mainnet" || !ep.PublicDefault || !ep.Default {
		t.Errorf("mainnet-public view = %+v", ep)
	}
	if ep.URL != "https://ethereum-rpc.publicnode.com" {
		t.Errorf("mainnet-public url = %q", ep.URL)
	}
}

// TestShowUnknownNetwork: ref.not_found for an unknown network.
func TestShowUnknownNetwork(t *testing.T) {
	dir, _ := newCfgDir(t)
	cfg := loadCfg(t, dir)
	_, err := cfg.ShowNetwork("nope")
	assertCode(t, err, domain.CodeRefNotFound)
}

// TestAddNetwork: a user network round-trips through Load with builtin=false; the
// --rpc-url convenience also creates the <name>-default endpoint + default-rpc.
func TestAddNetwork(t *testing.T) {
	dir, p := newCfgDir(t)
	n := Network{ChainID: 8453, NativeSymbol: "ETH"}
	if err := AddNetwork(p, "base", n, "https://mainnet.base.org"); err != nil {
		t.Fatalf("AddNetwork: %v", err)
	}
	cfg := loadCfg(t, dir)
	v, err := cfg.ShowNetwork("base")
	if err != nil {
		t.Fatalf("ShowNetwork base: %v", err)
	}
	if v.ChainID != 8453 || v.Builtin {
		t.Errorf("base view = %+v", v)
	}
	if v.DefaultRPC != "base-default" {
		t.Errorf("base default-rpc = %q, want base-default", v.DefaultRPC)
	}
	ep, err := cfg.ShowEndpoint("base-default")
	if err != nil {
		t.Fatalf("ShowEndpoint base-default: %v", err)
	}
	if ep.Network != "base" || ep.URL != "https://mainnet.base.org" {
		t.Errorf("base-default view = %+v", ep)
	}
}

// TestAddNetworkRejectsZeroChainID and bad name.
func TestAddNetworkValidation(t *testing.T) {
	dir, p := newCfgDir(t)
	if err := AddNetwork(p, "zero", Network{ChainID: 0}, ""); err == nil {
		t.Error("expected error on zero chain-id")
	}
	if err := AddNetwork(p, "Bad Name", Network{ChainID: 5}, ""); err == nil {
		t.Error("expected error on invalid name")
	}
	if err := AddNetwork(p, "mainnet", Network{ChainID: 1}, ""); err == nil {
		t.Error("expected network_exists on a built-in name")
	} else {
		assertCode(t, err, domain.CodeUsageNetworkExists)
	}
	// Add then re-add → network_exists.
	if err := AddNetwork(p, "base", Network{ChainID: 8453}, ""); err != nil {
		t.Fatal(err)
	}
	err := AddNetwork(p, "base", Network{ChainID: 8453}, "")
	assertCode(t, err, domain.CodeUsageNetworkExists)
	_ = loadCfg(t, dir)
}

// TestUseNetwork sets defaults.network; unknown → ref.not_found.
func TestUseNetwork(t *testing.T) {
	dir, p := newCfgDir(t)
	known := map[string]bool{"mainnet": true, "sepolia": true}
	if err := UseNetwork(p, "sepolia", known); err != nil {
		t.Fatalf("UseNetwork: %v", err)
	}
	cfg := loadCfg(t, dir)
	if cfg.Defaults.Network != "sepolia" {
		t.Errorf("defaults.network = %q, want sepolia", cfg.Defaults.Network)
	}
	v, _ := cfg.ShowNetwork("sepolia")
	if !v.Default {
		t.Error("sepolia should be marked default after use")
	}
	err := UseNetwork(p, "ghost", known)
	assertCode(t, err, domain.CodeRefNotFound)
}

// TestRemoveNetwork: refuses built-in, refuses referenced w/o force, removes user
// network and clears defaults.network if it pointed there.
func TestRemoveNetwork(t *testing.T) {
	dir, p := newCfgDir(t)
	// built-in → builtin_immutable
	err := RemoveNetwork(p, "mainnet", false, nil)
	assertCode(t, err, domain.CodeUsageBuiltinImmutable)

	// add a user network + an endpoint referencing it + make it default
	if err := AddNetwork(p, "base", Network{ChainID: 8453}, ""); err != nil {
		t.Fatal(err)
	}
	if err := UseNetwork(p, "base", map[string]bool{"base": true}); err != nil {
		t.Fatal(err)
	}
	// referenced w/o force → network_in_use
	err = RemoveNetwork(p, "base", false, []string{"base-rpc"})
	assertCode(t, err, domain.CodeUsageNetworkInUse)

	// force removes it AND clears defaults.network
	if err := RemoveNetwork(p, "base", true, []string{"base-rpc"}); err != nil {
		t.Fatalf("RemoveNetwork force: %v", err)
	}
	cfg := loadCfg(t, dir)
	if _, err := cfg.ShowNetwork("base"); err == nil {
		t.Error("base should be gone after force remove")
	}
	// defaults.network cleared → falls back to built-in mainnet on load
	if cfg.Defaults.Network != "mainnet" {
		t.Errorf("defaults.network after remove = %q, want mainnet (fallback)", cfg.Defaults.Network)
	}
}

// TestRemoveUnknownNetwork → ref.not_found.
func TestRemoveUnknownNetwork(t *testing.T) {
	_, p := newCfgDir(t)
	err := RemoveNetwork(p, "ghost", false, nil)
	assertCode(t, err, domain.CodeRefNotFound)
}

// TestNetworkUseReadOnly: a read-only mount maps to config.read_only (§2.11).
func TestNetworkUseReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based read-only simulation is POSIX-only")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("schema = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, _ := ResolvePaths(FlagValues{Config: dir})

	err := UseNetwork(p, "sepolia", map[string]bool{"sepolia": true})
	assertReadOnly(t, err)
}

// assertReadOnly asserts the canonical config.read_only/exit-10 error.
func assertReadOnly(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected config.read_only, got nil")
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("not a domain error: %v", err)
	}
	if de.Code != domain.CodeConfigReadOnly || de.Exit != domain.ExitNotFound {
		t.Errorf("got code=%q exit=%d, want config.read_only/10", de.Code, de.Exit)
	}
}
