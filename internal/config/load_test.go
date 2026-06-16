package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
)

// writeConfig writes a config.toml into a temp dir and returns the dir.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadDefaultsWhenFresh(t *testing.T) {
	withEnv(t, map[string]string{"HOME": t.TempDir()})
	// No --config, default file absent: the fresh-install case returns built-ins.
	cfg, _, err := Load(FlagValues{})
	if err != nil {
		t.Fatalf("fresh load should succeed: %v", err)
	}
	if cfg.Defaults.Network != "mainnet" {
		t.Errorf("default network = %q, want mainnet", cfg.Defaults.Network)
	}
	if cfg.Gas.Speed != "normal" {
		t.Errorf("default gas.speed = %q, want normal", cfg.Gas.Speed)
	}
	if cfg.Tx.WaitTimeout != 10*time.Minute {
		t.Errorf("default tx.wait-timeout = %v, want 10m", cfg.Tx.WaitTimeout)
	}
	if _, ok := cfg.Networks["mainnet"]; !ok {
		t.Errorf("built-in mainnet missing")
	}
	if cfg.Networks["mainnet"].ChainID != 1 {
		t.Errorf("mainnet chain-id = %d, want 1", cfg.Networks["mainnet"].ChainID)
	}
}

func TestLoadPrecedence(t *testing.T) {
	dir := writeConfig(t, `
schema = 1
[defaults]
network = "sepolia"
[gas]
speed = "fast"
`)
	// File sets defaults.network=sepolia and gas.speed=fast; env overrides
	// gas.speed; flag overrides defaults.network.
	withEnv(t, map[string]string{
		"HOME":            t.TempDir(),
		"DAXIE_CONFIG":    dir,
		"DAXIE_GAS_SPEED": "slow",
	})
	cfg, _, err := Load(FlagValues{Network: "base"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Defaults.Network != "base" {
		t.Errorf("network = %q, want base (flag wins over file)", cfg.Defaults.Network)
	}
	if cfg.Gas.Speed != "slow" {
		t.Errorf("gas.speed = %q, want slow (env wins over file)", cfg.Gas.Speed)
	}
}

func TestLoadFileOverridesDefault(t *testing.T) {
	dir := writeConfig(t, `
[tx]
wait-timeout = "5m"
[ens]
enabled = false
`)
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	cfg, _, err := Load(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tx.WaitTimeout != 5*time.Minute {
		t.Errorf("tx.wait-timeout = %v, want 5m", cfg.Tx.WaitTimeout)
	}
	if cfg.ENS.Enabled {
		t.Errorf("ens.enabled should be false from file")
	}
	// An unspecified key keeps its built-in default.
	if cfg.Tx.PollInterval != 4*time.Second {
		t.Errorf("tx.poll-interval = %v, want default 4s", cfg.Tx.PollInterval)
	}
}

func TestLoadMissingNamedFile(t *testing.T) {
	withEnv(t, map[string]string{"HOME": t.TempDir()})
	_, _, err := Load(FlagValues{Config: filepath.Join(t.TempDir(), "nope.toml")})
	assertCode(t, err, domain.CodeConfigNotFound)
}

func TestLoadBadType(t *testing.T) {
	dir := writeConfig(t, `
[gas]
fee-history-blocks = "not-an-int"
`)
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	_, _, err := Load(FlagValues{})
	assertCode(t, err, domain.CodeConfigInvalid)
}

func TestLoadBadDuration(t *testing.T) {
	dir := writeConfig(t, `
[tx]
wait-timeout = "not-a-duration"
`)
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	_, _, err := Load(FlagValues{})
	assertCode(t, err, domain.CodeConfigInvalid)
}

func TestLoadSchemaTooNew(t *testing.T) {
	dir := writeConfig(t, "schema = 99\n")
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	_, _, err := Load(FlagValues{})
	assertCode(t, err, domain.CodeConfigSchemaUnsupported)
}

func TestLoadNetworkSparseOverride(t *testing.T) {
	// Override only confirmations on the built-in mainnet; add a new network.
	dir := writeConfig(t, `
[networks.mainnet]
confirmations = 5

[networks.base]
chain-id = 8453
confirmations = 1
default-rpc = "base-default"

[rpc.base-default]
network = "base"
url = "https://mainnet.base.org"
`)
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	cfg, _, err := Load(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	mn := cfg.Networks["mainnet"]
	if mn.Confirmations != 5 {
		t.Errorf("mainnet confirmations = %d, want 5 (overridden)", mn.Confirmations)
	}
	// Sparse: the un-set fields keep the built-in values.
	if mn.ChainID != 1 {
		t.Errorf("mainnet chain-id = %d, want built-in 1", mn.ChainID)
	}
	if mn.DefaultRPC != "mainnet-public" {
		t.Errorf("mainnet default-rpc = %q, want built-in mainnet-public", mn.DefaultRPC)
	}
	if mn.ENSRegistry == [20]byte{} {
		t.Errorf("mainnet ens-registry lost on sparse override")
	}
	// User-added network present.
	base, ok := cfg.Networks["base"]
	if !ok || base.ChainID != 8453 {
		t.Errorf("user network base missing or wrong: %+v", base)
	}
	if ep, ok := cfg.RPC["base-default"]; !ok || ep.URLRef != "https://mainnet.base.org" {
		t.Errorf("user rpc base-default missing or wrong: %+v", ep)
	}
}

func TestLoadEndpointKeepsRawSecretRef(t *testing.T) {
	dir := writeConfig(t, `
[rpc.mainnet-alchemy]
network = "mainnet"
url = "https://eth-mainnet.example/v2/${env:ALCHEMY_API_KEY}"
`)
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir, "ALCHEMY_API_KEY": "should-not-be-resolved"})
	cfg, _, err := Load(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	ep := cfg.RPC["mainnet-alchemy"]
	if ep.URLRef != "https://eth-mainnet.example/v2/${env:ALCHEMY_API_KEY}" {
		t.Errorf("Load must NOT resolve secret refs; got %q", ep.URLRef)
	}
}

func TestLoadMCPPreserved(t *testing.T) {
	dir := writeConfig(t, `
[mcp]
transport = "stdio"
x-future = 42
`)
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	cfg, _, err := Load(FlagValues{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MCP["transport"] != "stdio" {
		t.Errorf("mcp.transport not preserved: %+v", cfg.MCP)
	}
}

// assertCode fails unless err is a *domain.Error with the given code.
func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", code)
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error is %T, want *domain.Error: %v", err, err)
	}
	if de.Code != code {
		t.Fatalf("error code = %q, want %q (msg: %s)", de.Code, code, de.Msg)
	}
}
