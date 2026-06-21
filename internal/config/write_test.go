package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// setKeyRoundTrip: set a key, then reload and read it back.
func TestSetKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, err := ResolvePaths(FlagValues{Config: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := SetKey(p, "defaults.network", "sepolia"); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	cfg, _, err := Load(FlagValues{Config: dir})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Defaults.Network != "sepolia" {
		t.Errorf("after SetKey, network = %q, want sepolia", cfg.Defaults.Network)
	}
	// Source should now be "file".
	for _, kv := range cfg.ListKeys() {
		if kv.Key == "defaults.network" && kv.Source != "file" {
			t.Errorf("source after set = %q, want file", kv.Source)
		}
	}
}

func TestSetKeyTypedValues(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, _ := ResolvePaths(FlagValues{Config: dir})

	if err := SetKey(p, "tx.wait", "true"); err != nil {
		t.Fatal(err)
	}
	if err := SetKey(p, "gas.limit-multiplier", "1.5"); err != nil {
		t.Fatal(err)
	}
	if err := SetKey(p, "tx.wait-timeout", "5m"); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Load(FlagValues{Config: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Tx.Wait {
		t.Error("tx.wait not persisted")
	}
	if cfg.Gas.LimitMultiplier != 1.5 {
		t.Errorf("gas.limit-multiplier = %v, want 1.5", cfg.Gas.LimitMultiplier)
	}
	if v, _ := cfg.GetKey("tx.wait-timeout"); v != "5m0s" {
		t.Errorf("tx.wait-timeout = %q, want 5m0s", v)
	}
}

func TestSetKeyBadValue(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, _ := ResolvePaths(FlagValues{Config: dir})
	for _, c := range []struct{ key, val string }{
		{"tx.wait", "yesnt"},
		{"gas.limit-multiplier", "abc"},
		{"gas.fee-history-blocks", "1.5"},
		{"tx.wait-timeout", "soon"},
	} {
		if err := SetKey(p, c.key, c.val); err == nil {
			t.Errorf("SetKey(%q,%q) should reject", c.key, c.val)
		}
	}
}

func TestSetKeyOutOfRange(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, _ := ResolvePaths(FlagValues{Config: dir})

	// Values that PARSE fine but are out of range must be rejected at set time
	// with a usage exit — the headline being a non-positive (or sub-floor) poll
	// interval, which would busy-loop the receive/tx-wait loops.
	reject := []struct{ key, val string }{
		{"receive.poll-interval", "0s"},
		{"receive.poll-interval", "-5s"},
		{"receive.poll-interval", "50ms"}, // below the 100ms floor
		{"tx.poll-interval", "0s"},
		{"tx.wait-timeout", "0s"},
		{"tx.lock-timeout", "0s"},
		{"receive.heartbeat-interval", "0s"},
		{"receive.timeout", "-1s"},
		{"gas.limit-multiplier", "0"},
		{"gas.base-fee-multiplier", "-1"},
		{"gas.rbf-bump-percent", "0"},
		{"gas.drift-tolerance", "-0.1"},
		{"gas.fee-history-blocks", "0"},
		{"receive.max-log-range", "0"},
		{"receive.lookback-blocks", "-1"},
	}
	for _, c := range reject {
		err := SetKey(p, c.key, c.val)
		if err == nil {
			t.Errorf("SetKey(%q,%q) should be rejected as out of range", c.key, c.val)
			continue
		}
		var de *domain.Error
		if !asError(err, &de) || de.Exit != domain.ExitUsage {
			t.Errorf("SetKey(%q,%q) error = %v, want usage exit", c.key, c.val, err)
		}
	}

	// Boundary-valid values must still be accepted (including the deliberate
	// zero-means-something cases: receive.timeout 0 = listen forever).
	accept := []struct{ key, val string }{
		{"receive.poll-interval", "100ms"}, // exactly the floor
		{"receive.timeout", "0s"},          // 0 = listen forever
		{"receive.lookback-blocks", "0"},   // 0 lookback is valid
		{"gas.drift-tolerance", "0"},       // 0 tolerance is valid
		{"gas.fee-history-blocks", "1"},
	}
	for _, c := range accept {
		if err := SetKey(p, c.key, c.val); err != nil {
			t.Errorf("SetKey(%q,%q) should be accepted: %v", c.key, c.val, err)
		}
	}
}

func TestSetKeyPolicyRejected(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, _ := ResolvePaths(FlagValues{Config: dir})
	err := SetKey(p, "policy.max-tx", "1")
	if err == nil {
		t.Fatal("policy.* set must be rejected")
	}
	var de *domain.Error
	if !asError(err, &de) {
		t.Fatalf("not a domain error: %v", err)
	}
	if de.Exit != domain.ExitUsage {
		t.Errorf("policy set exit = %d, want 2 (usage)", de.Exit)
	}
}

func TestSetKeyUnknownRejected(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, _ := ResolvePaths(FlagValues{Config: dir})
	err := SetKey(p, "no.such.key", "x")
	assertCode(t, err, domain.CodeRefNotFound)
}

// TestSetKeyPreservesUnknownKeys: a targeted change must not drop the reserved
// [mcp] block or x- keys (§7.4).
func TestSetKeyPreservesUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	body := `
schema = 1
[mcp]
transport = "stdio"
x-future = 42

[networks.base]
chain-id = 8453
`
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, _ := ResolvePaths(FlagValues{Config: dir})
	if err := SetKey(p, "defaults.network", "sepolia"); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := Load(FlagValues{Config: dir})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MCP["transport"] != "stdio" {
		t.Errorf("[mcp] block dropped after set: %+v", cfg.MCP)
	}
	if _, ok := cfg.Networks["base"]; !ok {
		t.Errorf("user network base dropped after set")
	}
	if cfg.Defaults.Network != "sepolia" {
		t.Errorf("the targeted change did not land")
	}
}

// TestSetKeyReadOnly: a read-only config dir maps to config.read_only (exit 10),
// not an opaque permission error (§7.10).
func TestSetKeyReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based read-only simulation is POSIX-only; Windows path tested via fsx")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	dir := t.TempDir()
	// Pre-create the config.toml, then make the dir read-only so the atomic
	// temp+rename cannot create its temp sibling.
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("schema = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, _ := ResolvePaths(FlagValues{Config: dir})
	err := SetKey(p, "defaults.network", "mainnet")
	if err == nil {
		t.Fatal("expected config.read_only on a read-only dir")
	}
	var de *domain.Error
	if !asError(err, &de) {
		t.Fatalf("not a domain error: %v", err)
	}
	if de.Code != domain.CodeConfigReadOnly || de.Exit != domain.ExitNotFound {
		t.Errorf("read-only set: code=%q exit=%d, want config.read_only/10", de.Code, de.Exit)
	}
}

// asError is errors.As specialized for *domain.Error (local helper).
func asError(err error, target **domain.Error) bool {
	return errors.As(err, target)
}
