package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

var allNets = map[string]bool{"mainnet": true, "sepolia": true}

// TestAddEndpoint: a user endpoint round-trips, stays RAW for refs, and is bound
// to its network. Networks and endpoints are separate objects.
func TestAddEndpoint(t *testing.T) {
	dir, p := newCfgDir(t)
	e := Endpoint{
		Network: "mainnet",
		URLRef:  "https://eth-mainnet.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}",
	}
	warn, err := AddEndpoint(p, "mainnet-alchemy", e, allNets, false)
	if err != nil {
		t.Fatalf("AddEndpoint: %v", err)
	}
	if len(warn) != 0 {
		t.Errorf("a ${env:} ref must not warn: %v", warn)
	}
	cfg := loadCfg(t, dir)
	// RAW ref preserved in the stored config (not resolved, §7.5).
	got := cfg.RPC["mainnet-alchemy"]
	if got.URLRef != e.URLRef {
		t.Errorf("stored url = %q, want RAW ref %q", got.URLRef, e.URLRef)
	}
	// Show masks but keeps the reference visible.
	v, _ := cfg.ShowEndpoint("mainnet-alchemy")
	if v.URL != e.URLRef {
		t.Errorf("masked url dropped the reference: %q", v.URL)
	}
}

// TestAddEndpointValidation: bad name, missing network/url, unknown network,
// collision.
func TestAddEndpointValidation(t *testing.T) {
	_, p := newCfgDir(t)
	if _, err := AddEndpoint(p, "Bad Name", Endpoint{Network: "mainnet", URLRef: "https://x"}, allNets, false); err == nil {
		t.Error("expected invalid-name error")
	}
	if _, err := AddEndpoint(p, "e1", Endpoint{URLRef: "https://x"}, allNets, false); err == nil {
		t.Error("expected missing-network error")
	}
	if _, err := AddEndpoint(p, "e2", Endpoint{Network: "ghost", URLRef: "https://x"}, allNets, false); err == nil {
		t.Error("expected unknown-network error")
	} else {
		assertCode(t, err, domain.CodeRefNotFound)
	}
	if _, err := AddEndpoint(p, "e3", Endpoint{Network: "mainnet"}, allNets, false); err == nil {
		t.Error("expected missing-url error")
	}
	// collide with a built-in endpoint
	if _, err := AddEndpoint(p, "mainnet-public", Endpoint{Network: "mainnet", URLRef: "https://x"}, allNets, false); err == nil {
		t.Error("expected rpc_exists on built-in name")
	} else {
		assertCode(t, err, domain.CodeUsageRPCExists)
	}
}

// TestAddEndpointHeadersAndTLS round-trips header + mTLS path fields.
func TestAddEndpointHeadersAndTLS(t *testing.T) {
	dir, p := newCfgDir(t)
	e := Endpoint{
		Network: "mainnet",
		URLRef:  "https://eth.internal.corp:8545",
		Headers: map[string]string{"Authorization": "Bearer ${file:~/jwt}"},
		TLS:     &TLSFiles{Cert: "/c.crt", Key: "/c.key", CA: "/ca.pem"},
	}
	if _, err := AddEndpoint(p, "corp-node", e, allNets, false); err != nil {
		t.Fatalf("AddEndpoint: %v", err)
	}
	cfg := loadCfg(t, dir)
	got := cfg.RPC["corp-node"]
	if got.Headers["Authorization"] != "Bearer ${file:~/jwt}" {
		t.Errorf("header ref not stored RAW: %q", got.Headers["Authorization"])
	}
	if got.TLS == nil || got.TLS.Cert != "/c.crt" || got.TLS.Key != "/c.key" || got.TLS.CA != "/ca.pem" {
		t.Errorf("tls paths not stored: %+v", got.TLS)
	}
	v, _ := cfg.ShowEndpoint("corp-node")
	if !v.HasHeaders || !v.HasTLS {
		t.Errorf("show should report headers+tls present: %+v", v)
	}
}

// TestAddEndpointLiteralSecretWarns: a literal key in the URL warns by default and
// hard-fails under strict.
func TestAddEndpointLiteralSecretWarns(t *testing.T) {
	_, p := newCfgDir(t)
	lit := "https://eth-mainnet.g.alchemy.com/v2/abcd1234EFGH5678ijkl9012mnop"
	warn, err := AddEndpoint(p, "lit1", Endpoint{Network: "mainnet", URLRef: lit}, allNets, false)
	if err != nil {
		t.Fatalf("non-strict should warn, not fail: %v", err)
	}
	if len(warn) == 0 {
		t.Error("expected a literal-secret warning")
	}

	_, p2 := newCfgDir(t)
	_, err = AddEndpoint(p2, "lit2", Endpoint{Network: "mainnet", URLRef: lit}, allNets, true)
	assertCode(t, err, domain.CodeUsageLiteralSecret)
}

// TestUseEndpoint sets the network's default-rpc to the endpoint.
func TestUseEndpoint(t *testing.T) {
	dir, p := newCfgDir(t)
	if _, err := AddEndpoint(p, "mainnet-alt", Endpoint{Network: "mainnet", URLRef: "https://eth.llamarpc.com"}, allNets, false); err != nil {
		t.Fatal(err)
	}
	if err := UseEndpoint(p, "mainnet-alt", "mainnet"); err != nil {
		t.Fatalf("UseEndpoint: %v", err)
	}
	cfg := loadCfg(t, dir)
	mn, _ := cfg.ShowNetwork("mainnet")
	if mn.DefaultRPC != "mainnet-alt" {
		t.Errorf("default-rpc = %q, want mainnet-alt", mn.DefaultRPC)
	}
	v, _ := cfg.ShowEndpoint("mainnet-alt")
	if !v.Default {
		t.Error("mainnet-alt should be marked default")
	}
	// the built-in public endpoint is no longer the default
	pub, _ := cfg.ShowEndpoint("mainnet-public")
	if pub.Default {
		t.Error("mainnet-public should no longer be default")
	}
}

// TestRenameEndpoint: renames + re-points the network default; refuses built-in.
func TestRenameEndpoint(t *testing.T) {
	dir, p := newCfgDir(t)
	if _, err := AddEndpoint(p, "old-name", Endpoint{Network: "mainnet", URLRef: "https://eth.llamarpc.com"}, allNets, false); err != nil {
		t.Fatal(err)
	}
	if err := UseEndpoint(p, "old-name", "mainnet"); err != nil {
		t.Fatal(err)
	}
	if err := RenameEndpoint(p, "old-name", "new-name"); err != nil {
		t.Fatalf("RenameEndpoint: %v", err)
	}
	cfg := loadCfg(t, dir)
	if _, err := cfg.ShowEndpoint("old-name"); err == nil {
		t.Error("old-name should be gone")
	}
	v, err := cfg.ShowEndpoint("new-name")
	if err != nil {
		t.Fatalf("new-name missing: %v", err)
	}
	if v.URL != "https://eth.llamarpc.com" {
		t.Errorf("rename dropped the url: %q", v.URL)
	}
	mn, _ := cfg.ShowNetwork("mainnet")
	if mn.DefaultRPC != "new-name" {
		t.Errorf("default-rpc not re-pointed: %q", mn.DefaultRPC)
	}
	// refuse built-in
	err = RenameEndpoint(p, "mainnet-public", "whatever")
	assertCode(t, err, domain.CodeUsageBuiltinImmutable)
	// unknown source
	err = RenameEndpoint(p, "ghost", "x")
	assertCode(t, err, domain.CodeRefNotFound)
}

// TestRemoveEndpoint: removes + clears the network default; refuses built-in.
func TestRemoveEndpoint(t *testing.T) {
	dir, p := newCfgDir(t)
	if _, err := AddEndpoint(p, "doomed", Endpoint{Network: "mainnet", URLRef: "https://eth.llamarpc.com"}, allNets, false); err != nil {
		t.Fatal(err)
	}
	if err := UseEndpoint(p, "doomed", "mainnet"); err != nil {
		t.Fatal(err)
	}
	cleared, err := RemoveEndpoint(p, "doomed")
	if err != nil {
		t.Fatalf("RemoveEndpoint: %v", err)
	}
	if cleared != "mainnet" {
		t.Errorf("cleared default for = %q, want mainnet", cleared)
	}
	cfg := loadCfg(t, dir)
	if _, err := cfg.ShowEndpoint("doomed"); err == nil {
		t.Error("doomed should be gone")
	}
	mn, _ := cfg.ShowNetwork("mainnet")
	if mn.DefaultRPC == "doomed" {
		t.Errorf("default-rpc still points at removed endpoint: %q", mn.DefaultRPC)
	}
	// refuse built-in
	_, err = RemoveEndpoint(p, "mainnet-public")
	assertCode(t, err, domain.CodeUsageBuiltinImmutable)
	// unknown
	_, err = RemoveEndpoint(p, "ghost")
	assertCode(t, err, domain.CodeRefNotFound)
}

// TestListEndpointsFiltered: filtering by network only returns that network's
// endpoints.
func TestListEndpointsFiltered(t *testing.T) {
	dir, p := newCfgDir(t)
	if _, err := AddEndpoint(p, "s1", Endpoint{Network: "sepolia", URLRef: "https://s"}, allNets, false); err != nil {
		t.Fatal(err)
	}
	cfg := loadCfg(t, dir)
	for _, v := range cfg.ListEndpoints("sepolia") {
		if v.Network != "sepolia" {
			t.Errorf("filtered list leaked %q (%s)", v.Name, v.Network)
		}
	}
	// the merged list includes the built-in sepolia-public plus s1
	names := map[string]bool{}
	for _, v := range cfg.ListEndpoints("sepolia") {
		names[v.Name] = true
	}
	if !names["sepolia-public"] || !names["s1"] {
		t.Errorf("filtered list missing expected endpoints: %v", names)
	}
}

// TestRPCAddReadOnly: `rpc add` against a read-only mount maps to config.read_only
// (exit 10), never an opaque permission error (§2.11). The literal-secret check
// runs BEFORE the write, so a clean ref still reaches the read-only write path.
func TestRPCAddReadOnly(t *testing.T) {
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

	_, err := AddEndpoint(p, "ro-ep",
		Endpoint{Network: "mainnet", URLRef: "https://eth.llamarpc.com"}, allNets, false)
	assertReadOnly(t, err)
}

// TestEndpointsReferencing reports endpoints bound to a network.
func TestEndpointsReferencing(t *testing.T) {
	dir, p := newCfgDir(t)
	if err := AddNetwork(p, "base", Network{ChainID: 8453}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := AddEndpoint(p, "base-a", Endpoint{Network: "base", URLRef: "https://a"}, map[string]bool{"base": true}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := AddEndpoint(p, "base-b", Endpoint{Network: "base", URLRef: "https://b"}, map[string]bool{"base": true}, false); err != nil {
		t.Fatal(err)
	}
	cfg := loadCfg(t, dir)
	refs := cfg.EndpointsReferencing("base")
	if len(refs) != 2 || refs[0] != "base-a" || refs[1] != "base-b" {
		t.Errorf("referencing = %v, want [base-a base-b]", refs)
	}
}
