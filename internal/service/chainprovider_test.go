package service

import (
	"context"
	"errors"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
)

// providerTestConfig builds a merged *config.Config the way Load would, with the
// built-in mainnet/sepolia presets plus a couple of user endpoints carrying secret
// references, headers and TLS paths — enough to exercise every resolution branch
// without touching disk.
func providerTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	withProviderEnv(t, dir)
	// Add user endpoints + a user network through the real config mutators so the
	// merged Config matches production exactly.
	p, err := config.ResolvePaths(config.FlagValues{Config: dir})
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	knownMain := map[string]bool{"mainnet": true, "sepolia": true}
	if _, err := config.AddEndpoint(p, "mainnet-keyed",
		config.Endpoint{Network: "mainnet", URLRef: "https://eth.example/v2/${env:DAXIE_TEST_KEY}",
			Headers: map[string]string{"Authorization": "Bearer ${env:DAXIE_TEST_TOKEN}"}},
		knownMain, false); err != nil {
		t.Fatalf("AddEndpoint keyed: %v", err)
	}
	if _, err := config.AddEndpoint(p, "mainnet-tls",
		config.Endpoint{Network: "mainnet", URLRef: "https://eth.internal:8545",
			TLS: &config.TLSFiles{Cert: "/c.crt", Key: "/c.key", CA: "/ca.pem"}},
		knownMain, false); err != nil {
		t.Fatalf("AddEndpoint tls: %v", err)
	}
	cfg, _, err := config.Load(config.FlagValues{Config: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// withProviderEnv points config path resolution at dir and clears the test secret
// vars by default (individual tests set them).
func withProviderEnv(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DAXIE_CONFIG", dir)
}

// captureDial records the Options it was dialed with and returns a fresh fake.
func captureDial(seen *chain.Options, cid uint64) dialFunc {
	return func(ctx context.Context, opts chain.Options) (chain.Client, error) {
		*seen = opts
		f := fake.New()
		f.ChainIDVal.SetUint64(cid)
		return f, nil
	}
}

// TestProviderDefaultSelection: no override → defaults.network (mainnet) → its
// default-rpc (mainnet-public), with the built-in public URL and chain-id 1.
func TestProviderDefaultSelection(t *testing.T) {
	cfg := providerTestConfig(t)
	var seen chain.Options
	d := &dialingProvider{cfg: cfg, dial: captureDial(&seen, 1)}

	cc, err := d.ClientFor(context.Background(), ChainRequest{})
	if err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	defer cc.Close()
	if seen.Network != "mainnet" {
		t.Errorf("network = %q, want mainnet", seen.Network)
	}
	if seen.URL != "https://ethereum-rpc.publicnode.com" {
		t.Errorf("url = %q, want the public default", seen.URL)
	}
	if seen.ExpectChainID == nil || seen.ExpectChainID.Uint64() != 1 {
		t.Errorf("ExpectChainID = %v, want 1", seen.ExpectChainID)
	}
}

// TestProviderRPCOverridePrecedence: a request --rpc beats the process default RPC
// which beats the network default-rpc.
func TestProviderRPCOverridePrecedence(t *testing.T) {
	cfg := providerTestConfig(t)
	t.Setenv("DAXIE_TEST_KEY", "live-key")
	t.Setenv("DAXIE_TEST_TOKEN", "live-token")

	var seen chain.Options
	// process default RPC is mainnet-public; request override is mainnet-keyed.
	d := &dialingProvider{cfg: cfg, defaultRPC: "mainnet-public", dial: captureDial(&seen, 1)}
	cc, err := d.ClientFor(context.Background(), ChainRequest{RPC: "mainnet-keyed"})
	if err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	defer cc.Close()
	// the request override wins
	if seen.URL != "https://eth.example/v2/live-key" {
		t.Errorf("url = %q, want the keyed endpoint with the resolved secret", seen.URL)
	}
}

// TestProviderSecretRefResolvedNotPersisted: the URL/header secret references are
// resolved IN-MEMORY into the dialed Options, but the stored config keeps the RAW
// reference (never the resolved value).
func TestProviderSecretRefResolvedNotPersisted(t *testing.T) {
	cfg := providerTestConfig(t)
	t.Setenv("DAXIE_TEST_KEY", "s3cr3t-key")
	t.Setenv("DAXIE_TEST_TOKEN", "s3cr3t-token")

	var seen chain.Options
	d := &dialingProvider{cfg: cfg, dial: captureDial(&seen, 1)}
	cc, err := d.ClientFor(context.Background(), ChainRequest{RPC: "mainnet-keyed"})
	if err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	defer cc.Close()

	// Resolved into the dialed Options.
	if seen.URL != "https://eth.example/v2/s3cr3t-key" {
		t.Errorf("url not resolved in-memory: %q", seen.URL)
	}
	if got := seen.Headers["Authorization"]; got != "Bearer s3cr3t-token" {
		t.Errorf("header not resolved in-memory: %q", got)
	}
	// The stored config still holds the RAW reference, NOT the resolved secret.
	stored := cfg.RPC["mainnet-keyed"]
	if stored.URLRef != "https://eth.example/v2/${env:DAXIE_TEST_KEY}" {
		t.Errorf("config URL was mutated to a resolved value: %q", stored.URLRef)
	}
	if stored.Headers["Authorization"] != "Bearer ${env:DAXIE_TEST_TOKEN}" {
		t.Errorf("config header was mutated to a resolved value: %q", stored.Headers["Authorization"])
	}
}

// TestProviderSecretRefUnresolved: a missing env var surfaces secret.unresolved
// (exit 2) and NEVER dials.
func TestProviderSecretRefUnresolved(t *testing.T) {
	cfg := providerTestConfig(t)
	// DAXIE_TEST_KEY deliberately unset.
	dialed := false
	d := &dialingProvider{cfg: cfg, dial: func(ctx context.Context, opts chain.Options) (chain.Client, error) {
		dialed = true
		return fake.New(), nil
	}}
	_, err := d.ClientFor(context.Background(), ChainRequest{RPC: "mainnet-keyed"})
	assertSvcCode(t, err, domain.CodeSecretUnresolved)
	if dialed {
		t.Error("must NOT dial when a secret reference is unresolved")
	}
}

// TestProviderTLSPathsWired: the mTLS cert/key/ca PATHS pass through to Options
// unchanged (they are paths, not secret refs).
func TestProviderTLSPathsWired(t *testing.T) {
	cfg := providerTestConfig(t)
	var seen chain.Options
	d := &dialingProvider{cfg: cfg, dial: captureDial(&seen, 1)}
	cc, err := d.ClientFor(context.Background(), ChainRequest{RPC: "mainnet-tls"})
	if err != nil {
		t.Fatalf("ClientFor: %v", err)
	}
	defer cc.Close()
	if seen.TLSCert != "/c.crt" || seen.TLSKey != "/c.key" || seen.TLSCA != "/ca.pem" {
		t.Errorf("tls paths not wired: cert=%q key=%q ca=%q", seen.TLSCert, seen.TLSKey, seen.TLSCA)
	}
}

// TestProviderUnknownNetwork → ref.not_found, never dials.
func TestProviderUnknownNetwork(t *testing.T) {
	cfg := providerTestConfig(t)
	d := &dialingProvider{cfg: cfg, dial: captureDial(new(chain.Options), 1)}
	_, err := d.ClientFor(context.Background(), ChainRequest{Network: "ghost"})
	assertSvcCode(t, err, domain.CodeRefNotFound)
}

// TestProviderUnknownEndpoint → ref.not_found.
func TestProviderUnknownEndpoint(t *testing.T) {
	cfg := providerTestConfig(t)
	d := &dialingProvider{cfg: cfg, dial: captureDial(new(chain.Options), 1)}
	_, err := d.ClientFor(context.Background(), ChainRequest{RPC: "no-such-endpoint"})
	assertSvcCode(t, err, domain.CodeRefNotFound)
}

// TestProviderRPCNamesNetwork: --rpc naming a NETWORK (strict separation) →
// ref.not_found (an endpoint, not a network, is expected here).
func TestProviderRPCNamesNetwork(t *testing.T) {
	cfg := providerTestConfig(t)
	d := &dialingProvider{cfg: cfg, dial: captureDial(new(chain.Options), 1)}
	_, err := d.ClientFor(context.Background(), ChainRequest{RPC: "mainnet"})
	assertSvcCode(t, err, domain.CodeRefNotFound)
}

// TestProviderEndpointNetworkMismatch: an endpoint bound to a DIFFERENT network
// than the selected one → usage.rpc_network_mismatch (never a silent cross-chain
// read).
func TestProviderEndpointNetworkMismatch(t *testing.T) {
	cfg := providerTestConfig(t)
	d := &dialingProvider{cfg: cfg, dial: captureDial(new(chain.Options), 1)}
	// select sepolia but force a mainnet endpoint.
	_, err := d.ClientFor(context.Background(), ChainRequest{Network: "sepolia", RPC: "mainnet-public"})
	assertSvcCode(t, err, domain.CodeUsageRPCNetworkMismatch)
}

// TestProviderNetworkWithoutDefaultEndpoint: a network whose default-rpc is empty
// and no --rpc given → ref.not_found with the add-an-endpoint hint.
func TestProviderNetworkWithoutDefaultEndpoint(t *testing.T) {
	dir := t.TempDir()
	withProviderEnv(t, dir)
	p, _ := config.ResolvePaths(config.FlagValues{Config: dir})
	// A user network with NO default-rpc and no endpoints.
	if err := config.AddNetwork(p, "base", config.Network{ChainID: 8453}, ""); err != nil {
		t.Fatalf("AddNetwork: %v", err)
	}
	cfg, _, err := config.Load(config.FlagValues{Config: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d := &dialingProvider{cfg: cfg, dial: captureDial(new(chain.Options), 8453)}
	_, err = d.ClientFor(context.Background(), ChainRequest{Network: "base"})
	assertSvcCode(t, err, domain.CodeRefNotFound)
}

// TestProviderDialErrorPropagates: a dial error (chain-id mismatch / unreachable)
// from chain.Dial flows straight through.
func TestProviderDialErrorPropagates(t *testing.T) {
	cfg := providerTestConfig(t)
	want := domain.New(domain.CodeRPCChainIDMismatch, "boom")
	d := &dialingProvider{cfg: cfg, dial: func(ctx context.Context, opts chain.Options) (chain.Client, error) {
		return nil, want
	}}
	_, err := d.ClientFor(context.Background(), ChainRequest{})
	assertSvcCode(t, err, domain.CodeRPCChainIDMismatch)
}

// TestNewDialingProviderUsesChainDial: the production constructor wires chain.Dial
// (not a test stub) and captures the per-process defaults.
func TestNewDialingProviderUsesChainDial(t *testing.T) {
	cfg := providerTestConfig(t)
	d := newDialingProvider(cfg, "sepolia", "sepolia-public")
	if d.defaultNetwork != "sepolia" || d.defaultRPC != "sepolia-public" {
		t.Errorf("defaults not captured: %q / %q", d.defaultNetwork, d.defaultRPC)
	}
	if d.dial == nil {
		t.Error("dial must be wired to chain.Dial")
	}
}

// assertSvcCode asserts err carries the given domain code (service-package local).
func assertSvcCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", want)
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("not a domain error: %T %v", err, err)
	}
	if de.Code != want {
		t.Errorf("code = %q, want %q (err: %v)", de.Code, want, err)
	}
}
