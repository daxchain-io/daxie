package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
)

// noVerifyChains swaps in a stub ChainProvider whose VerifyEndpoint is a no-op, so
// an RPCAdd unit test exercises the config write + the add-time guard wiring
// without making a real network dial (the §rpc add chain-ID verification is
// covered against anvil in balance_integration_test.go). Returns svc for chaining.
func noVerifyChains(svc *Service) *Service {
	svc.chains = &stubProvider{cc: fake.New()}
	return svc
}

func TestRPCList_BuiltinPublic(t *testing.T) {
	svc := openMutable(t)
	res, err := svc.RPCList(context.Background(), domain.LocalCLI(), domain.RPCListRequest{})
	if err != nil {
		t.Fatalf("RPCList: %v", err)
	}
	var sawMainnetPublic bool
	for _, e := range res.RPCs {
		if e.Name == "mainnet-public" {
			sawMainnetPublic = true
			if e.Network != "mainnet" {
				t.Errorf("mainnet-public network = %q, want mainnet", e.Network)
			}
			if !e.PublicDefault {
				t.Error("mainnet-public not marked public-default")
			}
			if !e.Default {
				t.Error("mainnet-public should be mainnet's default endpoint")
			}
		}
	}
	if !sawMainnetPublic {
		t.Fatal("built-in mainnet-public endpoint missing")
	}
}

func TestRPCList_FilterByNetwork(t *testing.T) {
	svc := openMutable(t)
	res, err := svc.RPCList(context.Background(), domain.LocalCLI(), domain.RPCListRequest{Network: "sepolia"})
	if err != nil {
		t.Fatalf("RPCList(sepolia): %v", err)
	}
	for _, e := range res.RPCs {
		if e.Network != "sepolia" {
			t.Errorf("filtered list contains %q on network %q, want sepolia only", e.Name, e.Network)
		}
	}
}

func TestRPCAdd_ThenShowMasked(t *testing.T) {
	svc := noVerifyChains(openMutable(t))
	_, err := svc.RPCAdd(context.Background(), domain.LocalCLI(), domain.RPCAddRequest{
		Name:    "mainnet-alchemy",
		Network: "mainnet",
		URL:     "https://eth-mainnet.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}",
	})
	if err != nil {
		t.Fatalf("RPCAdd: %v", err)
	}
	svc2 := openSameDir(t)
	res, err := svc2.RPCShow(context.Background(), domain.LocalCLI(), domain.RPCShowRequest{Name: "mainnet-alchemy"})
	if err != nil {
		t.Fatalf("RPCShow: %v", err)
	}
	// The secret reference is shown as the REFERENCE (not resolved, not stripped).
	if res.RPC.URL != "https://eth-mainnet.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}" {
		t.Errorf("masked URL = %q, want the ${env:} reference preserved", res.RPC.URL)
	}
}

func TestRPCAdd_LiteralSecretWarns(t *testing.T) {
	svc := noVerifyChains(openMutable(t))
	res, err := svc.RPCAdd(context.Background(), domain.LocalCLI(), domain.RPCAddRequest{
		Name:    "leaky",
		Network: "mainnet",
		URL:     "https://eth.example.com/v2/abcdef0123456789abcdef0123456789",
	})
	if err != nil {
		t.Fatalf("RPCAdd(literal, non-strict): unexpected error: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a literal-secret warning, got none")
	}
}

func TestRPCAdd_LiteralSecretStrictRejected(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.RPCAdd(context.Background(), domain.LocalCLI(), domain.RPCAddRequest{
		Name:          "leaky",
		Network:       "mainnet",
		URL:           "https://eth.example.com/v2/abcdef0123456789abcdef0123456789",
		StrictSecrets: true,
	})
	assertCode(t, err, domain.CodeUsageLiteralSecret)
}

func TestRPCAdd_UnknownNetworkRejected(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.RPCAdd(context.Background(), domain.LocalCLI(), domain.RPCAddRequest{
		Name: "x", Network: "nope", URL: "https://x.example.com",
	})
	de := domain.AsError(err)
	if de.Exit != domain.ExitNotFound {
		t.Fatalf("exit = %d, want %d (NOT_FOUND)", de.Exit, domain.ExitNotFound)
	}
}

func TestRPCAdd_DuplicateRejected(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.RPCAdd(context.Background(), domain.LocalCLI(), domain.RPCAddRequest{
		Name: "mainnet-public", Network: "mainnet", URL: "https://x.example.com",
	})
	assertCode(t, err, domain.CodeUsageRPCExists)
}

func TestRPCUse_SetsNetworkDefault(t *testing.T) {
	svc := noVerifyChains(openMutable(t))
	if _, err := svc.RPCAdd(context.Background(), domain.LocalCLI(), domain.RPCAddRequest{
		Name: "mainnet-alt", Network: "mainnet", URL: "https://alt.example.com",
	}); err != nil {
		t.Fatalf("RPCAdd: %v", err)
	}
	svc2 := openSameDir(t)
	if _, err := svc2.RPCUse(context.Background(), domain.LocalCLI(), domain.RPCUseRequest{Name: "mainnet-alt"}); err != nil {
		t.Fatalf("RPCUse: %v", err)
	}
	svc3 := openSameDir(t)
	n, err := svc3.NetworkShow(context.Background(), domain.LocalCLI(), domain.NetworkShowRequest{Name: "mainnet"})
	if err != nil {
		t.Fatalf("NetworkShow: %v", err)
	}
	if n.Network.DefaultRPC != "mainnet-alt" {
		t.Errorf("mainnet default-rpc = %q, want mainnet-alt", n.Network.DefaultRPC)
	}
}

func TestRPCUse_UnknownRejected(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.RPCUse(context.Background(), domain.LocalCLI(), domain.RPCUseRequest{Name: "nope"})
	de := domain.AsError(err)
	if de.Exit != domain.ExitNotFound {
		t.Fatalf("exit = %d, want %d (NOT_FOUND)", de.Exit, domain.ExitNotFound)
	}
}

func TestRPCRename_BuiltinRefused(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.RPCRename(context.Background(), domain.LocalCLI(), domain.RPCRenameRequest{Old: "mainnet-public", New: "mainnet-fallback"})
	assertCode(t, err, domain.CodeUsageBuiltinImmutable)
}

func TestRPCRemove_BuiltinRefused(t *testing.T) {
	svc := openMutable(t)
	_, err := svc.RPCRemove(context.Background(), domain.LocalCLI(), domain.RPCRemoveRequest{Name: "sepolia-public"})
	assertCode(t, err, domain.CodeUsageBuiltinImmutable)
}

func TestRPCRemove_UserEndpoint(t *testing.T) {
	svc := noVerifyChains(openMutable(t))
	if _, err := svc.RPCAdd(context.Background(), domain.LocalCLI(), domain.RPCAddRequest{
		Name: "mainnet-alt", Network: "mainnet", URL: "https://alt.example.com",
	}); err != nil {
		t.Fatalf("RPCAdd: %v", err)
	}
	svc2 := openSameDir(t)
	res, err := svc2.RPCRemove(context.Background(), domain.LocalCLI(), domain.RPCRemoveRequest{Name: "mainnet-alt"})
	if err != nil {
		t.Fatalf("RPCRemove: %v", err)
	}
	if !res.Removed {
		t.Error("Removed = false, want true")
	}
}

// TestRPCAdd_VerifiesChainID_AtAddTime proves the add-time guard runs: RPCAdd
// asks the provider to verify the just-written endpoint against its declared
// network (cli-spec §rpc, requirements §6, design §7.5).
func TestRPCAdd_VerifiesChainID_AtAddTime(t *testing.T) {
	svc := openMutable(t)
	stub := &stubProvider{cc: fake.New()}
	svc.chains = stub
	if _, err := svc.RPCAdd(context.Background(), domain.LocalCLI(), domain.RPCAddRequest{
		Name: "mainnet-alt", Network: "mainnet", URL: "https://alt.example.com",
	}); err != nil {
		t.Fatalf("RPCAdd: %v", err)
	}
	if stub.verifyNet != "mainnet" {
		t.Errorf("VerifyEndpoint network = %q, want mainnet", stub.verifyNet)
	}
	if stub.verifyEP.URLRef != "https://alt.example.com" {
		t.Errorf("VerifyEndpoint endpoint URL = %q, want https://alt.example.com", stub.verifyEP.URLRef)
	}
}

// TestRPCAdd_ChainIDMismatch_FailsClosed proves a reachable wrong-chain endpoint
// is REFUSED at add time (rpc.chain_id_mismatch, exit 12) — the security guard.
func TestRPCAdd_ChainIDMismatch_FailsClosed(t *testing.T) {
	svc := openMutable(t)
	svc.chains = &stubProvider{verifyErr: domain.New(domain.CodeRPCChainIDMismatch, "wrong chain")}
	_, err := svc.RPCAdd(context.Background(), domain.LocalCLI(), domain.RPCAddRequest{
		Name: "evil", Network: "mainnet", URL: "https://evil.example.com",
	})
	de := domain.AsError(err)
	if de.Code != domain.CodeRPCChainIDMismatch {
		t.Fatalf("code = %q, want %q", de.Code, domain.CodeRPCChainIDMismatch)
	}
	if de.Exit != domain.ExitIntegrity {
		t.Fatalf("exit = %d, want %d (INTEGRITY)", de.Exit, domain.ExitIntegrity)
	}
}

// TestRPCAdd_OfflineVerify_Downgrades proves a transport/secret-resolution failure
// at add time does NOT fail the add (offline `rpc add` still works) but appends a
// warning so the operator knows verification did not complete.
func TestRPCAdd_OfflineVerify_Downgrades(t *testing.T) {
	svc := openMutable(t)
	svc.chains = &stubProvider{verifyErr: domain.New(domain.CodeRPCUnreachable, "dial tcp: connection refused")}
	res, err := svc.RPCAdd(context.Background(), domain.LocalCLI(), domain.RPCAddRequest{
		Name: "offline", Network: "mainnet", URL: "https://offline.example.com",
	})
	if err != nil {
		t.Fatalf("RPCAdd(offline) should not fail: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected an add-time verification warning, got none")
	}
}

// TestRPCTest_ReportsChainID drives `rpc test` through a stub provider returning a
// fake that reports chain-id 1 — the guard runs inside Dial (the stub stands in
// for a successful guarded dial), and RPCTest reports the verified id + OK.
func TestRPCTest_ReportsChainID(t *testing.T) {
	isolate(t)
	f := fake.New()
	f.ChainIDVal = big.NewInt(1)
	svc := openSameDir(t)
	svc.chains = &stubProvider{cc: f}

	res, err := svc.RPCTest(context.Background(), domain.LocalCLI(), domain.RPCTestRequest{Name: "mainnet-public"})
	if err != nil {
		t.Fatalf("RPCTest: %v", err)
	}
	if !res.OK {
		t.Error("OK = false, want true")
	}
	if res.ChainID != 1 {
		t.Errorf("ChainID = %d, want 1", res.ChainID)
	}
	if res.Network != "mainnet" {
		t.Errorf("Network = %q, want mainnet (the endpoint's network)", res.Network)
	}
}

// TestRPCTest_UnknownEndpoint is ref.not_found before any dial.
func TestRPCTest_UnknownEndpoint(t *testing.T) {
	isolate(t)
	svc := openSameDir(t)
	svc.chains = &stubProvider{cc: fake.New()}
	_, err := svc.RPCTest(context.Background(), domain.LocalCLI(), domain.RPCTestRequest{Name: "nope"})
	de := domain.AsError(err)
	if de.Exit != domain.ExitNotFound {
		t.Fatalf("exit = %d, want %d (NOT_FOUND)", de.Exit, domain.ExitNotFound)
	}
}

// TestRPCTest_MismatchPropagates: the provider returns a chain-id mismatch (as a
// real guarded dial would); RPCTest surfaces it unchanged (exit 12).
func TestRPCTest_MismatchPropagates(t *testing.T) {
	isolate(t)
	svc := openSameDir(t)
	svc.chains = &stubProvider{err: domain.New(domain.CodeRPCChainIDMismatch, "mismatch")}
	_, err := svc.RPCTest(context.Background(), domain.LocalCLI(), domain.RPCTestRequest{Name: "mainnet-public"})
	de := domain.AsError(err)
	if de.Exit != domain.ExitIntegrity {
		t.Fatalf("exit = %d, want %d (INTEGRITY)", de.Exit, domain.ExitIntegrity)
	}
}
