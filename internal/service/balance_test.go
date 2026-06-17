package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// stubProvider is a ChainProvider that always returns the same fake client (or a
// dial error), recording the request it was asked for. It is the test seam that
// lets a use case run without a network.
type stubProvider struct {
	cc      chain.Client
	err     error
	lastReq ChainRequest

	// verifyErr is returned by VerifyEndpoint (nil = the add-time guard passes);
	// verifyNet/verifyEP record what RPCAdd verified.
	verifyErr error
	verifyNet string
	verifyEP  config.Endpoint
}

func (s *stubProvider) ClientFor(ctx context.Context, req ChainRequest) (chain.Client, error) {
	s.lastReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.cc, nil
}

func (s *stubProvider) VerifyEndpoint(ctx context.Context, netName string, ep config.Endpoint) error {
	s.verifyNet = netName
	s.verifyEP = ep
	return s.verifyErr
}

// openWithProvider opens an env-isolated service and swaps in a stub chain
// provider so the chain-touching use cases run against a fake.
func openWithProvider(t *testing.T, prov ChainProvider) *Service {
	t.Helper()
	isolate(t)
	svc, err := Open(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	svc.chains = prov
	return svc
}

func TestBalance_RawAddress(t *testing.T) {
	addr := common.HexToAddress("0x52908400098527886E0F7030069857D2E4169EE7")
	f := fake.New()
	f.Balances[addr] = big.NewInt(1_500_000_000_000_000_000) // 1.5 ETH
	svc := openWithProvider(t, &stubProvider{cc: f})

	res, err := svc.Balance(context.Background(), domain.LocalCLI(),
		domain.BalanceRequest{Account: addr.Hex()}, nil)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if res.Wei != "1500000000000000000" {
		t.Errorf("Wei = %q, want 1500000000000000000", res.Wei)
	}
	if res.Eth != "1.5" {
		t.Errorf("Eth = %q, want 1.5", res.Eth)
	}
	if res.Symbol != "ETH" {
		t.Errorf("Symbol = %q, want ETH", res.Symbol)
	}
	if res.Address != addr.Hex() {
		t.Errorf("Address = %q, want %q", res.Address, addr.Hex())
	}
	// A raw address ref must NOT echo the Account field (it is not a keystore ref).
	if res.Account != "" {
		t.Errorf("Account = %q, want empty for a raw address", res.Account)
	}
	// The fake must have been asked for the latest block (nil).
	calls := f.CallsFor("Balance")
	if len(calls) != 1 {
		t.Fatalf("Balance calls = %d, want 1", len(calls))
	}
	if blk := calls[0].Args[1]; blk != (*big.Int)(nil) {
		t.Errorf("Balance block arg = %v, want nil (latest)", blk)
	}
	// The provider closes the client.
	if len(f.CallsFor("Close")) == 0 {
		t.Error("client was not Closed")
	}
}

func TestBalance_ZeroForUnknownAddress(t *testing.T) {
	f := fake.New() // empty balances map => zero
	svc := openWithProvider(t, &stubProvider{cc: f})
	res, err := svc.Balance(context.Background(), domain.LocalCLI(),
		domain.BalanceRequest{Account: "0x000000000000000000000000000000000000dEaD"}, nil)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if res.Wei != "0" || res.Eth != "0" {
		t.Errorf("zero balance = wei %q eth %q, want 0/0", res.Wei, res.Eth)
	}
}

func TestBalance_TokenRejectedM5(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: fake.New()})
	_, err := svc.Balance(context.Background(), domain.LocalCLI(),
		domain.BalanceRequest{Account: "0x000000000000000000000000000000000000dEaD", Token: "USDC"}, nil)
	assertCode(t, err, domain.CodeUsageUnsupported)
}

func TestBalance_AllRejectedM5(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: fake.New()})
	_, err := svc.Balance(context.Background(), domain.LocalCLI(),
		domain.BalanceRequest{Account: "0x000000000000000000000000000000000000dEaD", All: true}, nil)
	assertCode(t, err, domain.CodeUsageUnsupported)
}

func TestBalance_ENSRejectedM7(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: fake.New()})
	_, err := svc.Balance(context.Background(), domain.LocalCLI(),
		domain.BalanceRequest{Account: "vitalik.eth"}, nil)
	assertCode(t, err, domain.CodeUsageUnsupported)
}

func TestBalance_NoAccountNoDefault(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: fake.New()})
	_, err := svc.Balance(context.Background(), domain.LocalCLI(), domain.BalanceRequest{}, nil)
	de := domain.AsError(err)
	if de.Exit != domain.ExitUsage {
		t.Fatalf("exit = %d, want %d (USAGE)", de.Exit, domain.ExitUsage)
	}
}

func TestBalance_NetworkUnreachable(t *testing.T) {
	// A dial failure from the provider funnels through unchanged (rpc.unreachable).
	svc := openWithProvider(t, &stubProvider{err: domain.New(domain.CodeRPCUnreachable, "down")})
	_, err := svc.Balance(context.Background(), domain.LocalCLI(),
		domain.BalanceRequest{Account: "0x000000000000000000000000000000000000dEaD"}, nil)
	de := domain.AsError(err)
	if de.Exit != domain.ExitNetwork {
		t.Fatalf("exit = %d, want %d (NETWORK)", de.Exit, domain.ExitNetwork)
	}
}

// assertCode fails unless err carries the given domain code.
func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %q, got nil", code)
	}
	de := domain.AsError(err)
	if de.Code != code {
		t.Fatalf("error code = %q, want %q", de.Code, code)
	}
}
