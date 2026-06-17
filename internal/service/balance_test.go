package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ens"
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

// M5: --token now resolves a bundled major (USDC) registry-only and reads its
// balance — no longer the M2 usage.unsupported rejection.
func TestBalance_TokenBundledMajor(t *testing.T) {
	cc := erc20Fake(6, "USDC", big.NewInt(5_000_000), nil) // 5 USDC
	svc := openWithProvider(t, &stubProvider{cc: cc})
	res, err := svc.Balance(context.Background(), domain.LocalCLI(),
		domain.BalanceRequest{Account: "0x000000000000000000000000000000000000dEaD", Token: "USDC", Network: "mainnet"}, nil)
	if err != nil {
		t.Fatalf("Balance --token USDC: %v", err)
	}
	if res.Token == nil || res.Token.Formatted != "5" {
		t.Fatalf("USDC balance = %+v, want formatted 5", res.Token)
	}
}

// M5: --all now reads ETH + every registry token (zeros omitted) — no longer the M2
// usage.unsupported rejection.
func TestBalance_AllReads(t *testing.T) {
	cc := erc20Fake(6, "USDC", nil, nil) // every token reads zero ⇒ omitted
	svc := openWithProvider(t, &stubProvider{cc: cc})
	res, err := svc.Balance(context.Background(), domain.LocalCLI(),
		domain.BalanceRequest{Account: "0x000000000000000000000000000000000000dEaD", All: true, Network: "mainnet"}, nil)
	if err != nil {
		t.Fatalf("Balance --all: %v", err)
	}
	if res.Eth == "" {
		t.Errorf("--all must carry the ETH value")
	}
}

// M7 ACTIVATES read-only ENS: `balance vitalik.eth` resolves the name against the
// connected network (§3.2: ENS is legal wherever a read-only address is). A name with
// no on-chain record resolves to nothing ⇒ ref.not_found (exit 10) — NOT the M6
// usage.unsupported, and NEVER an all-zero address read as a real account.
func TestBalance_ENSUnresolvedIsRefNotFound(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: ensFake(nil, nil)})
	_, err := svc.Balance(context.Background(), domain.LocalCLI(),
		domain.BalanceRequest{Account: "vitalik.eth"}, nil)
	assertCode(t, err, domain.CodeRefNotFound)
}

// A registered ENS name reads the balance of the RESOLVED address.
func TestBalance_ENSResolvedReadsResolvedAddress(t *testing.T) {
	resolved := common.HexToAddress("0x00000000000000000000000000000000000000ab")
	node := ens.Namehash("vitalik.eth")
	cc := ensFake(map[[32]byte]common.Address{node: resolved}, nil)
	cc.Balances = map[common.Address]*big.Int{resolved: big.NewInt(7)}
	svc := openWithProvider(t, &stubProvider{cc: cc})
	res, err := svc.Balance(context.Background(), domain.LocalCLI(),
		domain.BalanceRequest{Account: "vitalik.eth"}, nil)
	if err != nil {
		t.Fatalf("Balance vitalik.eth: %v", err)
	}
	if res.Address != resolved.Hex() {
		t.Fatalf("balance address = %s, want the resolved %s", res.Address, resolved.Hex())
	}
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
