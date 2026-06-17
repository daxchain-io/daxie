package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// balance_token_test.go covers `balance --token` (a single ERC-20 balance) and
// `balance --all` (ETH + every registry token with a nonzero balance).

func TestBalance_Token_Single(t *testing.T) {
	owner := someAddr(0x01)
	contract := someAddr(0x42)
	cc := erc20Fake(6, "TST", big.NewInt(2_500_000), nil) // 2.5 TST at 6 decimals
	svc := openWithProvider(t, &stubProvider{cc: cc})

	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}

	res, err := svc.Balance(context.Background(), domain.LocalCLI(), domain.BalanceRequest{
		Account: owner.Hex(), Token: "tst", Network: "mainnet",
	}, nil)
	if err != nil {
		t.Fatalf("Balance --token: %v", err)
	}
	if res.Token == nil {
		t.Fatal("--token balance result has no Token block")
	}
	if res.Token.Base != "2500000" {
		t.Errorf("token base = %q, want 2500000", res.Token.Base)
	}
	if res.Token.Formatted != "2.5" {
		t.Errorf("token formatted = %q, want 2.5", res.Token.Formatted)
	}
	if res.Token.Alias != "tst" {
		t.Errorf("token alias = %q, want tst", res.Token.Alias)
	}
	// A token-only read carries no ETH value.
	if res.Wei != "" {
		t.Errorf("--token read should not carry an ETH Wei value, got %q", res.Wei)
	}
}

func TestBalance_Token_RawAddress(t *testing.T) {
	owner := someAddr(0x01)
	contract := someAddr(0x55)
	cc := erc20Fake(18, "RAW", big.NewInt(1_000_000_000_000_000_000), nil) // 1.0 at 18 decimals
	svc := openWithProvider(t, &stubProvider{cc: cc})

	res, err := svc.Balance(context.Background(), domain.LocalCLI(), domain.BalanceRequest{
		Account: owner.Hex(), Token: contract.Hex(), Network: "mainnet",
	}, nil)
	if err != nil {
		t.Fatalf("Balance --token raw 0x: %v", err)
	}
	if res.Token == nil || res.Token.Formatted != "1" {
		t.Fatalf("raw-token balance = %+v, want formatted 1", res.Token)
	}
}

func TestBalance_All_OmitsZero(t *testing.T) {
	owner := someAddr(0x01)
	cc := erc20Fake(6, "TST", nil, nil)                        // every token reads zero balance (bal=nil → 0)
	cc.Balances[owner] = big.NewInt(3_000_000_000_000_000_000) // 3 ETH
	svc := openWithProvider(t, &stubProvider{cc: cc})

	res, err := svc.Balance(context.Background(), domain.LocalCLI(), domain.BalanceRequest{
		Account: owner.Hex(), All: true, Network: "mainnet",
	}, nil)
	if err != nil {
		t.Fatalf("Balance --all: %v", err)
	}
	// ETH value present.
	if res.Eth != "3" {
		t.Errorf("--all ETH = %q, want 3", res.Eth)
	}
	// Every bundled major reads zero ⇒ the token list is empty (zeros omitted).
	if len(res.Tokens) != 0 {
		t.Errorf("--all with all-zero token balances must omit them, got %+v", res.Tokens)
	}
}

func TestBalance_All_IncludesNonzero(t *testing.T) {
	owner := someAddr(0x01)
	contract := someAddr(0x42)
	cc := erc20Fake(6, "TST", big.NewInt(7_000_000), nil) // every balanceOf reads 7.0
	cc.Balances[owner] = big.NewInt(1_000_000_000_000_000_000)
	svc := openWithProvider(t, &stubProvider{cc: cc})

	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}

	res, err := svc.Balance(context.Background(), domain.LocalCLI(), domain.BalanceRequest{
		Account: owner.Hex(), All: true, Network: "mainnet",
	}, nil)
	if err != nil {
		t.Fatalf("Balance --all: %v", err)
	}
	// Both bundled majors + the registered token read 7.0 (the fake answers every
	// balanceOf the same) — they all appear, alias-sorted, all nonzero.
	if len(res.Tokens) == 0 {
		t.Fatal("--all with nonzero balances must list them")
	}
	found := false
	for _, tb := range res.Tokens {
		if tb.Alias == "tst" && tb.Formatted == "7" {
			found = true
		}
	}
	if !found {
		t.Errorf("--all missing the registered 'tst' 7.0 balance: %+v", res.Tokens)
	}
}

func TestBalance_TokenAndAll_MutuallyExclusive_AtCLI(t *testing.T) {
	// service does not itself reject --token + --all (the cli guards it); a request
	// with both set takes the --token branch (Token != "" wins the switch). Assert
	// that deterministic precedence so the behavior is pinned.
	owner := someAddr(0x01)
	contract := someAddr(0x42)
	cc := erc20Fake(6, "TST", big.NewInt(1_000_000), nil)
	svc := openWithProvider(t, &stubProvider{cc: cc})
	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}
	res, err := svc.Balance(context.Background(), domain.LocalCLI(), domain.BalanceRequest{
		Account: owner.Hex(), Token: "tst", All: true, Network: "mainnet",
	}, nil)
	if err != nil {
		t.Fatalf("Balance: %v", err)
	}
	if res.Token == nil {
		t.Errorf("--token + --all should take the --token branch")
	}
}
