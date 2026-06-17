package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// token_test.go pins the human renderers for the M5 token views: the essential
// value prints even under --quiet; provenance + context lines are quiet-suppressed.

func TestTokenInfoEssential(t *testing.T) {
	r := domain.TokenInfoResult{
		Network: "mainnet", Contract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		Kind: "erc20", Symbol: "USDC", Decimals: 6, Registered: true, Alias: "usdc", Bundled: true,
	}
	var quiet bytes.Buffer
	TokenInfo(&quiet, Mode{Quiet: true}, r)
	if !strings.HasPrefix(quiet.String(), r.Contract+"\n") {
		t.Errorf("quiet TokenInfo must still print the contract; got %q", quiet.String())
	}

	var full bytes.Buffer
	TokenInfo(&full, Mode{}, r)
	out := full.String()
	for _, want := range []string{"USDC", "decimals: 6", "usdc", "bundled"} {
		if !strings.Contains(out, want) {
			t.Errorf("TokenInfo missing %q:\n%s", want, out)
		}
	}
}

func TestTokenListProvenance(t *testing.T) {
	r := domain.TokenListResult{Network: "mainnet", Tokens: []domain.TokenRow{
		{Alias: "usdc", Contract: "0xA0b8", Symbol: "USDC", Decimals: 6, Network: "mainnet", Bundled: true},
		{Alias: "mytoken", Contract: "0x4242", Symbol: "MYC", Decimals: 18, Network: "mainnet"},
	}}
	var buf bytes.Buffer
	TokenList(&buf, Mode{}, r)
	out := buf.String()
	if !strings.Contains(out, "bundled") || !strings.Contains(out, "registered") {
		t.Errorf("TokenList must mark provenance (bundled/registered):\n%s", out)
	}
	if !strings.Contains(out, "usdc") || !strings.Contains(out, "mytoken") {
		t.Errorf("TokenList missing rows:\n%s", out)
	}
}

func TestAllowanceUnlimited(t *testing.T) {
	r := domain.AllowanceResult{
		Network: "mainnet", Contract: "0x4242", Symbol: "TST", Decimals: 18,
		Owner: "0x01", Spender: "0x02", Allowance: "115792089237316195423570985008687907853269984665640564039457584007913129639935",
		AllowanceFormatted: "huge", Unlimited: true,
	}
	var buf bytes.Buffer
	Allowance(&buf, Mode{Quiet: true}, r)
	if !strings.HasPrefix(buf.String(), "unlimited") {
		t.Errorf("an unlimited allowance must render 'unlimited' as the headline; got %q", buf.String())
	}
}

func TestBalanceTokenEssential(t *testing.T) {
	r := domain.BalanceResult{
		Address: "0xdEaD", Network: "mainnet",
		Token: &domain.TokenBalance{Alias: "usdc", Contract: "0xA0b8", Symbol: "USDC", Decimals: 6, Base: "2500000", Formatted: "2.5"},
	}
	var quiet bytes.Buffer
	BalanceToken(&quiet, Mode{Quiet: true}, r)
	if !strings.HasPrefix(quiet.String(), "2.5 USDC\n") {
		t.Errorf("quiet BalanceToken must print the formatted balance; got %q", quiet.String())
	}
}

func TestBalanceAllTable(t *testing.T) {
	r := domain.BalanceResult{
		Address: "0xdEaD", Network: "mainnet", Eth: "3", Symbol: "ETH",
		Tokens: []domain.TokenBalance{
			{Alias: "usdc", Symbol: "USDC", Formatted: "100", Contract: "0xA0b8"},
		},
	}
	var buf bytes.Buffer
	BalanceAll(&buf, Mode{}, r)
	out := buf.String()
	if !strings.HasPrefix(out, "3 ETH\n") {
		t.Errorf("BalanceAll headline must be the ETH balance; got %q", out)
	}
	if !strings.Contains(out, "USDC") || !strings.Contains(out, "100") {
		t.Errorf("BalanceAll missing the token row:\n%s", out)
	}
}
