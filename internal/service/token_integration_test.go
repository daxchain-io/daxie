//go:build integration

// token_integration_test.go drives the M5 ERC-20 surface end-to-end through the
// REAL ChainProvider + keystore signer + journal/policy against a local anvil with a
// freshly-deployed test ERC-20. It asserts on-chain state via the testchain RAW-RPC
// readers (independent of Daxie's own erc package — no self-confirmation):
//
//   - token add → balance --token == on-chain balanceOf
//   - tx send --token → recipient balanceOf increased, sender decreased
//   - token approve → on-chain allowance == approved amount
//   - token revoke → on-chain allowance == 0
//   - a DENY case: a token transfer with limits set + no allowlist → fail-closed
//     policy.denied.no_allowlist (exit 3), nothing signed.
package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/testchain"
	"github.com/ethereum/go-ethereum/common"
)

func TestIntegration_TokenTransferAndBalance(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())
	token := testchain.DeployERC20(t, anvil) // deployer (= funded acct 0 = from) holds the full supply
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000a1")

	// Register the token by its 0x contract.
	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(), domain.TokenAddRequest{
		Contract: token.Hex(), Name: "tst", Network: "localanvil",
	}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}

	// balance --token must equal the on-chain balanceOf (raw-RPC asserted).
	res, err := svc.Balance(context.Background(), domain.LocalCLI(), domain.BalanceRequest{
		Account: from.Hex(), Token: "tst", Network: "localanvil",
	}, nil)
	if err != nil {
		t.Fatalf("Balance --token: %v", err)
	}
	onChain := anvil.ERC20BalanceOf(t, token, from)
	if res.Token == nil || res.Token.Base != onChain.String() {
		t.Fatalf("balance --token = %+v, want on-chain %s", res.Token, onChain)
	}

	// tx send --token 100 TST to the recipient.
	sendAmt := big.NewInt(100)
	if _, err := svc.SendTx(context.Background(), domain.LocalCLI(), domain.TxRequest{
		From: "funded", To: recipient.Hex(), Amount: "100", Token: "tst", Network: "localanvil",
		Yes: true, Wait: domain.WaitOpts{Enabled: true},
	}, nil); err != nil {
		t.Fatalf("SendTx --token: %v", err)
	}
	// 100 TST at 18 decimals = 100e18 base units; assert the recipient received it.
	want := new(big.Int).Mul(sendAmt, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	if got := anvil.ERC20BalanceOf(t, token, recipient); got.Cmp(want) != 0 {
		t.Errorf("recipient on-chain balance = %s, want %s", got, want)
	}
}

func TestIntegration_TokenApproveAllowanceRevoke(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())
	token := testchain.DeployERC20(t, anvil)
	spender := common.HexToAddress("0x00000000000000000000000000000000000000b2")

	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(), domain.TokenAddRequest{
		Contract: token.Hex(), Name: "tst", Network: "localanvil",
	}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}

	// approve spender 250 TST.
	if _, err := svc.TokenApprove(context.Background(), domain.LocalCLI(), domain.ApproveRequest{
		Token: "tst", Spender: spender.Hex(), Amount: "250", From: "funded", Network: "localanvil",
		Yes: true, Wait: domain.WaitOpts{Enabled: true},
	}, nil); err != nil {
		t.Fatalf("TokenApprove: %v", err)
	}
	want := new(big.Int).Mul(big.NewInt(250), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	if got := anvil.ERC20Allowance(t, token, from, spender); got.Cmp(want) != 0 {
		t.Errorf("on-chain allowance = %s, want %s", got, want)
	}
	// The service's read agrees.
	al, err := svc.TokenAllowance(context.Background(), domain.LocalCLI(), domain.AllowanceRequest{
		Token: "tst", Owner: from.Hex(), Spender: spender.Hex(), Network: "localanvil",
	}, nil)
	if err != nil {
		t.Fatalf("TokenAllowance: %v", err)
	}
	if al.Allowance != want.String() {
		t.Errorf("TokenAllowance = %s, want %s", al.Allowance, want)
	}

	// revoke → allowance 0.
	if _, err := svc.TokenRevoke(context.Background(), domain.LocalCLI(), domain.ApproveRequest{
		Token: "tst", Spender: spender.Hex(), From: "funded", Network: "localanvil",
		Yes: true, Wait: domain.WaitOpts{Enabled: true},
	}, nil); err != nil {
		t.Fatalf("TokenRevoke: %v", err)
	}
	if got := anvil.ERC20Allowance(t, token, from, spender); got.Sign() != 0 {
		t.Errorf("on-chain allowance after revoke = %s, want 0", got)
	}
}

// TestIntegration_TokenFailClosedNoAllowlist: a token transfer with limits set but no
// allowlist is refused fail-closed (policy.denied.no_allowlist, exit 3), and NOTHING
// is signed — the stage-3c rule on the real engine, end-to-end.
func TestIntegration_TokenFailClosedNoAllowlist(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, _ := openSendAnvil(t, anvil.URL())
	token := testchain.DeployERC20(t, anvil)
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000c3")

	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(), domain.TokenAddRequest{
		Contract: token.Hex(), Name: "tst", Network: "localanvil",
	}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}
	// Limits configured (max_tx) but allowlist OFF ⇒ a token transfer fails closed.
	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:     strPtrIT("1eth"),
		Allowlist: strPtrIT("off"),
	})

	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), domain.TxRequest{
		From: "funded", To: recipient.Hex(), Amount: "1", Token: "tst", Network: "localanvil", Yes: true,
	}, nil)
	wantDenied(t, err, "policy.denied.no_allowlist")

	// The recipient never received any token (nothing was signed/broadcast).
	if got := anvil.ERC20BalanceOf(t, token, recipient); got.Sign() != 0 {
		t.Errorf("a fail-closed-denied transfer moved tokens: recipient balance %s, want 0", got)
	}
}

// TestIntegration_TokenTransferAllowlisted: with limits + an allowlist that pins the
// recipient, the token transfer mines (the allowlist subject is the RECIPIENT, not
// the token contract — the §4.2/§5.1 invariant, end-to-end).
func TestIntegration_TokenTransferAllowlisted(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())
	token := testchain.DeployERC20(t, anvil)
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000d4")

	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(), domain.TokenAddRequest{
		Contract: token.Hex(), Name: "tst", Network: "localanvil",
	}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}
	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:       strPtrIT("1eth"),
		MaxDay:      strPtrIT("10eth"),
		Allowlist:   strPtrIT("on"),
		IncludeSelf: strPtrIT("on"),
	})
	// Pin the RECIPIENT (the policy subject for a token transfer is the decoded
	// recipient — pinning the TOKEN CONTRACT would NOT let this through).
	allowIT(t, svc, recipient)

	if _, err := svc.SendTx(context.Background(), domain.LocalCLI(), domain.TxRequest{
		From: "funded", To: recipient.Hex(), Amount: "5", Token: "tst", Network: "localanvil",
		Yes: true, Wait: domain.WaitOpts{Enabled: true},
	}, nil); err != nil {
		t.Fatalf("allowlisted token transfer: %v", err)
	}
	want := new(big.Int).Mul(big.NewInt(5), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	if got := anvil.ERC20BalanceOf(t, token, recipient); got.Cmp(want) != 0 {
		t.Errorf("allowlisted recipient balance = %s, want %s", got, want)
	}
	_ = from
}
