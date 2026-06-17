package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/policy"
	"github.com/daxchain-io/daxie/internal/secret"
	"github.com/ethereum/go-ethereum/common"
)

// approve_test.go covers the ERC-20 approval path: the calldata + the policy Check
// it builds (Dest = SPENDER, never the token contract), the --unlimited --yes
// ceremony (unacked → denied), the fail-closed-no-allowlist rule (limits set, no
// allowlist → denied), and the KindApprove routing — all through the REAL M4 engine.

// sealPolicy seals a policy under an admin passphrase via the engine directly (the
// same engine service holds), so a unit test can exercise the real gates without the
// integration harness. ch carries the limits/allowlist/flags.
func sealPolicy(t *testing.T, svc *Service, ch policy.Change) {
	t.Helper()
	pass := secret.NewString("unit-admin-pass")
	if _, err := svc.policy.Set(pass, ch); err != nil {
		t.Fatalf("seal policy: %v", err)
	}
}

func boolPtr(b bool) *bool  { return &b }
func sptr(s string) *string { return &s }

func TestApprove_PolicyDestIsSpenderNotContract(t *testing.T) {
	from := someAddr(0x01)
	spender := someAddr(0x0b)
	contract := someAddr(0x42)

	svc, f, _ := sendService(t, from)
	f.CallContractFn = erc20Fake(6, "TST", nil, nil).CallContractFn
	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}

	in, _, err := svc.resolveApproveIntent(context.Background(), domain.LocalCLI(), domain.ApproveRequest{
		Token: "tst", Spender: spender.Hex(), Amount: "100", From: from.Hex(), Network: "mainnet",
	}, false, nil)
	if err != nil {
		t.Fatalf("resolveApproveIntent: %v", err)
	}
	defer in.cc.Close()

	// The policy subject is the SPENDER, never the token contract.
	if in.checkDest() != spender {
		t.Fatalf("approve policy dest = %s, want the spender %s", in.checkDest().Hex(), spender.Hex())
	}
	if in.checkDest() == contract {
		t.Fatal("approve policy dest is the token contract — the spender-as-dest invariant is broken")
	}
	// The tx goes TO the token contract; value is 0.
	if in.to != contract || in.value.Sign() != 0 {
		t.Fatalf("approve to=%s value=%s, want contract %s value 0", in.to.Hex(), in.value, contract.Hex())
	}
	// It routes through KindApprove (the spend-equivalent gates).
	if in.policyCheckKind() != "approve" {
		t.Errorf("approve check kind = %q, want approve", in.policyCheckKind())
	}
	if in.kind != journal.KindApprove {
		t.Errorf("journal kind = %q, want approve", in.kind)
	}
	// The calldata is approve(spender, 100): selector 0x095ea7b3 || spender || amount.
	data := in.data
	wantSel := []byte{0x09, 0x5e, 0xa7, 0xb3}
	for i := 0; i < 4; i++ {
		if data[i] != wantSel[i] {
			t.Fatalf("approve selector = %x, want 095ea7b3", data[:4])
		}
	}
	if common.BytesToAddress(data[4:36]) != spender {
		t.Errorf("approve calldata spender = %s, want %s", common.BytesToAddress(data[4:36]).Hex(), spender.Hex())
	}
	if got := new(big.Int).SetBytes(data[36:68]); got.Cmp(big.NewInt(100_000_000)) != 0 {
		t.Errorf("approve amount = %s, want 100000000 (100 * 1e6)", got)
	}
}

func TestApprove_UnlimitedUnackedDenied(t *testing.T) {
	from := someAddr(0x01)
	spender := someAddr(0x0b)
	contract := someAddr(0x42)

	svc, f, _ := sendService(t, from)
	f.CallContractFn = erc20Fake(18, "TST", nil, nil).CallContractFn
	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}
	// A sealed policy with an allowlist that INCLUDES the spender (so the only thing
	// that can bite is the unlimited gate), and a per-tx limit so gates are active.
	sealPolicy(t, svc, policy.Change{
		Default:   &policy.Limits{MaxTxWei: sptr("1000000000000000000"), AllowlistEnabled: boolPtr(true)},
		WrittenBy: "test",
	})
	allowSpender(t, svc, spender)

	// --unlimited WITHOUT the acknowledgement (AckUnlimited=false) ⇒ denied
	// unlimited_unacked (exit 3). Yes (the TTY-skip) is irrelevant to the ack now (§6.3).
	_, err := svc.TokenApprove(context.Background(), domain.LocalCLI(), domain.ApproveRequest{
		Token: "tst", Spender: spender.Hex(), Unlimited: true, From: from.Hex(), Network: "mainnet",
		AckUnlimited: false, Yes: false,
	}, nil)
	if err == nil {
		t.Fatal("an unacked --unlimited approval must be denied")
	}
	if de := domain.AsError(err); de.Code != "policy.denied.unlimited_unacked" {
		t.Fatalf("code = %q, want policy.denied.unlimited_unacked", de.Code)
	}
}

// TestApprove_SentinelAmountIsUnlimited proves the §4.2 sentinel-via-amount
// derivation at the builder level: a bounded --amount that lands on 2^256-1 (here
// trivially reachable on a 0-decimal token) sets in.unlimited even though the
// --unlimited flag is false — so the unlimited ceremony fires exactly as on the
// typed path (design §4.2 lines 1633/1644). This is the probe the adversarial
// review used to prove the bypass.
func TestApprove_SentinelAmountIsUnlimited(t *testing.T) {
	from := someAddr(0x01)
	spender := someAddr(0x0b)
	contract := someAddr(0x42)

	svc, f, _ := sendService(t, from)
	// 0 decimals ⇒ 2^256-1 is integer-reachable verbatim via --amount.
	f.CallContractFn = erc20Fake(0, "TST", nil, nil).CallContractFn
	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}

	sentinel := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)).String()
	in, amount, err := svc.resolveApproveIntent(context.Background(), domain.LocalCLI(), domain.ApproveRequest{
		Token: "tst", Spender: spender.Hex(), Amount: sentinel, From: from.Hex(), Network: "mainnet",
		// NOTE: Unlimited flag is FALSE — the sentinel arrives via --amount only.
	}, false, nil)
	if err != nil {
		t.Fatalf("resolveApproveIntent: %v", err)
	}
	defer in.cc.Close()

	if !in.unlimited {
		t.Fatal("a sentinel --amount (2^256-1) must set in.unlimited so the ceremony fires")
	}
	// The calldata encodes the exact infinite-allowance word.
	wantWord := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	if got := new(big.Int).SetBytes(in.data[36:68]); got.Cmp(wantWord) != 0 {
		t.Fatalf("approve amount word = %s, want 2^256-1", got)
	}
	if amount.Cmp(wantWord) != 0 {
		t.Fatalf("resolved amount = %s, want 2^256-1", amount)
	}
}

// TestApprove_SentinelAmountUnackedDenied is the end-to-end proof the bypass is
// closed: a sentinel --amount on a 0-decimal token WITHOUT --yes routes through the
// real M4 engine and is denied policy.denied.unlimited_unacked (exit 3) — the same
// verdict the --unlimited path gets. The allowlist includes the spender so the only
// gate that can bite is the unlimited-ack ceremony.
func TestApprove_SentinelAmountUnackedDenied(t *testing.T) {
	from := someAddr(0x01)
	spender := someAddr(0x0b)
	contract := someAddr(0x42)

	svc, f, _ := sendService(t, from)
	f.CallContractFn = erc20Fake(0, "TST", nil, nil).CallContractFn
	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}
	sealPolicy(t, svc, policy.Change{
		Default:   &policy.Limits{MaxTxWei: sptr("1000000000000000000"), AllowlistEnabled: boolPtr(true)},
		WrittenBy: "test",
	})
	allowSpender(t, svc, spender)

	sentinel := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)).String()
	// A sentinel --amount WITHOUT the acknowledgement ⇒ denied unlimited_unacked, exactly
	// like --unlimited without the ack. The --unlimited flag is false here.
	_, err := svc.TokenApprove(context.Background(), domain.LocalCLI(), domain.ApproveRequest{
		Token: "tst", Spender: spender.Hex(), Amount: sentinel, From: from.Hex(), Network: "mainnet",
		AckUnlimited: false, Yes: false,
	}, nil)
	if err == nil {
		t.Fatal("an unacked sentinel --amount approval must be denied (unlimited bypass)")
	}
	if de := domain.AsError(err); de.Code != "policy.denied.unlimited_unacked" {
		t.Fatalf("code = %q, want policy.denied.unlimited_unacked", de.Code)
	}
}

func TestApprove_FailClosedNoAllowlistDenied(t *testing.T) {
	from := someAddr(0x01)
	spender := someAddr(0x0b)
	contract := someAddr(0x42)

	svc, f, _ := sendService(t, from)
	f.CallContractFn = erc20Fake(6, "TST", nil, nil).CallContractFn
	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}
	// Limits configured but allowlist OFF ⇒ stage-3c fail-closed for a token approval.
	sealPolicy(t, svc, policy.Change{
		Default:   &policy.Limits{MaxTxWei: sptr("1000000000000000000"), AllowlistEnabled: boolPtr(false)},
		WrittenBy: "test",
	})

	_, err := svc.TokenApprove(context.Background(), domain.LocalCLI(), domain.ApproveRequest{
		Token: "tst", Spender: spender.Hex(), Amount: "10", From: from.Hex(), Network: "mainnet", Yes: true,
	}, nil)
	if err == nil {
		t.Fatal("a token approval with limits set but no allowlist must fail closed")
	}
	if de := domain.AsError(err); de.Code != "policy.denied.no_allowlist" {
		t.Fatalf("code = %q, want policy.denied.no_allowlist", de.Code)
	}
}

func TestRevoke_IsApproveZero(t *testing.T) {
	from := someAddr(0x01)
	spender := someAddr(0x0b)
	contract := someAddr(0x42)

	svc, f, _ := sendService(t, from)
	f.CallContractFn = erc20Fake(6, "TST", nil, nil).CallContractFn
	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}

	in, amount, err := svc.resolveApproveIntent(context.Background(), domain.LocalCLI(), domain.ApproveRequest{
		Token: "tst", Spender: spender.Hex(), From: from.Hex(), Network: "mainnet",
	}, true, nil) // revoke=true
	if err != nil {
		t.Fatalf("resolveApproveIntent revoke: %v", err)
	}
	defer in.cc.Close()
	if amount.Sign() != 0 {
		t.Fatalf("revoke amount = %s, want 0 (approve spender 0)", amount)
	}
	if got := new(big.Int).SetBytes(in.data[36:68]); got.Sign() != 0 {
		t.Errorf("revoke calldata amount = %s, want 0", got)
	}
	if in.unlimited {
		t.Errorf("revoke must never be flagged unlimited")
	}
}

// allowSpender pins an allowlist address under the unit admin passphrase.
func allowSpender(t *testing.T, svc *Service, addr common.Address) {
	t.Helper()
	pass := secret.NewString("unit-admin-pass")
	if _, err := svc.policy.Allow(pass, policy.AllowEntry{
		PinEntry:  policy.PinEntry{Source: "address", Address: addr.Hex()},
		WrittenBy: "test",
	}); err != nil {
		t.Fatalf("allow spender: %v", err)
	}
}
