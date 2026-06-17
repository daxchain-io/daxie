package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// tx_token_test.go pins the ERC-20 transfer path's correctness against the chain
// fake: the calldata is the ERC-20 transfer(recipient, amount), the signed tx goes
// TO the token contract (not the recipient), and the policy Check.Dest is the
// DECODED RECIPIENT (never the token contract). It captures the signed tx via the
// fakeSigner and decodes it.

// captureSigner is a fakeSigner that also retains the last unsigned tx so the test
// can decode the destination + calldata it carried.
type captureSigner struct {
	fakeSigner
	lastTx *types.Transaction
}

func (c *captureSigner) SignTx(ctx context.Context, ref domain.AccountRef, tx *types.Transaction, chainID *big.Int, u domain.Unlocker) ([]byte, common.Hash, error) {
	c.lastTx = tx
	return c.fakeSigner.SignTx(ctx, ref, tx, chainID, u)
}

func TestSendTx_Token_CalldataAndContractTarget(t *testing.T) {
	from := someAddr(0x01)
	recipient := someAddr(0x0a)
	contract := someAddr(0x42)

	svc, f, _ := sendService(t, from)
	// Swap in a capturing signer + an ERC-20 metadata fake on the SAME provider client.
	cs := &captureSigner{fakeSigner: fakeSigner{addr: from}}
	svc.signer = cs
	f.CallContractFn = erc20Fake(6, "TST", nil, nil).CallContractFn
	f.SendRawFn = func(_ context.Context, _ []byte) (common.Hash, error) { return common.HexToHash("0xabc"), nil }

	// Register the token so the alias resolves registry-only.
	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}

	// Send 1.5 TST (6 decimals ⇒ 1_500_000 base units) to the recipient.
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), domain.TxRequest{
		From:    from.Hex(),
		To:      recipient.Hex(),
		Amount:  "1.5",
		Token:   "tst",
		Network: "mainnet",
		Yes:     true,
	}, nil)
	if err != nil {
		t.Fatalf("SendTx --token: %v", err)
	}

	tx := cs.lastTx
	if tx == nil {
		t.Fatal("no tx was signed")
	}
	// The tx target is the TOKEN CONTRACT (not the recipient).
	if tx.To() == nil || *tx.To() != contract {
		t.Fatalf("tx To = %v, want the token contract %s", tx.To(), contract.Hex())
	}
	// The tx carries ZERO ETH value (a token transfer moves no ETH).
	if tx.Value().Sign() != 0 {
		t.Errorf("tx value = %s, want 0 (token transfer carries no ETH)", tx.Value())
	}
	// The calldata is transfer(recipient, 1_500_000): selector 0xa9059cbb || recipient
	// word || amount word.
	data := tx.Data()
	if len(data) != 4+32+32 {
		t.Fatalf("calldata len = %d, want 68 (selector + 2 words)", len(data))
	}
	wantSel := []byte{0xa9, 0x05, 0x9c, 0xbb}
	for i := 0; i < 4; i++ {
		if data[i] != wantSel[i] {
			t.Fatalf("calldata selector = %x, want a9059cbb", data[:4])
		}
	}
	gotRecipient := common.BytesToAddress(data[4 : 4+32])
	if gotRecipient != recipient {
		t.Errorf("calldata recipient = %s, want %s (NOT the token contract)", gotRecipient.Hex(), recipient.Hex())
	}
	gotAmount := new(big.Int).SetBytes(data[4+32 : 4+64])
	if gotAmount.Cmp(big.NewInt(1_500_000)) != 0 {
		t.Errorf("calldata amount = %s, want 1500000", gotAmount)
	}
}

func TestSendTx_Token_PolicyDestIsRecipientNotContract(t *testing.T) {
	from := someAddr(0x01)
	recipient := someAddr(0x0a)
	contract := someAddr(0x42)

	svc, f, _ := sendService(t, from)
	f.CallContractFn = erc20Fake(18, "TST", nil, nil).CallContractFn
	f.SendRawFn = func(_ context.Context, _ []byte) (common.Hash, error) { return common.HexToHash("0xabc"), nil }
	if _, err := svc.TokenAdd(context.Background(), domain.LocalCLI(),
		domain.TokenAddRequest{Contract: contract.Hex(), Name: "tst", Network: "mainnet"}); err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}

	// Capture the policy Check by intercepting via a recording engine is heavy; instead
	// assert the OUTCOME: build the intent and inspect checkDest()/checkAsset() directly
	// — they are the exact values authorize hands the engine.
	in, err := svc.resolveIntent(context.Background(), domain.LocalCLI(), domain.TxRequest{
		From: from.Hex(), To: recipient.Hex(), Amount: "1", Token: "tst", Network: "mainnet",
	}, nil)
	if err != nil {
		t.Fatalf("resolveIntent: %v", err)
	}
	defer in.cc.Close()

	if in.checkDest() != recipient {
		t.Errorf("policy dest = %s, want the recipient %s (NOT the token contract)", in.checkDest().Hex(), recipient.Hex())
	}
	if in.checkDest() == contract {
		t.Fatal("policy dest is the token contract — the recipient-as-dest invariant is broken")
	}
	if in.to != contract {
		t.Errorf("tx to = %s, want the token contract %s", in.to.Hex(), contract.Hex())
	}
	if in.value.Sign() != 0 {
		t.Errorf("token transfer SpendWei (value) = %s, want 0 (no ETH, no price oracle)", in.value)
	}
	if in.checkAsset() == "eth" {
		t.Errorf("token transfer asset tag = eth, want the lowercase contract (so stage-3c fires)")
	}
	if in.kind != journal.KindERC20Transfer {
		t.Errorf("kind = %q, want erc20-transfer", in.kind)
	}
}

func TestSendTx_Token_UnregisteredAliasIsNotFound(t *testing.T) {
	from := someAddr(0x01)
	svc, _, _ := sendService(t, from)
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), domain.TxRequest{
		From: from.Hex(), To: someAddr(0x0a).Hex(), Amount: "1", Token: "ghost-token", Network: "mainnet", Yes: true,
	}, nil)
	if err == nil {
		t.Fatal("sending an unregistered token alias must error (ref.not_found), never a symbol lookup")
	}
	if de := domain.AsError(err); de.Code != domain.CodeRefNotFound {
		t.Fatalf("code = %q, want ref.not_found", de.Code)
	}
}
