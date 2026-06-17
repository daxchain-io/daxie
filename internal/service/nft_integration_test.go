//go:build integration

// nft_integration_test.go drives the M6 ERC-721/1155 surface end-to-end through the
// REAL ChainProvider + keystore signer + journal/policy against a local anvil with
// freshly-deployed test NFT collections. It asserts on-chain state via the testchain
// RAW-RPC readers (independent of Daxie's own erc package — no self-confirmation):
//
//   - nft add → ERC-165 detection is REAL: a 721 stores kind erc721, a 1155 stores
//     kind erc1155, and adding a plain ERC-20 (a non-NFT) FAILS (usage.not_nft);
//   - nft send (721) → ownerOf changed to the recipient (raw-RPC asserted);
//   - nft send (1155, --amount 5) → balanceOf moved 5 to the recipient, sender down 5;
//   - nft show → the owner / balance match;
//   - a DENY case: an NFT send with limits set + no allowlist → fail-closed
//     policy.denied.no_allowlist (exit 3), nothing signed, ownerOf unchanged (the
//     §4.3 NFT-not-exempt rule).
package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/testchain"
	"github.com/ethereum/go-ethereum/common"
)

func TestIntegration_NFT721_AddDetectSendOwnership(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())
	collection := testchain.DeployERC721(t, anvil)
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000a1")

	// Mint token id 42 to the sender (the funded deployer = from).
	tokenID := big.NewInt(42)
	testchain.MintNFT721(t, anvil, collection, from, tokenID)

	// ERC-165 detection is REAL: the fixture answers supportsInterface(0x80ac58cd)=true.
	if !anvil.ERC721SupportsInterface(t, collection, [4]byte{0x80, 0xac, 0x58, 0xcd}) {
		t.Fatal("the 721 fixture must answer supportsInterface(0x80ac58cd)=true")
	}

	// nft add → the stored kind must be erc721 (detection at add).
	addRes, err := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: collection.Hex(), Name: "punks", Network: "localanvil",
	})
	if err != nil {
		t.Fatalf("NFTAdd 721: %v", err)
	}
	if addRes.Collection.Kind != "erc721" {
		t.Fatalf("stored kind = %q, want erc721 (ERC-165 detection at add)", addRes.Collection.Kind)
	}

	// A non-NFT address (the test ERC-20) MUST be rejected (usage.not_nft, exit 2).
	erc20 := testchain.DeployERC20(t, anvil)
	if _, aerr := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: erc20.Hex(), Name: "nope", Network: "localanvil",
	}); aerr == nil {
		t.Fatal("adding a non-NFT (ERC-20) must fail (usage.not_nft)")
	} else if de := domain.AsError(aerr); de.Code != "usage.not_nft" {
		t.Fatalf("non-NFT add code = %q, want usage.not_nft", de.Code)
	}

	// nft send punks#42 to the recipient, waiting for the receipt.
	if _, err := svc.SendNFT(context.Background(), domain.LocalCLI(), domain.NFTSendRequest{
		NFT: "punks#42", To: recipient.Hex(), From: "funded", Network: "localanvil",
		Yes: true, Wait: domain.WaitOpts{Enabled: true},
	}, nil); err != nil {
		t.Fatalf("SendNFT 721: %v", err)
	}

	// ownerOf(42) is now the recipient (RAW-RPC asserted).
	if got := anvil.ERC721OwnerOf(t, collection, tokenID); got != recipient {
		t.Errorf("ownerOf(42) = %s, want the recipient %s", got.Hex(), recipient.Hex())
	}

	// nft show #42 → the owner matches.
	show, err := svc.NFTShow(context.Background(), domain.LocalCLI(), domain.NFTShowRequest{
		NFT: "punks#42", Network: "localanvil",
	}, nil)
	if err != nil {
		t.Fatalf("NFTShow: %v", err)
	}
	if common.HexToAddress(show.Owner) != recipient {
		t.Errorf("nft show owner = %s, want %s", show.Owner, recipient.Hex())
	}
	if show.Kind != "erc721" {
		t.Errorf("nft show kind = %q, want erc721", show.Kind)
	}
}

func TestIntegration_NFT1155_AddSendBalance(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())
	collection := testchain.DeployERC1155(t, anvil)
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000b2")

	// Mint 100 of id 9 to the sender.
	tokenID := big.NewInt(9)
	testchain.MintNFT1155(t, anvil, collection, from, tokenID, big.NewInt(100))

	addRes, err := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: collection.Hex(), Name: "items", Network: "localanvil",
	})
	if err != nil {
		t.Fatalf("NFTAdd 1155: %v", err)
	}
	if addRes.Collection.Kind != "erc1155" {
		t.Fatalf("stored kind = %q, want erc1155", addRes.Collection.Kind)
	}

	// nft send items#9 --amount 5 to the recipient, waiting.
	if _, err := svc.SendNFT(context.Background(), domain.LocalCLI(), domain.NFTSendRequest{
		NFT: "items#9", To: recipient.Hex(), Amount: "5", From: "funded", Network: "localanvil",
		Yes: true, Wait: domain.WaitOpts{Enabled: true},
	}, nil); err != nil {
		t.Fatalf("SendNFT 1155: %v", err)
	}

	// The recipient now holds 5 of id 9; the sender dropped to 95 (RAW-RPC asserted).
	if got := anvil.ERC1155BalanceOf(t, collection, recipient, tokenID); got.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("recipient 1155 balance of id 9 = %s, want 5", got)
	}
	if got := anvil.ERC1155BalanceOf(t, collection, from, tokenID); got.Cmp(big.NewInt(95)) != 0 {
		t.Errorf("sender 1155 balance of id 9 = %s, want 95 (100 - 5)", got)
	}

	// nft show with --account reports the recipient's balance.
	show, err := svc.NFTShow(context.Background(), domain.LocalCLI(), domain.NFTShowRequest{
		NFT: "items#9", Account: recipient.Hex(), Network: "localanvil",
	}, nil)
	if err != nil {
		t.Fatalf("NFTShow 1155: %v", err)
	}
	if show.Balance != "5" {
		t.Errorf("nft show 1155 balance = %q, want 5", show.Balance)
	}
}

// TestIntegration_NFTFailClosedNoAllowlist: an NFT send with limits set but no
// allowlist is refused fail-closed (policy.denied.no_allowlist, exit 3), NOTHING is
// signed, and ownerOf is unchanged — the stage-3c rule on the real engine, applied
// to NFTs (ETH exempt, NFT NOT), end-to-end.
func TestIntegration_NFTFailClosedNoAllowlist(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())
	collection := testchain.DeployERC721(t, anvil)
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000c3")

	tokenID := big.NewInt(7)
	testchain.MintNFT721(t, anvil, collection, from, tokenID)

	if _, err := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: collection.Hex(), Name: "punks", Network: "localanvil",
	}); err != nil {
		t.Fatalf("NFTAdd: %v", err)
	}
	// Limits configured (max_tx) but allowlist OFF ⇒ an NFT transfer fails closed.
	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:     strPtrIT("1eth"),
		Allowlist: strPtrIT("off"),
	})

	_, err := svc.SendNFT(context.Background(), domain.LocalCLI(), domain.NFTSendRequest{
		NFT: "punks#7", To: recipient.Hex(), From: "funded", Network: "localanvil", Yes: true,
	}, nil)
	wantDenied(t, err, "policy.denied.no_allowlist")

	// ownerOf(7) is unchanged — the sender still holds it (nothing was signed/broadcast).
	if got := anvil.ERC721OwnerOf(t, collection, tokenID); got != from {
		t.Errorf("a fail-closed-denied NFT send moved ownership: ownerOf(7) = %s, want the sender %s", got.Hex(), from.Hex())
	}
}

// TestIntegration_NFTSendAllowlisted: with limits + an allowlist pinning the
// RECIPIENT, the NFT send mines (the allowlist subject is the RECIPIENT, not the
// collection — the §4.2/§4.3 invariant, end-to-end).
func TestIntegration_NFTSendAllowlisted(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())
	collection := testchain.DeployERC721(t, anvil)
	recipient := common.HexToAddress("0x00000000000000000000000000000000000000d4")

	tokenID := big.NewInt(11)
	testchain.MintNFT721(t, anvil, collection, from, tokenID)

	if _, err := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: collection.Hex(), Name: "punks", Network: "localanvil",
	}); err != nil {
		t.Fatalf("NFTAdd: %v", err)
	}
	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:       strPtrIT("1eth"),
		MaxDay:      strPtrIT("10eth"),
		Allowlist:   strPtrIT("on"),
		IncludeSelf: strPtrIT("on"),
	})
	// Pin the RECIPIENT (pinning the COLLECTION CONTRACT would NOT let this through).
	allowIT(t, svc, recipient)

	if _, err := svc.SendNFT(context.Background(), domain.LocalCLI(), domain.NFTSendRequest{
		NFT: "punks#11", To: recipient.Hex(), From: "funded", Network: "localanvil",
		Yes: true, Wait: domain.WaitOpts{Enabled: true},
	}, nil); err != nil {
		t.Fatalf("allowlisted NFT send: %v", err)
	}
	if got := anvil.ERC721OwnerOf(t, collection, tokenID); got != recipient {
		t.Errorf("allowlisted recipient ownerOf(11) = %s, want %s", got.Hex(), recipient.Hex())
	}
	_ = from
}
