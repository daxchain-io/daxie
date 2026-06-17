package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/policy"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// nft_test.go covers the M6 NFT use cases over the chain fake + temp-dir registry:
//
//   - ERC-165 detection at `nft add` (721 vs 1155 stored; a non-NFT rejected);
//   - resolveNFT: registry-only alias resolution (a miss is ref.not_found, NEVER an
//     on-chain name() lookup) + the raw-0x always-allowed branch + a 2^200 token id
//     round-tripping as a decimal string;
//   - SendNFT: the 721/1155 safeTransferFrom calldata is byte-correct, the tx goes
//     TO the collection (not the recipient), and the policy Dest is the RECIPIENT
//     (never the collection);
//   - the §4.3 fail-closed-no-allowlist DENY for an NFT send (limits set, no
//     allowlist) — ETH exempt, NFT NOT.

// NFT/ERC-165 read selectors (the first 4 keccak bytes), for the fake's
// CallContract dispatch. Pinned literally so the fake answers independently of erc.
var (
	selSupportsIface = []byte{0x01, 0xff, 0xc9, 0xa7} // supportsInterface(bytes4)
	selOwnerOf       = []byte{0x63, 0x52, 0x21, 0x1e} // ownerOf(uint256)
	selBalanceOf1155 = []byte{0x00, 0xfd, 0xd5, 0x8e} // balanceOf(address,uint256)
	selName          = []byte{0x06, 0xfd, 0xde, 0x03} // name()

	iface721ID  = []byte{0x80, 0xac, 0x58, 0xcd}
	iface1155ID = []byte{0xd9, 0xb6, 0x7a, 0x26}
)

// nftFake returns a fake chain client whose CallContract answers the ERC-165 +
// metadata reads for an NFT of the given kind. owner is the 721 ownerOf return;
// balance the 1155 balanceOf return; name the name() (display) return — which is
// what the NFT registry reads for the default alias / echoed name (§7.8), NOT
// symbol() (the token-registry default; the two registries intentionally differ).
func nftFake(kind string, owner common.Address, balance *big.Int, name string) *fake.Client {
	f := fake.New()
	f.CallContractFn = func(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
		switch {
		case hasSelector(msg.Data, selSupportsIface):
			// The queried interface id is the bytes4 LEFT-aligned in the arg word.
			want := msg.Data[4:8]
			is721 := bytesEq(want, iface721ID)
			is1155 := bytesEq(want, iface1155ID)
			ok := (kind == "erc721" && is721) || (kind == "erc1155" && is1155)
			if ok {
				return abiWord(big.NewInt(1)), nil
			}
			return abiWord(big.NewInt(0)), nil
		case hasSelector(msg.Data, selOwnerOf):
			return common.LeftPadBytes(owner.Bytes(), 32), nil
		case hasSelector(msg.Data, selBalanceOf1155):
			if balance == nil {
				return abiWord(big.NewInt(0)), nil
			}
			return abiWord(balance), nil
		case hasSelector(msg.Data, selName):
			return abiString(name), nil
		default:
			return nil, nil
		}
	}
	return f
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNFTAdd_ERC165Detection_721(t *testing.T) {
	cc := nftFake("erc721", common.Address{}, nil, "PUNK")
	svc := openWithProvider(t, &stubProvider{cc: cc})
	contract := someAddr(0x71)

	res, err := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: contract.Hex(), Name: "punks", Network: "mainnet",
	})
	if err != nil {
		t.Fatalf("NFTAdd 721: %v", err)
	}
	if res.Collection.Kind != "erc721" {
		t.Fatalf("detected kind = %q, want erc721 (ERC-165 detection at add)", res.Collection.Kind)
	}
	if res.Collection.Alias != "punks" {
		t.Errorf("alias = %q, want punks", res.Collection.Alias)
	}
}

// TestNFTAdd_DefaultAliasFromName proves the NFT default alias derives from the
// on-chain name() (cli-spec §`daxie nft` line 283 / design §7.8), NOT symbol() (the
// token-registry default). It uses the exact spec example: CryptoPunks' name()
// returns "CryptoPunks" (folds to "cryptopunks"), while its symbol() returns "Ͼ" — a
// non-ASCII glyph that would fail the §3.1 alias grammar. With --name omitted, the
// alias and echoed name MUST come from name(); reading symbol() here would break the
// spec example outright (the glyph cannot fold to a valid alias). DISPLAY/default
// only — resolution is still registry-only (the anti-spoofing wall).
func TestNFTAdd_DefaultAliasFromName(t *testing.T) {
	cc := nftFake("erc721", common.Address{}, nil, "CryptoPunks")
	// Make symbol() answer the non-ASCII glyph the real CryptoPunks returns, so the
	// test fails loudly if the code ever reads symbol() for the NFT default alias.
	cc.CallContractFn = wrapWithSymbol(cc.CallContractFn, "Ͼ")
	svc := openWithProvider(t, &stubProvider{cc: cc})
	contract := someAddr(0x71)

	res, err := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: contract.Hex(), Network: "mainnet", // --name OMITTED ⇒ default from name()
	})
	if err != nil {
		t.Fatalf("NFTAdd (default alias from name): %v", err)
	}
	if res.Collection.Alias != "cryptopunks" {
		t.Errorf("default alias = %q, want cryptopunks (case-folded on-chain name(), not symbol())", res.Collection.Alias)
	}
	if res.Collection.Name != "CryptoPunks" {
		t.Errorf("echoed name = %q, want CryptoPunks (the on-chain name(), not the symbol glyph)", res.Collection.Name)
	}
}

// wrapWithSymbol layers a symbol() answer onto an existing CallContract dispatcher
// so a test can distinguish name() from symbol() reads.
func wrapWithSymbol(inner func(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error), sym string) func(context.Context, ethereum.CallMsg, *big.Int) ([]byte, error) {
	return func(ctx context.Context, msg ethereum.CallMsg, blk *big.Int) ([]byte, error) {
		if hasSelector(msg.Data, selSymbol) {
			return abiString(sym), nil
		}
		return inner(ctx, msg, blk)
	}
}

func TestNFTAdd_ERC165Detection_1155(t *testing.T) {
	cc := nftFake("erc1155", common.Address{}, big.NewInt(0), "ITEMS")
	svc := openWithProvider(t, &stubProvider{cc: cc})
	contract := someAddr(0x55)

	res, err := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: contract.Hex(), Name: "items", Network: "mainnet",
	})
	if err != nil {
		t.Fatalf("NFTAdd 1155: %v", err)
	}
	if res.Collection.Kind != "erc1155" {
		t.Fatalf("detected kind = %q, want erc1155", res.Collection.Kind)
	}
}

func TestNFTAdd_NonNFTRejected(t *testing.T) {
	// A fake that supports NEITHER interface (a plain ERC-20 / EOA) must be refused
	// with usage.not_nft (exit 2) — a non-NFT address is rejected at add.
	cc := nftFake("erc20", common.Address{}, nil, "TST") // kind "erc20" ⇒ supportsInterface always 0
	svc := openWithProvider(t, &stubProvider{cc: cc})

	_, err := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: someAddr(0x20).Hex(), Name: "nope", Network: "mainnet",
	})
	if err == nil {
		t.Fatal("adding a non-NFT address must be rejected (usage.not_nft)")
	}
	de := domain.AsError(err)
	if de.Code != "usage.not_nft" {
		t.Fatalf("code = %q, want usage.not_nft", de.Code)
	}
	if de.Exit != domain.ExitUsage {
		t.Errorf("exit = %d, want 2 (usage)", de.Exit)
	}
}

func TestNFTAdd_RevertingSupportsInterfaceIsNotNFT(t *testing.T) {
	// A real ERC-20 / non-165 contract REVERTS the supportsInterface eth_call (the
	// node returns "execution reverted", which the chain layer flattens into
	// rpc.unreachable). detectKind must map that to usage.not_nft (exit 2) — a non-NFT
	// is rejected, NOT reported as an unreachable endpoint (exit 6).
	cc := fake.New()
	cc.CallContractFn = func(_ context.Context, _ ethereum.CallMsg, _ *big.Int) ([]byte, error) {
		return nil, errString("execution reverted")
	}
	svc := openWithProvider(t, &stubProvider{cc: cc})

	_, err := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: someAddr(0x20).Hex(), Name: "nope", Network: "mainnet",
	})
	if err == nil {
		t.Fatal("adding a contract that reverts supportsInterface must be rejected (usage.not_nft)")
	}
	de := domain.AsError(err)
	if de.Code != "usage.not_nft" {
		t.Fatalf("code = %q, want usage.not_nft (a revert is not-an-NFT, not unreachable)", de.Code)
	}
	if de.Exit != domain.ExitUsage {
		t.Errorf("exit = %d, want 2 (usage)", de.Exit)
	}
}

func TestNFTAdd_TransportErrorStaysRetryable(t *testing.T) {
	// A GENUINE transport failure (not a revert) during detection must NOT be
	// mislabeled not_nft — it stays rpc.unreachable (exit 6, retryable).
	cc := fake.New()
	cc.Err = errString("dial tcp 127.0.0.1:1: connect: connection refused")
	svc := openWithProvider(t, &stubProvider{cc: cc})

	_, err := svc.NFTAdd(context.Background(), domain.LocalCLI(), domain.NFTAddRequest{
		Contract: someAddr(0x20).Hex(), Name: "nope", Network: "mainnet",
	})
	if err == nil {
		t.Fatal("a transport failure during detection must surface an error")
	}
	if de := domain.AsError(err); de.Code != domain.CodeRPCUnreachable {
		t.Fatalf("code = %q, want rpc.unreachable (a transport failure is retryable, not not_nft)", de.Code)
	}
}

func TestResolveNFT_UnregisteredAliasIsNotFound_NoChainCall(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: fake.New()})
	cc := fake.New()

	// An unregistered collection alias MUST be ref.not_found — NEVER an on-chain
	// name() lookup (the anti-spoofing wall applied to collections). No CallContract.
	_, err := svc.resolveNFT(context.Background(), cc, "mainnet", "ghost#1")
	if err == nil {
		t.Fatal("resolveNFT of an unregistered collection alias must error (ref.not_found)")
	}
	if de := domain.AsError(err); de.Code != domain.CodeRefNotFound {
		t.Fatalf("code = %q, want ref.not_found", de.Code)
	}
	for _, call := range cc.Calls {
		if call.Method == "CallContract" {
			t.Fatalf("resolveNFT did an on-chain CallContract for an unregistered alias — anti-spoofing wall breached")
		}
	}
}

func TestResolveNFT_RawCollectionAndBigTokenID(t *testing.T) {
	cc := nftFake("erc721", someAddr(0xaa), nil, "PUNK")
	svc := openWithProvider(t, &stubProvider{cc: cc})
	contract := someAddr(0x71)

	// A 2^200 token id must round-trip as a decimal STRING (never an int64/float).
	bigID := new(big.Int).Lsh(big.NewInt(1), 200) // 2^200, far beyond 2^53
	ref := contract.Hex() + "#" + bigID.String()

	rn, err := svc.resolveNFT(context.Background(), cc, "mainnet", ref)
	if err != nil {
		t.Fatalf("resolveNFT raw 0x#bigID: %v", err)
	}
	if rn.collection != contract {
		t.Errorf("collection = %s, want %s", rn.collection.Hex(), contract.Hex())
	}
	if rn.tokenID != bigID.String() {
		t.Fatalf("token id = %q, want %q (decimal string, magnitude-safe)", rn.tokenID, bigID.String())
	}
	// kind was empty for the raw unregistered collection ⇒ service detected it once.
	if rn.kind != "erc721" {
		t.Errorf("detected kind for raw collection = %q, want erc721", rn.kind)
	}
}

func TestSendNFT_721_CalldataAndPolicyDest(t *testing.T) {
	from := someAddr(0x01)
	recipient := someAddr(0x0a)
	contract := someAddr(0x71)

	svc, f, _ := sendService(t, from)
	cs := &captureSigner{fakeSigner: fakeSigner{addr: from}}
	svc.signer = cs
	f.CallContractFn = nftFake("erc721", from, nil, "PUNK").CallContractFn
	f.SendRawFn = func(_ context.Context, _ []byte) (common.Hash, error) { return common.HexToHash("0xabc"), nil }

	// Register the collection so the alias resolves registry-only.
	if _, err := svc.NFTAdd(context.Background(), domain.LocalCLI(),
		domain.NFTAddRequest{Contract: contract.Hex(), Name: "punks", Network: "mainnet"}); err != nil {
		t.Fatalf("NFTAdd: %v", err)
	}

	if _, err := svc.SendNFT(context.Background(), domain.LocalCLI(), domain.NFTSendRequest{
		NFT: "punks#42", To: recipient.Hex(), From: from.Hex(), Network: "mainnet", Yes: true,
	}, nil); err != nil {
		t.Fatalf("SendNFT 721: %v", err)
	}

	tx := cs.lastTx
	if tx == nil {
		t.Fatal("no tx was signed")
	}
	// The tx target is the COLLECTION contract (not the recipient).
	if tx.To() == nil || *tx.To() != contract {
		t.Fatalf("tx To = %v, want the collection %s", tx.To(), contract.Hex())
	}
	if tx.Value().Sign() != 0 {
		t.Errorf("tx value = %s, want 0 (NFT transfer carries no ETH)", tx.Value())
	}
	// The calldata is safeTransferFrom(from, to, 42): selector 0x42842e0e || from ||
	// to || tokenId — byte-for-byte the ERC-721 standard.
	data := tx.Data()
	if len(data) != 4+32*3 {
		t.Fatalf("721 calldata len = %d, want 100 (selector + 3 words)", len(data))
	}
	wantSel := []byte{0x42, 0x84, 0x2e, 0x0e}
	if !bytesEq(data[:4], wantSel) {
		t.Fatalf("721 selector = %x, want 42842e0e", data[:4])
	}
	if common.BytesToAddress(data[4:36]) != from {
		t.Errorf("721 calldata from = %s, want %s", common.BytesToAddress(data[4:36]).Hex(), from.Hex())
	}
	if common.BytesToAddress(data[36:68]) != recipient {
		t.Errorf("721 calldata to = %s, want %s", common.BytesToAddress(data[36:68]).Hex(), recipient.Hex())
	}
	if got := new(big.Int).SetBytes(data[68:100]); got.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("721 calldata tokenId = %s, want 42", got)
	}
}

func TestSendNFT_PolicyDestIsRecipientNotCollection(t *testing.T) {
	from := someAddr(0x01)
	recipient := someAddr(0x0a)
	contract := someAddr(0x71)

	svc, f, _ := sendService(t, from)
	f.CallContractFn = nftFake("erc721", from, nil, "PUNK").CallContractFn
	if _, err := svc.NFTAdd(context.Background(), domain.LocalCLI(),
		domain.NFTAddRequest{Contract: contract.Hex(), Name: "punks", Network: "mainnet"}); err != nil {
		t.Fatalf("NFTAdd: %v", err)
	}

	in, err := svc.resolveNFTSendIntent(context.Background(), domain.LocalCLI(), domain.NFTSendRequest{
		NFT: "punks#7", To: recipient.Hex(), From: from.Hex(), Network: "mainnet",
	}, nil)
	if err != nil {
		t.Fatalf("resolveNFTSendIntent: %v", err)
	}
	defer in.cc.Close()

	// The policy subject is the RECIPIENT, never the collection contract.
	if in.checkDest() != recipient {
		t.Fatalf("policy dest = %s, want the recipient %s (NOT the collection)", in.checkDest().Hex(), recipient.Hex())
	}
	if in.checkDest() == contract {
		t.Fatal("policy dest is the collection contract — the recipient-as-dest invariant is broken")
	}
	if in.to != contract {
		t.Errorf("tx to = %s, want the collection %s", in.to.Hex(), contract.Hex())
	}
	// An NFT send is a token-class op: the asset tag is the collection (not "eth") so
	// the §4.3 fail-closed-no-allowlist gate fires.
	if in.checkAsset() == "eth" {
		t.Errorf("NFT send asset tag = eth, want the collection (so stage-3c fires; ETH exempt, NFT NOT)")
	}
	if in.kind != journal.KindERC721Transfer {
		t.Errorf("kind = %q, want erc721-transfer", in.kind)
	}
	// effectiveKind defaults the journal kind string to KindTransfer (the policy
	// engine maps it), so the policy check kind is the journal string.
	if in.policyCheckKind() != string(journal.KindERC721Transfer) {
		t.Errorf("policy check kind = %q, want %q", in.policyCheckKind(), journal.KindERC721Transfer)
	}
}

func TestSendNFT_1155_CalldataAndAmount(t *testing.T) {
	from := someAddr(0x01)
	recipient := someAddr(0x0a)
	contract := someAddr(0x55)

	svc, f, _ := sendService(t, from)
	cs := &captureSigner{fakeSigner: fakeSigner{addr: from}}
	svc.signer = cs
	f.CallContractFn = nftFake("erc1155", common.Address{}, big.NewInt(100), "ITEMS").CallContractFn
	f.SendRawFn = func(_ context.Context, _ []byte) (common.Hash, error) { return common.HexToHash("0xabc"), nil }

	if _, err := svc.NFTAdd(context.Background(), domain.LocalCLI(),
		domain.NFTAddRequest{Contract: contract.Hex(), Name: "items", Network: "mainnet"}); err != nil {
		t.Fatalf("NFTAdd: %v", err)
	}

	if _, err := svc.SendNFT(context.Background(), domain.LocalCLI(), domain.NFTSendRequest{
		NFT: "items#9", To: recipient.Hex(), Amount: "5", From: from.Hex(), Network: "mainnet", Yes: true,
	}, nil); err != nil {
		t.Fatalf("SendNFT 1155: %v", err)
	}

	data := cs.lastTx.Data()
	// safeTransferFrom(from,to,id,amount,bytes): selector 0xf242432a || from || to ||
	// id || amount || offset(0xa0) || len(0) — 4 + 6*32 = 196 bytes.
	if len(data) != 4+32*6 {
		t.Fatalf("1155 calldata len = %d, want 196 (selector + 6 words)", len(data))
	}
	wantSel := []byte{0xf2, 0x42, 0x43, 0x2a}
	if !bytesEq(data[:4], wantSel) {
		t.Fatalf("1155 selector = %x, want f242432a", data[:4])
	}
	if common.BytesToAddress(data[4:36]) != from {
		t.Errorf("1155 from = %s, want %s", common.BytesToAddress(data[4:36]).Hex(), from.Hex())
	}
	if common.BytesToAddress(data[36:68]) != recipient {
		t.Errorf("1155 to = %s, want %s", common.BytesToAddress(data[36:68]).Hex(), recipient.Hex())
	}
	if got := new(big.Int).SetBytes(data[68:100]); got.Cmp(big.NewInt(9)) != 0 {
		t.Errorf("1155 id = %s, want 9", got)
	}
	if got := new(big.Int).SetBytes(data[100:132]); got.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("1155 amount = %s, want 5 (raw unit count, NOT decimals-scaled)", got)
	}
	// The dynamic bytes tail: offset word = 0xa0, length word = 0 (empty data).
	if got := new(big.Int).SetBytes(data[132:164]); got.Cmp(big.NewInt(0xa0)) != 0 {
		t.Errorf("1155 bytes offset = %s, want 0xa0", got)
	}
	if got := new(big.Int).SetBytes(data[164:196]); got.Sign() != 0 {
		t.Errorf("1155 bytes length = %s, want 0 (empty data)", got)
	}
}

func TestSendNFT_721_RejectsAmountAboveOne(t *testing.T) {
	from := someAddr(0x01)
	contract := someAddr(0x71)
	svc, f, _ := sendService(t, from)
	f.CallContractFn = nftFake("erc721", from, nil, "PUNK").CallContractFn
	if _, err := svc.NFTAdd(context.Background(), domain.LocalCLI(),
		domain.NFTAddRequest{Contract: contract.Hex(), Name: "punks", Network: "mainnet"}); err != nil {
		t.Fatalf("NFTAdd: %v", err)
	}
	_, err := svc.SendNFT(context.Background(), domain.LocalCLI(), domain.NFTSendRequest{
		NFT: "punks#1", To: someAddr(0x0a).Hex(), Amount: "3", From: from.Hex(), Network: "mainnet", Yes: true,
	}, nil)
	if err == nil {
		t.Fatal("a 721 send with --amount > 1 must be rejected (usage.bad_amount)")
	}
	if de := domain.AsError(err); de.Code != "usage.bad_amount" {
		t.Fatalf("code = %q, want usage.bad_amount", de.Code)
	}
}

// TestSendNFT_FailClosedNoAllowlistDenied: an NFT send with limits set but no
// allowlist is refused fail-closed (policy.denied.no_allowlist, exit 3) — ETH
// exempt, NFT NOT (the §4.3 stage-3c rule), through the REAL engine.
func TestSendNFT_FailClosedNoAllowlistDenied(t *testing.T) {
	from := someAddr(0x01)
	recipient := someAddr(0x0a)
	contract := someAddr(0x71)

	svc, f, _ := sendService(t, from)
	f.CallContractFn = nftFake("erc721", from, nil, "PUNK").CallContractFn
	if _, err := svc.NFTAdd(context.Background(), domain.LocalCLI(),
		domain.NFTAddRequest{Contract: contract.Hex(), Name: "punks", Network: "mainnet"}); err != nil {
		t.Fatalf("NFTAdd: %v", err)
	}
	// Limits configured but allowlist OFF ⇒ stage-3c fail-closed for the NFT transfer.
	sealPolicy(t, svc, policy.Change{
		Default:   &policy.Limits{MaxTxWei: sptr("1000000000000000000"), AllowlistEnabled: boolPtr(false)},
		WrittenBy: "test",
	})

	_, err := svc.SendNFT(context.Background(), domain.LocalCLI(), domain.NFTSendRequest{
		NFT: "punks#1", To: recipient.Hex(), From: from.Hex(), Network: "mainnet", Yes: true,
	}, nil)
	if err == nil {
		t.Fatal("an NFT send with limits set but no allowlist must fail closed (ETH exempt, NFT NOT)")
	}
	de := domain.AsError(err)
	if de.Code != "policy.denied.no_allowlist" {
		t.Fatalf("code = %q, want policy.denied.no_allowlist", de.Code)
	}
	if de.Exit != domain.ExitPolicyDenied {
		t.Errorf("exit = %d, want 3 (POLICY_DENIED)", de.Exit)
	}
}

// TestSendNFT_AllowlistedRecipientPasses: with limits + an allowlist that pins the
// RECIPIENT (not the collection), the NFT send is authorized — proving the policy
// subject is the recipient. It is a dry-run so no signing/broadcast machinery runs.
func TestSendNFT_AllowlistedRecipientPasses(t *testing.T) {
	from := someAddr(0x01)
	recipient := someAddr(0x0a)
	contract := someAddr(0x71)

	svc, f, _ := sendService(t, from)
	f.CallContractFn = nftFake("erc721", from, nil, "PUNK").CallContractFn
	if _, err := svc.NFTAdd(context.Background(), domain.LocalCLI(),
		domain.NFTAddRequest{Contract: contract.Hex(), Name: "punks", Network: "mainnet"}); err != nil {
		t.Fatalf("NFTAdd: %v", err)
	}
	sealPolicy(t, svc, policy.Change{
		Default: &policy.Limits{
			MaxTxWei: sptr("1000000000000000000"), MaxDayWei: sptr("10000000000000000000"),
			AllowlistEnabled: boolPtr(true),
		},
		WrittenBy: "test",
	})
	// Pin the RECIPIENT (pinning the collection would NOT let this through).
	allowSpender(t, svc, recipient)

	// A dry-run runs the full policy verdict (no reservation) — it must be allowed.
	res, err := svc.SendNFT(context.Background(), domain.LocalCLI(), domain.NFTSendRequest{
		NFT: "punks#1", To: recipient.Hex(), From: from.Hex(), Network: "mainnet", DryRun: true, Yes: true,
	}, nil)
	if err != nil {
		t.Fatalf("allowlisted (recipient-pinned) NFT send dry-run denied: %v", err)
	}
	if !res.DryRun {
		t.Errorf("expected a dry-run result")
	}
}
