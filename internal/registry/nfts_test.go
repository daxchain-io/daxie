package registry

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

func newNFTs(t *testing.T) (*NFTs, string) {
	t.Helper()
	dir := t.TempDir()
	n, err := OpenNFTs(dir)
	if err != nil {
		t.Fatalf("OpenNFTs: %v", err)
	}
	return n, dir
}

var (
	addrPunks   = common.HexToAddress("0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb")
	addrGame    = common.HexToAddress("0x495f947276749ce646f68ac8c248420045cb7b5e")
	addrUnknown = common.HexToAddress("0x9999999999999999999999999999999999999999")
)

func col721(alias string, addr common.Address) Collection {
	return Collection{Alias: alias, Address: addr, Kind: KindERC721}
}

// assertCode asserts err is a *domain.Error with the given code.
func assertNFTCode(t *testing.T, err error, code string) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error %v is not a *domain.Error", err)
	}
	if de.Code != code {
		t.Fatalf("error code = %q, want %q (%v)", de.Code, code, err)
	}
}

// ── collections CRUD ─────────────────────────────────────────────────────────

func TestAddCollectionRoundTrip(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)

	if err := n.AddCollection(ctx, "mainnet", col721("punks", addrPunks)); err != nil {
		t.Fatalf("AddCollection: %v", err)
	}

	got, found, err := n.ResolveCollection(ctx, "mainnet", "punks")
	if err != nil || !found {
		t.Fatalf("ResolveCollection: found=%v err=%v", found, err)
	}
	if got.Address != addrPunks || got.Kind != KindERC721 || got.Alias != "punks" {
		t.Fatalf("resolved wrong: %+v", got)
	}

	list, err := n.ListCollections(ctx, "mainnet")
	if err != nil {
		t.Fatalf("ListCollections: %v", err)
	}
	if len(list) != 1 || list[0].Alias != "punks" {
		t.Fatalf("ListCollections = %+v, want [punks]", list)
	}

	if err := n.RemoveCollection(ctx, "mainnet", "punks"); err != nil {
		t.Fatalf("RemoveCollection: %v", err)
	}
	_, found, _ = n.ResolveCollection(ctx, "mainnet", "punks")
	if found {
		t.Fatal("collection still resolves after RemoveCollection")
	}
}

func TestAddCollection1155Kind(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	if err := n.AddCollection(ctx, "mainnet", Collection{Alias: "game", Address: addrGame, Kind: KindERC1155}); err != nil {
		t.Fatalf("AddCollection 1155: %v", err)
	}
	got, found, _ := n.ResolveCollection(ctx, "mainnet", "game")
	if !found || got.Kind != KindERC1155 {
		t.Fatalf("1155 kind not stored: %+v found=%v", got, found)
	}
}

func TestAddCollectionRejectsBadKind(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	// erc20 (or anything not 721/1155) must be rejected — the registry validates the
	// kind it was handed (service detected it via ERC-165).
	err := n.AddCollection(ctx, "mainnet", Collection{Alias: "bad", Address: addrPunks, Kind: KindERC20})
	if err == nil {
		t.Fatal("AddCollection(erc20 kind) must be rejected")
	}
	assertNFTCode(t, err, CodeUsageBadKind)

	err = n.AddCollection(ctx, "mainnet", Collection{Alias: "bad", Address: addrPunks, Kind: ""})
	if err == nil {
		t.Fatal("AddCollection(empty kind) must be rejected")
	}
	assertNFTCode(t, err, CodeUsageBadKind)
}

func TestAddCollectionRejectsBadAlias(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	// An address-shaped alias is rejected by the §3.1 grammar (canonicalName).
	err := n.AddCollection(ctx, "mainnet", col721(addrPunks.Hex(), addrPunks))
	if err == nil {
		t.Fatal("AddCollection with an address-shaped alias must be rejected")
	}
	assertNFTCode(t, err, domain.CodeUsage+".bad_name")
}

// ── case-fold ────────────────────────────────────────────────────────────────

func TestCollectionCaseFold(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	if err := n.AddCollection(ctx, "mainnet", col721("Punks", addrPunks)); err != nil {
		t.Fatalf("AddCollection: %v", err)
	}
	// Stored lowercase; resolved case-insensitively.
	for _, q := range []string{"punks", "PUNKS", "PuNkS"} {
		got, found, err := n.ResolveCollection(ctx, "mainnet", q)
		if err != nil || !found {
			t.Fatalf("ResolveCollection(%q): found=%v err=%v", q, found, err)
		}
		if got.Alias != "punks" {
			t.Fatalf("stored alias = %q, want lowercase punks", got.Alias)
		}
	}
}

// ── collision-requires-name ──────────────────────────────────────────────────

func TestCollectionCollisionRequiresName(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	if err := n.AddCollection(ctx, "mainnet", col721("punks", addrPunks)); err != nil {
		t.Fatalf("AddCollection: %v", err)
	}
	// Same alias (case-insensitive) → usage.duplicate (instructing --name).
	err := n.AddCollection(ctx, "mainnet", col721("PUNKS", addrGame))
	if err == nil {
		t.Fatal("duplicate collection alias must be rejected")
	}
	assertNFTCode(t, err, CodeUsageDuplicate)
}

func TestNFTAliasCollisionRequiresName(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	mustAddCol(t, n, "mainnet", col721("punks", addrPunks))
	if err := n.AliasNFT(ctx, "mainnet", "my-punk", "punks", "42"); err != nil {
		t.Fatalf("AliasNFT: %v", err)
	}
	err := n.AliasNFT(ctx, "mainnet", "MY-PUNK", "punks", "43")
	if err == nil {
		t.Fatal("duplicate nft alias must be rejected")
	}
	assertNFTCode(t, err, CodeUsageDuplicate)
}

// ── per-network isolation ────────────────────────────────────────────────────

func TestCollectionPerNetworkIsolation(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	// Same alias, different address per network — they do not collide.
	if err := n.AddCollection(ctx, "mainnet", col721("punks", addrPunks)); err != nil {
		t.Fatalf("AddCollection mainnet: %v", err)
	}
	if err := n.AddCollection(ctx, "sepolia", col721("punks", addrGame)); err != nil {
		t.Fatalf("AddCollection sepolia: %v", err)
	}
	m, _, _ := n.ResolveCollection(ctx, "mainnet", "punks")
	s, _, _ := n.ResolveCollection(ctx, "sepolia", "punks")
	if m.Address != addrPunks {
		t.Fatalf("mainnet punks = %s, want %s", m.Address, addrPunks)
	}
	if s.Address != addrGame {
		t.Fatalf("sepolia punks = %s, want %s", s.Address, addrGame)
	}
	// A collection on mainnet does not appear on a third network.
	if _, found, _ := n.ResolveCollection(ctx, "polygon", "punks"); found {
		t.Fatal("punks must not resolve on polygon")
	}
}

// ── registry-only resolution (a miss is found=false / ref.not_found, never on-chain) ──

func TestResolveCollectionMissIsCleanFalse(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	// An unknown alias resolves found=false with a nil error — NEVER an on-chain
	// name()/symbol() lookup (the anti-spoofing wall). The store holds no chain.
	got, found, err := n.ResolveCollection(ctx, "mainnet", "ghost")
	if err != nil {
		t.Fatalf("ResolveCollection(ghost) err = %v, want nil", err)
	}
	if found {
		t.Fatalf("ResolveCollection(ghost) found=true, want false; got %+v", got)
	}
}

func TestResolveCollectionBadAliasIsCleanMiss(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	// A non-grammar alias is a clean miss (found=false, nil err) so a caller can fall
	// through to a raw-0x branch.
	_, found, err := n.ResolveCollection(ctx, "mainnet", "not a name!")
	if err != nil || found {
		t.Fatalf("ResolveCollection(bad alias) = found=%v err=%v, want false/nil", found, err)
	}
}

// ── individual-NFT aliasing ──────────────────────────────────────────────────

func TestAliasNFTRoundTrip(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	mustAddCol(t, n, "mainnet", col721("punks", addrPunks))
	if err := n.AliasNFT(ctx, "mainnet", "my-punk", "punks", "42"); err != nil {
		t.Fatalf("AliasNFT: %v", err)
	}

	// Bare-alias resolution chases the collection alias → {address,kind}.
	rn, err := n.ResolveNFT(ctx, "mainnet", "my-punk")
	if err != nil {
		t.Fatalf("ResolveNFT(my-punk): %v", err)
	}
	if rn.Collection != addrPunks || rn.Kind != KindERC721 || rn.TokenID != "42" {
		t.Fatalf("ResolveNFT(my-punk) = %+v, want punks/erc721/42", rn)
	}
	if rn.CollectionAlias != "punks" || rn.NFTAlias != "my-punk" {
		t.Fatalf("ResolveNFT aliases = col=%q nft=%q, want punks/my-punk", rn.CollectionAlias, rn.NFTAlias)
	}

	list, err := n.ListNFTAliases(ctx, "mainnet")
	if err != nil {
		t.Fatalf("ListNFTAliases: %v", err)
	}
	if len(list) != 1 || list[0].Alias != "my-punk" || list[0].TokenID != "42" {
		t.Fatalf("ListNFTAliases = %+v, want [my-punk #42]", list)
	}

	if err := n.RemoveNFTAlias(ctx, "mainnet", "my-punk"); err != nil {
		t.Fatalf("RemoveNFTAlias: %v", err)
	}
	if _, err := n.ResolveNFT(ctx, "mainnet", "my-punk"); err == nil {
		t.Fatal("nft alias still resolves after RemoveNFTAlias")
	}
}

func TestAliasNFTRequiresExistingCollection(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	// No collection registered → an nft alias cannot bind → ref.not_found.
	err := n.AliasNFT(ctx, "mainnet", "my-punk", "punks", "42")
	if err == nil {
		t.Fatal("AliasNFT against an unknown collection must be rejected")
	}
	assertNFTCode(t, err, domain.CodeRefNotFound)
}

func TestAliasNFTRejectsBadTokenID(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	mustAddCol(t, n, "mainnet", col721("punks", addrPunks))
	for _, bad := range []string{"", "-1", "0x2a", "4.2", "forty-two", "1e3"} {
		err := n.AliasNFT(ctx, "mainnet", "x", "punks", bad)
		if err == nil {
			t.Fatalf("AliasNFT token id %q must be rejected", bad)
		}
		assertNFTCode(t, err, CodeUsageBadTokenID)
	}
}

// ── the collection#id ref: raw + by-collection-alias ─────────────────────────

func TestResolveNFTByCollectionAlias(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	mustAddCol(t, n, "mainnet", col721("punks", addrPunks))

	rn, err := n.ResolveNFT(ctx, "mainnet", "punks#42")
	if err != nil {
		t.Fatalf("ResolveNFT(punks#42): %v", err)
	}
	if rn.Collection != addrPunks || rn.Kind != KindERC721 || rn.TokenID != "42" {
		t.Fatalf("ResolveNFT(punks#42) = %+v, want punks/erc721/42", rn)
	}
	if rn.CollectionAlias != "punks" || rn.NFTAlias != "" {
		t.Fatalf("aliases = col=%q nft=%q, want punks/\"\"", rn.CollectionAlias, rn.NFTAlias)
	}
	// Case-insensitive collection alias.
	if rn, err := n.ResolveNFT(ctx, "mainnet", "PUNKS#42"); err != nil || rn.Collection != addrPunks {
		t.Fatalf("ResolveNFT(PUNKS#42) = %+v err=%v", rn, err)
	}
}

func TestResolveNFTRawAddressAlwaysAllowed(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	// A raw 0x collection is always resolvable (like a raw --token), even with NO
	// registered collection — kind is "" (service detects it once for display).
	rn, err := n.ResolveNFT(ctx, "mainnet", addrUnknown.Hex()+"#7")
	if err != nil {
		t.Fatalf("ResolveNFT(raw#7): %v", err)
	}
	if rn.Collection != addrUnknown || rn.Kind != "" || rn.TokenID != "7" {
		t.Fatalf("ResolveNFT(raw#7) = %+v, want unknown/\"\"/7", rn)
	}
	if rn.CollectionAlias != "" {
		t.Fatalf("raw collection must have no alias, got %q", rn.CollectionAlias)
	}
}

func TestResolveNFTRawAddressSurfacesRegisteredKind(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	mustAddCol(t, n, "mainnet", col721("punks", addrPunks))
	// The raw form of a REGISTERED collection surfaces its stored kind + alias.
	rn, err := n.ResolveNFT(ctx, "mainnet", addrPunks.Hex()+"#9")
	if err != nil {
		t.Fatalf("ResolveNFT(rawPunks#9): %v", err)
	}
	if rn.Kind != KindERC721 || rn.CollectionAlias != "punks" {
		t.Fatalf("raw registered collection = %+v, want kind erc721 + alias punks", rn)
	}
}

func TestResolveNFTUnknownCollectionAliasIsRefNotFound(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	// An unknown collection ALIAS (not 0x) → ref.not_found — NEVER an on-chain
	// name() lookup (the anti-spoofing wall, applied to collections).
	_, err := n.ResolveNFT(ctx, "mainnet", "ghost#1")
	if err == nil {
		t.Fatal("ResolveNFT(ghost#1) must error (unknown collection alias)")
	}
	assertNFTCode(t, err, domain.CodeRefNotFound)
}

func TestResolveNFTUnknownBareAliasIsRefNotFound(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	_, err := n.ResolveNFT(ctx, "mainnet", "no-such-nft")
	if err == nil {
		t.Fatal("ResolveNFT(no-such-nft) must error")
	}
	assertNFTCode(t, err, domain.CodeRefNotFound)
}

func TestResolveNFTBadTokenID(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	mustAddCol(t, n, "mainnet", col721("punks", addrPunks))
	_, err := n.ResolveNFT(ctx, "mainnet", "punks#notanumber")
	if err == nil {
		t.Fatal("ResolveNFT(punks#notanumber) must error")
	}
	assertNFTCode(t, err, CodeUsageBadTokenID)
}

func TestResolveNFTEmptyRefBadNFTRef(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	_, err := n.ResolveNFT(ctx, "mainnet", "   ")
	if err == nil {
		t.Fatal("ResolveNFT(empty) must error")
	}
	assertNFTCode(t, err, CodeUsageBadNFTRef)
}

// ── token_id is a DECIMAL STRING (math/big; never int64/float) ────────────────

func TestTokenIDBigDecimalStringRoundTrip(t *testing.T) {
	ctx := context.Background()
	n, dir := newNFTs(t)
	mustAddCol(t, n, "mainnet", col721("punks", addrPunks))

	// 2^200 — far beyond int64/float53 — must round-trip intact as a decimal string.
	const big2pow200 = "1606938044258990275541962092341162602522202993782792835301376"
	if err := n.AliasNFT(ctx, "mainnet", "huge", "punks", big2pow200); err != nil {
		t.Fatalf("AliasNFT(2^200): %v", err)
	}
	rn, err := n.ResolveNFT(ctx, "mainnet", "huge")
	if err != nil {
		t.Fatalf("ResolveNFT(huge): %v", err)
	}
	if rn.TokenID != big2pow200 {
		t.Fatalf("token id round-trip = %q, want %q", rn.TokenID, big2pow200)
	}

	// And via the collection#id form.
	rn2, err := n.ResolveNFT(ctx, "mainnet", "punks#"+big2pow200)
	if err != nil {
		t.Fatalf("ResolveNFT(punks#2^200): %v", err)
	}
	if rn2.TokenID != big2pow200 {
		t.Fatalf("collection#id token id = %q, want %q", rn2.TokenID, big2pow200)
	}

	// On disk the token_id must be a JSON STRING, not a number.
	b, err := os.ReadFile(filepath.Join(dir, "mainnet.json"))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var raw struct {
		NFTAliases []struct {
			TokenID json.RawMessage `json:"token_id"`
		} `json:"nft_aliases"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(raw.NFTAliases) != 1 {
		t.Fatalf("expected 1 nft alias on disk, got %d", len(raw.NFTAliases))
	}
	if got := string(raw.NFTAliases[0].TokenID); got != `"`+big2pow200+`"` {
		t.Fatalf("on-disk token_id = %s, want a quoted string %q", got, big2pow200)
	}
}

func TestTokenIDCanonicalizesLeadingZeros(t *testing.T) {
	ctx := context.Background()
	n, _ := newNFTs(t)
	mustAddCol(t, n, "mainnet", col721("punks", addrPunks))
	if err := n.AliasNFT(ctx, "mainnet", "z", "punks", "007"); err != nil {
		t.Fatalf("AliasNFT(007): %v", err)
	}
	rn, _ := n.ResolveNFT(ctx, "mainnet", "z")
	if rn.TokenID != "7" {
		t.Fatalf("token id = %q, want canonical 7", rn.TokenID)
	}
}

// ── shared envelope: collections/nft_aliases co-exist with tokens, one file ───

func TestNFTAndTokensShareOneEnvelope(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tk, _ := OpenTokens(dir)
	n, _ := OpenNFTs(dir)

	if err := tk.Add(ctx, "mainnet", erc20("mytoken", addrMyToken, 18, "MTK")); err != nil {
		t.Fatalf("Tokens.Add: %v", err)
	}
	if err := n.AddCollection(ctx, "mainnet", col721("punks", addrPunks)); err != nil {
		t.Fatalf("AddCollection: %v", err)
	}
	if err := n.AliasNFT(ctx, "mainnet", "my-punk", "punks", "42"); err != nil {
		t.Fatalf("AliasNFT: %v", err)
	}

	// Adding the collection (a save of the whole envelope) must NOT clobber the token.
	got, found, err := tk.Resolve(ctx, "mainnet", "mytoken")
	if err != nil || !found || got.Address != addrMyToken {
		t.Fatalf("token lost after NFT writes: found=%v err=%v got=%+v", found, err, got)
	}
	// And the collection + nft alias survive a token write.
	if err := tk.Add(ctx, "mainnet", erc20("two", addrMyToken2, 6, "TWO")); err != nil {
		t.Fatalf("Tokens.Add two: %v", err)
	}
	if _, found, _ := n.ResolveCollection(ctx, "mainnet", "punks"); !found {
		t.Fatal("collection lost after a token write")
	}
	if _, err := n.ResolveNFT(ctx, "mainnet", "my-punk"); err != nil {
		t.Fatalf("nft alias lost after a token write: %v", err)
	}

	// One file holds all three arrays.
	b, err := os.ReadFile(filepath.Join(dir, "mainnet.json"))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	var f tokensFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(f.Tokens) != 2 || len(f.Collections) != 1 || len(f.NFTAliases) != 1 {
		t.Fatalf("envelope = %d tokens / %d collections / %d nft_aliases, want 2/1/1", len(f.Tokens), len(f.Collections), len(f.NFTAliases))
	}
}

// mustAddCol adds a collection or fails the test.
func mustAddCol(t *testing.T, n *NFTs, network string, col Collection) {
	t.Helper()
	if err := n.AddCollection(context.Background(), network, col); err != nil {
		t.Fatalf("AddCollection(%s): %v", col.Alias, err)
	}
}
