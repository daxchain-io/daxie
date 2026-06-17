package registry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

func newTokens(t *testing.T) (*Tokens, string) {
	t.Helper()
	dir := t.TempDir()
	tk, err := OpenTokens(dir)
	if err != nil {
		t.Fatalf("OpenTokens: %v", err)
	}
	return tk, dir
}

var (
	addrMyToken  = common.HexToAddress("0x1111111111111111111111111111111111111111")
	addrMyToken2 = common.HexToAddress("0x2222222222222222222222222222222222222222")
	addrCustomUS = common.HexToAddress("0x3333333333333333333333333333333333333333")
)

func erc20(alias string, addr common.Address, decimals uint8, symbol string) Token {
	return Token{Alias: alias, Address: addr, Kind: KindERC20, Decimals: decimals, Symbol: symbol}
}

// TestAddListRemoveRoundTrip walks the token CRUD lifecycle and confirms a file entry
// resolves with Bundled=false.
func TestAddListRemoveRoundTrip(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)

	if err := tk.Add(ctx, "mainnet", erc20("mytoken", addrMyToken, 18, "MTK")); err != nil {
		t.Fatalf("Add mytoken: %v", err)
	}

	got, found, err := tk.Resolve(ctx, "mainnet", "mytoken")
	if err != nil || !found {
		t.Fatalf("Resolve mytoken: found=%v err=%v", found, err)
	}
	if got.Bundled {
		t.Fatalf("file entry must have Bundled=false")
	}
	if got.Address != addrMyToken || got.Decimals != 18 || got.Kind != KindERC20 {
		t.Fatalf("resolved wrong: %+v", got)
	}

	// List shows the file entry plus the four bundled majors (alias-sorted).
	list, err := tk.List(ctx, "mainnet")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	// mainnet bundles 4 majors + 1 file entry = 5.
	if len(list) != 5 {
		t.Fatalf("List len = %d, want 5 (4 bundled + 1 file): %+v", len(list), list)
	}
	// alias-sorted
	for i := 1; i < len(list); i++ {
		if list[i-1].Alias > list[i].Alias {
			t.Fatalf("List not alias-sorted: %+v", list)
		}
	}

	if err := tk.Remove(ctx, "mainnet", "mytoken"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, found, _ := tk.Resolve(ctx, "mainnet", "mytoken"); found {
		t.Fatalf("mytoken still resolves after Remove")
	}
	// Remove of a missing alias is ref.not_found.
	if err := tk.Remove(ctx, "mainnet", "mytoken"); !isCode(err, domain.CodeRefNotFound) {
		t.Fatalf("Remove missing: want ref.not_found, got %v", err)
	}
}

// TestResolveCaseInsensitive confirms aliases are stored lowercase and matched
// case-insensitively (the §3.1 + §7.8 case-fold property).
func TestResolveCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)

	if err := tk.Add(ctx, "mainnet", erc20("MyToken", addrMyToken, 18, "MTK")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	for _, in := range []string{"mytoken", "MYTOKEN", "MyToken", "mYtOkEn"} {
		got, found, err := tk.Resolve(ctx, "mainnet", in)
		if err != nil || !found {
			t.Fatalf("Resolve(%q): found=%v err=%v", in, found, err)
		}
		if got.Alias != "mytoken" {
			t.Fatalf("stored alias = %q, want canonical lowercase mytoken", got.Alias)
		}
	}
}

// TestResolveMissNeverChainLookup is the core anti-spoofing property: an alias not in
// the file AND not bundled is a MISS (found=false, nil error) — it is NEVER promoted
// to an on-chain symbol() lookup. The store has no chain.Client by construction, so
// the only correct behaviour is a clean miss the caller turns into ref.not_found.
func TestResolveMissNeverChainLookup(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)

	// A plausible token symbol that is NOT registered and NOT bundled.
	got, found, err := tk.Resolve(ctx, "mainnet", "shib")
	if err != nil {
		t.Fatalf("Resolve unknown alias must not error (clean miss): %v", err)
	}
	if found {
		t.Fatalf("unknown alias resolved (must be a miss — no on-chain symbol fallback): %+v", got)
	}
	if got != (ResolvedToken{}) {
		t.Fatalf("miss returned a non-zero token: %+v", got)
	}

	// A non-grammar input is also a clean miss (so a 0x-first caller falls through).
	for _, in := range []string{
		"0x1111111111111111111111111111111111111111", // address literal
		"vitalik.eth", // ENS literal
		"",            // empty
		"has space",   // bad grammar
	} {
		_, found, err := tk.Resolve(ctx, "mainnet", in)
		if err != nil {
			t.Fatalf("Resolve(%q) must fall through cleanly, got err %v", in, err)
		}
		if found {
			t.Fatalf("Resolve(%q) reported found=true", in)
		}
	}
}

// TestPerNetworkIsolation confirms the same alias maps independently per network and
// a token added on mainnet is invisible on sepolia (§7.8 per-network keying).
func TestPerNetworkIsolation(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)

	if err := tk.Add(ctx, "mainnet", erc20("mytoken", addrMyToken, 18, "MTK")); err != nil {
		t.Fatalf("Add mainnet: %v", err)
	}
	if err := tk.Add(ctx, "sepolia", erc20("mytoken", addrMyToken2, 6, "MTK")); err != nil {
		t.Fatalf("Add sepolia: %v", err)
	}

	mn, found, err := tk.Resolve(ctx, "mainnet", "mytoken")
	if err != nil || !found {
		t.Fatalf("Resolve mainnet: found=%v err=%v", found, err)
	}
	sp, found, err := tk.Resolve(ctx, "sepolia", "mytoken")
	if err != nil || !found {
		t.Fatalf("Resolve sepolia: found=%v err=%v", found, err)
	}
	if mn.Address == sp.Address {
		t.Fatalf("per-network isolation broken: same address on both networks")
	}
	if mn.Address != addrMyToken || sp.Address != addrMyToken2 {
		t.Fatalf("wrong per-network addresses: mn=%s sp=%s", mn.Address, sp.Address)
	}

	// A token added only on mainnet does not resolve on a third network.
	if _, found, _ := tk.Resolve(ctx, "holesky", "mytoken"); found {
		t.Fatalf("mytoken leaked to holesky")
	}
}

// TestAddCollisionRequiresName confirms an alias colliding (case-insensitive) with an
// existing FILE entry OR a bundled major is usage.duplicate (the
// collision-requires-an-explicit-name rule, §7.8).
func TestAddCollisionRequiresName(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)

	// Collision with a bundled major (usdc on mainnet).
	err := tk.Add(ctx, "mainnet", erc20("USDC", addrCustomUS, 6, "USDC"))
	if !isCode(err, CodeUsageDuplicate) {
		t.Fatalf("add colliding with bundled major: want usage.duplicate, got %v", err)
	}
	if !isExit(err, domain.ExitUsage) {
		t.Fatalf("usage.duplicate must be exit 2, got %v", err)
	}

	// Collision with a file entry (case-insensitive).
	if err := tk.Add(ctx, "mainnet", erc20("mytoken", addrMyToken, 18, "MTK")); err != nil {
		t.Fatalf("Add mytoken: %v", err)
	}
	err = tk.Add(ctx, "mainnet", erc20("MyToken", addrMyToken2, 18, "MTK2"))
	if !isCode(err, CodeUsageDuplicate) {
		t.Fatalf("add colliding with file entry: want usage.duplicate, got %v", err)
	}

	// The original survives the rejected duplicate.
	got, found, err := tk.Resolve(ctx, "mainnet", "mytoken")
	if err != nil || !found || got.Address != addrMyToken {
		t.Fatalf("original corrupted by rejected duplicate: %+v found=%v err=%v", got, found, err)
	}
}

// TestFileOverridesBundled confirms a file entry with the same alias as a bundled
// major... is rejected at Add (collision-requires-name), but a DIFFERENT alias for a
// custom token coexists; and that a file token written DIRECTLY (bypassing Add's
// guard, as a pre-seeded operator file would) overrides the bundled one in Resolve
// and List (§7.8 "a same-alias file entry overrides the bundled one").
func TestFileOverridesBundled(t *testing.T) {
	ctx := context.Background()
	tk, dir := newTokens(t)

	// Simulate a pre-seeded operator file (init container, §7.8) that aliases "usdc"
	// to a different address than the bundled major. Add() guards against this via
	// collision-requires-name, but a hand-written/pre-seeded file is the override
	// path the spec calls out.
	f := &tokensFile{
		V:       tokensVersion,
		Network: "mainnet",
		Tokens:  []Token{erc20("usdc", addrCustomUS, 6, "USDC-CUSTOM")},
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mainnet.json"), b, 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	// Resolve: the file entry wins over the bundled major.
	got, found, err := tk.Resolve(ctx, "mainnet", "usdc")
	if err != nil || !found {
		t.Fatalf("Resolve usdc: found=%v err=%v", found, err)
	}
	if got.Bundled {
		t.Fatalf("file entry should win: Bundled must be false")
	}
	if got.Address != addrCustomUS {
		t.Fatalf("file override not applied: address = %s, want %s", got.Address, addrCustomUS)
	}

	// List: usdc appears ONCE (the file entry), not duplicated by the bundled major.
	list, err := tk.List(ctx, "mainnet")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	usdcCount := 0
	for _, r := range list {
		if r.Alias == "usdc" {
			usdcCount++
			if r.Bundled {
				t.Fatalf("listed usdc should be the file entry (Bundled=false)")
			}
			if r.Address != addrCustomUS {
				t.Fatalf("listed usdc has wrong address: %s", r.Address)
			}
		}
	}
	if usdcCount != 1 {
		t.Fatalf("usdc appears %d times in List, want exactly 1 (file shadows bundled)", usdcCount)
	}
	// The other three majors still appear (4 bundled - 1 shadowed + 1 file = 4).
	if len(list) != 4 {
		t.Fatalf("List len = %d, want 4 (usdt/weth/dai bundled + usdc file): %+v", len(list), list)
	}
}

// TestRenameFileEntry confirms rename of a file entry, and that renaming a bundled
// major or onto an occupied alias is rejected.
func TestRenameFileEntry(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)

	if err := tk.Add(ctx, "mainnet", erc20("oldname", addrMyToken, 18, "OLD")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := tk.Rename(ctx, "mainnet", "oldname", "newname"); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, found, _ := tk.Resolve(ctx, "mainnet", "oldname"); found {
		t.Fatalf("old alias still resolves after rename")
	}
	got, found, err := tk.Resolve(ctx, "mainnet", "newname")
	if err != nil || !found || got.Address != addrMyToken {
		t.Fatalf("new alias wrong: %+v found=%v err=%v", got, found, err)
	}

	// Renaming a bundled major in place is rejected.
	if err := tk.Rename(ctx, "mainnet", "usdc", "mystable"); !isCode(err, CodeUsageBundledImmutable) {
		t.Fatalf("rename bundled major: want usage.bundled_immutable, got %v", err)
	}

	// Rename onto a bundled alias is a duplicate.
	if err := tk.Rename(ctx, "mainnet", "newname", "usdc"); !isCode(err, CodeUsageDuplicate) {
		t.Fatalf("rename onto bundled alias: want usage.duplicate, got %v", err)
	}

	// Rename of a missing alias is not_found.
	if err := tk.Rename(ctx, "mainnet", "ghost", "spook"); !isCode(err, domain.CodeRefNotFound) {
		t.Fatalf("rename missing: want ref.not_found, got %v", err)
	}
}

// TestRemoveBundledRejected confirms a bundled major cannot be removed.
func TestRemoveBundledRejected(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)
	if err := tk.Remove(ctx, "mainnet", "usdc"); !isCode(err, CodeUsageBundledImmutable) {
		t.Fatalf("remove bundled major: want usage.bundled_immutable, got %v", err)
	}
}

// TestTokensOnDiskSchema confirms the §7.8 on-disk shape: per-network file with
// v/network/tokens/collections/nft_aliases, lowercase address string, empty NFT
// arrays in M5.
func TestTokensOnDiskSchema(t *testing.T) {
	ctx := context.Background()
	tk, dir := newTokens(t)
	if err := tk.Add(ctx, "mainnet", erc20("mytoken", addrMyToken, 18, "MTK")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "mainnet.json"))
	if err != nil {
		t.Fatalf("read mainnet.json: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		`"v": 1`,
		`"network": "mainnet"`,
		`"alias": "mytoken"`,
		`"kind": "erc20"`,
		`"decimals": 18`,
		`"symbol": "MTK"`,
		`"collections": []`,
		`"nft_aliases": []`,
		`"address": "0x1111111111111111111111111111111111111111"`, // lowercase
	} {
		if !contains(s, want) {
			t.Fatalf("mainnet.json missing %q; got:\n%s", want, s)
		}
	}

	// Confirm round-trip: a fresh store reads the same entry.
	tk2, _ := OpenTokens(dir)
	got, found, err := tk2.Resolve(ctx, "mainnet", "mytoken")
	if err != nil || !found || got.Address != addrMyToken {
		t.Fatalf("round-trip lost the entry: %+v found=%v err=%v", got, found, err)
	}
}

// TestTokensCorruptFileIsStateError confirms a non-JSON per-network file fails closed
// as a state error (not a panic, not silent loss).
func TestTokensCorruptFileIsStateError(t *testing.T) {
	ctx := context.Background()
	tk, dir := newTokens(t)
	if err := os.WriteFile(filepath.Join(dir, "mainnet.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}
	if _, err := tk.List(ctx, "mainnet"); !isCode(err, "state.corrupt") {
		t.Fatalf("corrupt file List: want state.corrupt, got %v", err)
	}
	if _, _, err := tk.Resolve(ctx, "mainnet", "usdc"); !isCode(err, "state.corrupt") {
		t.Fatalf("corrupt file Resolve: want state.corrupt, got %v", err)
	}
}

// TestNewerVersionRefused confirms a file with v greater than this binary forward-reads
// (tokensMaxReadableVersion) is refused (fail closed), while an additive v=2 (M10's
// contracts[] bump) is forward-read.
func TestNewerVersionRefused(t *testing.T) {
	ctx := context.Background()
	tk, dir := newTokens(t)

	// v=2 (M10 additive) forward-reads: tokens still resolve, contracts ignored.
	v2 := `{"v":2,"network":"mainnet","tokens":[{"alias":"mytoken","address":"0x1111111111111111111111111111111111111111","kind":"erc20","decimals":18,"symbol":"MTK"}],"collections":[],"nft_aliases":[],"contracts":[{"alias":"x","address":"0x2222222222222222222222222222222222222222","abi":[]}]}`
	if err := os.WriteFile(filepath.Join(dir, "mainnet.json"), []byte(v2), 0o600); err != nil {
		t.Fatalf("seed v2: %v", err)
	}
	got, found, err := tk.Resolve(ctx, "mainnet", "mytoken")
	if err != nil || !found || got.Address != addrMyToken {
		t.Fatalf("v=2 file should forward-read tokens: %+v found=%v err=%v", got, found, err)
	}

	// v=3 (unknown future breaking schema) is refused.
	v3 := `{"v":3,"network":"mainnet","tokens":[]}`
	if err := os.WriteFile(filepath.Join(dir, "sepolia.json"), []byte(v3), 0o600); err != nil {
		t.Fatalf("seed v3: %v", err)
	}
	if _, err := tk.List(ctx, "sepolia"); !isCode(err, "state.corrupt") {
		t.Fatalf("v=3 file: want state.corrupt (fail closed), got %v", err)
	}
}

// TestBadAliasRejected confirms Add rejects a non-§3.1-grammar alias with a usage
// error (exit 2).
func TestBadAliasRejected(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)
	for _, bad := range []string{"", "   ", "-lead", "has.dot", "has/slash", "has space", "0x1111111111111111111111111111111111111111"} {
		err := tk.Add(ctx, "mainnet", erc20(bad, addrMyToken, 18, "X"))
		if err == nil {
			t.Fatalf("bad alias %q accepted", bad)
		}
		if !isExit(err, domain.ExitUsage) {
			t.Fatalf("bad alias %q: want exit 2, got %v", bad, err)
		}
	}
}

// TestDiscoverySeam confirms *Tokens satisfies registry.Discovery and the seam
// methods delegate to Resolve/List (the §10.3 seam the future indexer reuses).
func TestDiscoverySeam(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)
	var d Discovery = tk // compile-time + runtime: *Tokens IS a Discovery

	if err := tk.Add(ctx, "mainnet", erc20("mytoken", addrMyToken, 18, "MTK")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// ResolveAsset == Resolve.
	got, found, err := d.ResolveAsset(ctx, "mainnet", "mytoken")
	if err != nil || !found || got.Address != addrMyToken {
		t.Fatalf("ResolveAsset: %+v found=%v err=%v", got, found, err)
	}
	// ResolveAsset miss is a clean miss (anti-spoofing — no chain lookup).
	if _, found, err := d.ResolveAsset(ctx, "mainnet", "unregistered"); err != nil || found {
		t.Fatalf("ResolveAsset miss: want found=false nil err, got found=%v err=%v", found, err)
	}
	// KnownAssets == List (owner ignored by the local impl).
	known, err := d.KnownAssets(ctx, "mainnet", addrMyToken2)
	if err != nil {
		t.Fatalf("KnownAssets: %v", err)
	}
	if len(known) != 5 { // 4 bundled + 1 file
		t.Fatalf("KnownAssets len = %d, want 5", len(known))
	}
}

// TestReadOnlyMount confirms a write against a read-only registry dir surfaces the
// state-class read-only sibling of config.read_only (exit 10). It uses a 0500 dir to
// trigger the MkdirAll/WriteAtomic read-only path the same way contacts does.
func TestReadOnlyMount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not block writes")
	}
	ctx := context.Background()
	parent := t.TempDir()
	roDir := filepath.Join(parent, "ro-registry")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatalf("mkdir ro: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) }) // let TempDir cleanup remove it

	tk, err := OpenTokens(roDir)
	if err != nil {
		t.Fatalf("OpenTokens: %v", err)
	}
	err = tk.Add(ctx, "mainnet", erc20("mytoken", addrMyToken, 18, "MTK"))
	if !isCode(err, domain.CodeConfigReadOnly) {
		t.Fatalf("Add on read-only mount: want config.read_only (exit 10), got %v", err)
	}
}
