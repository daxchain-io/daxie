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

// contracts_test.go pins the M10 contract registry (§7.8): CRUD, collision, case-
// insensitivity, per-network keying, registry-only resolution (no symbol fallback),
// structural ABI rejection at add, and the v1→v2 forward-migration that coexists with the
// token namespace in the shared per-network envelope.

func newContracts(t *testing.T) (*Contracts, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := OpenContracts(dir)
	if err != nil {
		t.Fatalf("OpenContracts: %v", err)
	}
	return c, dir
}

var (
	stakingAddr = common.HexToAddress("0x7a250d5630b4cf539739df2c5dacb4c659f2488d")
	otherAddr   = common.HexToAddress("0x1111111111111111111111111111111111111111")
)

// stakingABI is a minimal valid canonical Solidity ABI array (one function + one event).
const stakingABI = `[
  {"type":"function","name":"stake","stateMutability":"nonpayable",
   "inputs":[{"name":"amount","type":"uint256"}],"outputs":[]},
  {"type":"event","name":"Staked","anonymous":false,
   "inputs":[{"name":"user","type":"address","indexed":true},
             {"name":"amount","type":"uint256","indexed":false}]}
]`

func staking(alias string, addr common.Address, abiJSON string) Contract {
	return Contract{Alias: alias, Address: addr, ABI: json.RawMessage(abiJSON)}
}

// TestContractAddListResolveRemove walks the contract CRUD lifecycle.
func TestContractAddListResolveRemove(t *testing.T) {
	ctx := context.Background()
	c, _ := newContracts(t)

	if err := c.Add(ctx, "mainnet", staking("staking", stakingAddr, stakingABI)); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, found, err := c.Resolve(ctx, "mainnet", "staking")
	if err != nil || !found {
		t.Fatalf("Resolve: found=%v err=%v", found, err)
	}
	if got.Address != stakingAddr {
		t.Fatalf("address = %s, want %s", got.Address.Hex(), stakingAddr.Hex())
	}
	if len(got.ABI) == 0 {
		t.Fatal("ABI must round-trip")
	}

	list, err := c.List(ctx, "mainnet")
	if err != nil || len(list) != 1 {
		t.Fatalf("List len = %d err=%v, want 1", len(list), err)
	}

	if err := c.Remove(ctx, "mainnet", "staking"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, found, _ := c.Resolve(ctx, "mainnet", "staking"); found {
		t.Fatal("after remove the alias must not resolve")
	}
}

// TestContractResolveCaseInsensitive confirms aliases match case-insensitively.
func TestContractResolveCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	c, _ := newContracts(t)
	if err := c.Add(ctx, "mainnet", staking("Staking", stakingAddr, stakingABI)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, found, _ := c.Resolve(ctx, "mainnet", "STAKING"); !found {
		t.Fatal("alias must resolve case-insensitively")
	}
}

// TestContractCollisionRequiresName confirms a duplicate alias is rejected usage.duplicate.
func TestContractCollisionRequiresName(t *testing.T) {
	ctx := context.Background()
	c, _ := newContracts(t)
	if err := c.Add(ctx, "mainnet", staking("staking", stakingAddr, stakingABI)); err != nil {
		t.Fatalf("Add 1: %v", err)
	}
	err := c.Add(ctx, "mainnet", staking("staking", otherAddr, stakingABI))
	if err == nil {
		t.Fatal("a duplicate alias must be rejected")
	}
	if domain.AsError(err).Code != CodeUsageDuplicate {
		t.Fatalf("code = %q, want %q", domain.AsError(err).Code, CodeUsageDuplicate)
	}
}

// TestContractPerNetwork confirms the same alias maps independently per network.
func TestContractPerNetwork(t *testing.T) {
	ctx := context.Background()
	c, _ := newContracts(t)
	if err := c.Add(ctx, "mainnet", staking("staking", stakingAddr, stakingABI)); err != nil {
		t.Fatalf("Add mainnet: %v", err)
	}
	if err := c.Add(ctx, "sepolia", staking("staking", otherAddr, stakingABI)); err != nil {
		t.Fatalf("Add sepolia: %v", err)
	}
	m, _, _ := c.Resolve(ctx, "mainnet", "staking")
	s, _, _ := c.Resolve(ctx, "sepolia", "staking")
	if m.Address == s.Address {
		t.Fatal("per-network aliases must resolve independently")
	}
	// A sepolia-only alias must not resolve on mainnet.
	if err := c.Add(ctx, "sepolia", staking("only-sep", otherAddr, stakingABI)); err != nil {
		t.Fatalf("Add only-sep: %v", err)
	}
	if _, found, _ := c.Resolve(ctx, "mainnet", "only-sep"); found {
		t.Fatal("a sepolia alias must not resolve on mainnet")
	}
}

// TestContractInvalidABIRejectedAtAdd confirms a structurally-invalid ABI is rejected
// usage.bad_abi and never stored.
func TestContractInvalidABIRejectedAtAdd(t *testing.T) {
	ctx := context.Background()
	c, dir := newContracts(t)

	cases := []struct {
		name string
		abi  string
	}{
		{"empty", ""},
		{"not json", "not json"},
		{"object not array", `{"type":"function"}`},
		{"empty array", `[]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Add(ctx, "mainnet", staking("staking", stakingAddr, tc.abi))
			if err == nil {
				t.Fatalf("%s: an invalid ABI must be rejected", tc.name)
			}
			if domain.AsError(err).Code != domain.CodeUsage+".bad_abi" {
				t.Fatalf("%s: code = %q, want usage.bad_abi", tc.name, domain.AsError(err).Code)
			}
		})
	}
	// Nothing was stored.
	if _, err := os.Stat(filepath.Join(dir, "mainnet.json")); err == nil {
		// File may exist only if a prior successful add wrote it — none did here.
		list, _ := c.List(ctx, "mainnet")
		if len(list) != 0 {
			t.Fatalf("a rejected ABI must not be stored; got %d contracts", len(list))
		}
	}
}

// TestContractResolveRegistryOnly confirms a miss is found=false (no symbol fallback),
// including for a non-grammar alias (a clean miss, not an error).
func TestContractResolveRegistryOnly(t *testing.T) {
	ctx := context.Background()
	c, _ := newContracts(t)
	if _, found, err := c.Resolve(ctx, "mainnet", "nope"); found || err != nil {
		t.Fatalf("a miss must be found=false, nil err; got found=%v err=%v", found, err)
	}
	if _, found, err := c.Resolve(ctx, "mainnet", "Not A Name!"); found || err != nil {
		t.Fatalf("a non-grammar alias must be a clean miss; got found=%v err=%v", found, err)
	}
}

// TestContractV1ForwardMigration confirms a v1 file (no contracts key) reads as empty and a
// contract add upgrades it to v2 while PRESERVING the existing token data (the shared-
// envelope coexistence invariant).
func TestContractV1ForwardMigration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	// Hand-write a v1 envelope with a token but no contracts key.
	v1 := `{"v":1,"network":"mainnet",
	  "tokens":[{"alias":"mytok","address":"0x1111111111111111111111111111111111111111","kind":"erc20","decimals":18,"symbol":"MTK"}],
	  "collections":[],"nft_aliases":[]}`
	if err := os.WriteFile(filepath.Join(dir, "mainnet.json"), []byte(v1), 0o600); err != nil {
		t.Fatalf("write v1: %v", err)
	}

	c, _ := OpenContracts(dir)
	// A v1 file reads as zero contracts (forward-migration).
	if list, err := c.List(ctx, "mainnet"); err != nil || len(list) != 0 {
		t.Fatalf("a v1 file must read 0 contracts; len=%d err=%v", len(list), err)
	}

	// Adding a contract upgrades to v2 and preserves the token.
	if err := c.Add(ctx, "mainnet", staking("staking", stakingAddr, stakingABI)); err != nil {
		t.Fatalf("Add upgrades v1→v2: %v", err)
	}

	// Re-read the raw file: v must be 2, the token must survive, the contract present.
	b, err := os.ReadFile(filepath.Join(dir, "mainnet.json"))
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	var f tokensFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f.V != 2 {
		t.Fatalf("v = %d, want 2 after a contract add", f.V)
	}
	if len(f.Tokens) != 1 || f.Tokens[0].Alias != "mytok" {
		t.Fatalf("the pre-existing token must survive the v1→v2 upgrade; tokens=%+v", f.Tokens)
	}
	if len(f.Contracts) != 1 || f.Contracts[0].Alias != "staking" {
		t.Fatalf("the contract must be stored; contracts=%+v", f.Contracts)
	}

	// And the Tokens store still resolves the token (cross-namespace coexistence).
	tk, _ := OpenTokens(dir)
	if _, found, _ := tk.Resolve(ctx, "mainnet", "mytok"); !found {
		t.Fatal("the token must still resolve after the contract add")
	}
}

// TestContractAddNormalizesABI confirms the stored ABI is compacted (no incidental
// whitespace) so the on-disk form is stable.
func TestContractAddNormalizesABI(t *testing.T) {
	ctx := context.Background()
	c, _ := newContracts(t)
	if err := c.Add(ctx, "mainnet", staking("staking", stakingAddr, stakingABI)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, _, _ := c.Resolve(ctx, "mainnet", "staking")
	// Compacted JSON has no leading newline/indent.
	if len(got.ABI) > 0 && (got.ABI[0] == '\n' || got.ABI[0] == ' ') {
		t.Fatalf("stored ABI must be compacted, got leading whitespace: %q", string(got.ABI[:8]))
	}
	// It must still be valid JSON.
	var arr []json.RawMessage
	if err := json.Unmarshal(got.ABI, &arr); err != nil || len(arr) != 2 {
		t.Fatalf("normalized ABI must round-trip to 2 entries; err=%v len=%d", err, len(arr))
	}
}
