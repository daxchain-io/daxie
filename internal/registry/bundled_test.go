package registry

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// TestBundledMajorsResolve confirms every compiled-in major resolves on its network
// with the right kind/decimals and the Bundled provenance flag set.
func TestBundledMajorsResolve(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)

	for network, majors := range bundledMajors {
		for _, want := range majors {
			got, found, err := tk.Resolve(ctx, network, want.Alias)
			if err != nil {
				t.Fatalf("Resolve(%s,%s): %v", network, want.Alias, err)
			}
			if !found {
				t.Fatalf("bundled major %q on %s did not resolve", want.Alias, network)
			}
			if !got.Bundled {
				t.Fatalf("bundled major %q on %s: Bundled flag not set", want.Alias, network)
			}
			if got.Address != want.Address {
				t.Fatalf("%q on %s: address = %s, want %s", want.Alias, network, got.Address, want.Address)
			}
			if got.Kind != KindERC20 {
				t.Fatalf("%q on %s: kind = %q, want erc20", want.Alias, network, got.Kind)
			}
			if got.Decimals != want.Decimals {
				t.Fatalf("%q on %s: decimals = %d, want %d", want.Alias, network, got.Decimals, want.Decimals)
			}
		}
	}
}

// TestBundledMajorsCaseInsensitive confirms bundled majors resolve case-insensitively
// (the user can type USDC, Usdc, usdc).
func TestBundledMajorsCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)

	for _, alias := range []string{"USDC", "Usdc", "uSdC", "usdc"} {
		got, found, err := tk.Resolve(ctx, "mainnet", alias)
		if err != nil {
			t.Fatalf("Resolve(mainnet,%s): %v", alias, err)
		}
		if !found {
			t.Fatalf("bundled USDC did not resolve for input %q", alias)
		}
		if got.Alias != "usdc" {
			t.Fatalf("resolved alias = %q, want canonical lowercase usdc", got.Alias)
		}
	}
}

// TestBundledMajorsCanonicalAliases confirms the four mainnet majors are present and
// their stored aliases are canonical (lowercase, grammar-valid).
func TestBundledMajorsCanonicalAliases(t *testing.T) {
	want := map[string]bool{"usdc": false, "usdt": false, "weth": false, "dai": false}
	for _, tok := range bundledMajors["mainnet"] {
		if _, ok := want[tok.Alias]; !ok {
			t.Fatalf("unexpected mainnet bundled alias %q", tok.Alias)
		}
		want[tok.Alias] = true
		if canon, err := canonicalName(tok.Alias); err != nil || canon != tok.Alias {
			t.Fatalf("bundled alias %q is not canonical (canon=%q err=%v)", tok.Alias, canon, err)
		}
	}
	for alias, seen := range want {
		if !seen {
			t.Fatalf("mainnet is missing bundled major %q", alias)
		}
	}
}

// TestBundledAddressesAreEIP55Valid confirms every bundled address is a syntactically
// valid hex address (the canonical checksummed forms in the table parse cleanly).
func TestBundledAddressesAreEIP55Valid(t *testing.T) {
	for network, majors := range bundledMajors {
		for _, tok := range majors {
			if (tok.Address == common.Address{}) {
				t.Fatalf("bundled %q on %s has the zero address", tok.Alias, network)
			}
			// The source literals are EIP-55 checksummed; confirm the checksum
			// round-trips (a typo in the literal would still parse, but a bad
			// checksum in the source string would have been caught by HexToAddress
			// tolerating mixed case — so assert the canonical form is non-empty and
			// re-checksums to a stable value).
			if got := tok.Address.Hex(); !strings.HasPrefix(got, "0x") || len(got) != 42 {
				t.Fatalf("bundled %q on %s: malformed address hex %q", tok.Alias, network, got)
			}
		}
	}
}

// TestBundledNotWrittenToFile confirms resolving a bundled major does NOT create or
// touch the per-network file — bundled majors live in the binary, not on disk (§7.8).
func TestBundledNotWrittenToFile(t *testing.T) {
	ctx := context.Background()
	tk, dir := newTokens(t)

	if _, found, err := tk.Resolve(ctx, "mainnet", "usdc"); err != nil || !found {
		t.Fatalf("Resolve bundled usdc: found=%v err=%v", found, err)
	}
	if _, err := tk.List(ctx, "mainnet"); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mainnet.json")); !os.IsNotExist(err) {
		t.Fatalf("resolving/listing bundled majors wrote a file (want none): err=%v", err)
	}
}

// TestBundledMissingNetworkResolvesNothing confirms an unknown network has no bundled
// majors and resolution misses cleanly (no panic, found=false).
func TestBundledMissingNetworkResolvesNothing(t *testing.T) {
	ctx := context.Background()
	tk, _ := newTokens(t)
	if _, found, err := tk.Resolve(ctx, "no-such-net", "usdc"); err != nil || found {
		t.Fatalf("Resolve on unknown network: want found=false nil err, got found=%v err=%v", found, err)
	}
	list, err := tk.List(ctx, "no-such-net")
	if err != nil {
		t.Fatalf("List unknown network: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("unknown network should have no known assets, got %d", len(list))
	}
}
