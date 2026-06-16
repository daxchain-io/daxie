package domain

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestParseAccountRef(t *testing.T) {
	const addrHex = "0x52908400098527886E0F7030069857D2E4169EE7" // EIP-55 checksummed sample
	cases := []struct {
		name       string
		in         string
		wantKind   RefKind
		wantWallet string
		wantIndex  uint32
		wantName   string
		wantAddr   string // hex if RefAddress
	}{
		{"hd index", "treasury/3", RefHDIndex, "treasury", 3, "", ""},
		{"hd index zero", "treasury/0", RefHDIndex, "treasury", 0, "", ""},
		{"hd alias", "treasury/payroll", RefHDAlias, "treasury", 0, "payroll", ""},
		{"named", "ops-key", RefNamed, "", 0, "ops-key", ""},
		{"named dotted", "ops.key", RefNamed, "", 0, "ops.key", ""},
		{"address", addrHex, RefAddress, "", 0, "", addrHex},
		{"ens", "vitalik.eth", RefENS, "", 0, "vitalik", ""},
		{"ens subdomain", "pay.vitalik.eth", RefENS, "", 0, "pay.vitalik", ""},
		{"ens uppercase suffix", "Foo.ETH", RefENS, "", 0, "Foo", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseAccountRef(c.in)
			if err != nil {
				t.Fatalf("ParseAccountRef(%q) unexpected error: %v", c.in, err)
			}
			if got.Kind != c.wantKind {
				t.Errorf("kind = %v, want %v", got.Kind, c.wantKind)
			}
			if got.Wallet != c.wantWallet {
				t.Errorf("wallet = %q, want %q", got.Wallet, c.wantWallet)
			}
			if got.Index != c.wantIndex {
				t.Errorf("index = %d, want %d", got.Index, c.wantIndex)
			}
			if got.Name != c.wantName {
				t.Errorf("name = %q, want %q", got.Name, c.wantName)
			}
			if c.wantAddr != "" && got.Addr != common.HexToAddress(c.wantAddr) {
				t.Errorf("addr = %s, want %s", got.Addr.Hex(), c.wantAddr)
			}
			if got.Raw != c.in {
				t.Errorf("raw = %q, want %q", got.Raw, c.in)
			}
		})
	}
}

func TestParseAccountRefErrors(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantCode string
	}{
		{"empty", "", CodeUsage + ".empty_account_ref"},
		{"empty wallet", "/3", CodeUsage + ".bad_account_ref"},
		{"empty tail", "treasury/", CodeUsage + ".bad_account_ref"},
		{"double slash", "a/b/c", CodeUsage + ".bad_account_ref"},
		{"bad address", "0x1234", CodeUsage + ".bad_address"},
		{"bad address long", "0xZZ908400098527886E0F7030069857D2E4169EE7", CodeUsage + ".bad_address"},
		{"address in wallet segment", "0x52908400098527886E0F7030069857D2E4169EE7/3", CodeRefAmbiguous},
		{"ens in wallet segment", "vitalik.eth/3", CodeRefAmbiguous},
		{"bad name space", "ops key", CodeUsage + ".bad_account_ref"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseAccountRef(c.in)
			if err == nil {
				t.Fatalf("ParseAccountRef(%q) expected error", c.in)
			}
			var de *Error
			if !errors.As(err, &de) {
				t.Fatalf("error is not *domain.Error: %T", err)
			}
			if de.Code != c.wantCode {
				t.Errorf("code = %q, want %q", de.Code, c.wantCode)
			}
		})
	}
}

// TestLeadingZeroTailIsAlias documents the boundary: "treasury/01" is a valid
// alias (digits are a legal alias charset), not an index and not an error.
func TestLeadingZeroTailIsAlias(t *testing.T) {
	got, err := ParseAccountRef("treasury/01")
	if err != nil {
		t.Fatalf("treasury/01 should parse as an alias, got error: %v", err)
	}
	if got.Kind != RefHDAlias || got.Name != "01" {
		t.Errorf("treasury/01 = {%v, name=%q}, want {hd-alias, name=01}", got.Kind, got.Name)
	}
}

func TestParseIndexBounds(t *testing.T) {
	// uint32 max is 4294967295; one over must fall through to alias parsing.
	got, err := ParseAccountRef("w/4294967295")
	if err != nil || got.Kind != RefHDIndex || got.Index != 4294967295 {
		t.Fatalf("max uint32 index: got %+v err %v", got, err)
	}
	over, err := ParseAccountRef("w/4294967296")
	if err != nil {
		t.Fatalf("over-max should fall back to alias (digits are valid alias chars): %v", err)
	}
	if over.Kind != RefHDAlias {
		t.Errorf("over-max index should be treated as alias, got %v", over.Kind)
	}
}
