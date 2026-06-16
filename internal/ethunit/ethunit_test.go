package ethunit

import (
	"math/big"
	"testing"
)

func TestSplitAmountUnit(t *testing.T) {
	tests := []struct {
		in        string
		wantValue string
		wantUnit  string
	}{
		{"1.5eth", "1.5", "eth"},
		{"100", "100", ""},
		{"30000000000wei", "30000000000", "wei"},
		{"0.000000001gwei", "0.000000001", "gwei"},
		{"  1.5ETH  ", "1.5", "eth"},
		{"1eth", "1", "eth"},
		{".5eth", ".5", "eth"},
		{"+1.5eth", "+1.5", "eth"},
		{"-1.5eth", "-1.5", "eth"},
		{"eth", "", "eth"},
		{"1.5 eth", "1.5", "eth"}, // internal space lands in the unit-side trim
	}
	for _, tc := range tests {
		v, u := SplitAmountUnit(tc.in)
		if v != tc.wantValue || u != tc.wantUnit {
			t.Errorf("SplitAmountUnit(%q) = (%q,%q), want (%q,%q)", tc.in, v, u, tc.wantValue, tc.wantUnit)
		}
	}
}

func TestParseAmount(t *testing.T) {
	tests := []struct {
		decimal string
		unit    Unit
		want    string // expected wei as decimal string
		wantErr bool
	}{
		// exact integer wei
		{"1", Wei, "1", false},
		{"0", Wei, "0", false},
		{"30000000000", Wei, "30000000000", false},
		// gwei
		{"1", Gwei, "1000000000", false},
		{"30", Gwei, "30000000000", false},
		{"0.000000001", Gwei, "1", false}, // 1 wei = smallest gwei fraction
		{"1.5", Gwei, "1500000000", false},
		// eth
		{"1", Eth, "1000000000000000000", false},
		{"0.5", Eth, "500000000000000000", false},
		{"1.5", Eth, "1500000000000000000", false},
		{"0.000000000000000001", Eth, "1", false}, // 1 wei
		// leading/trailing forms
		{".5", Eth, "500000000000000000", false},
		{"5.", Eth, "5000000000000000000", false},
		{"+1", Eth, "1000000000000000000", false},
		{"000.5", Eth, "500000000000000000", false},
		// trailing zeros beyond unit precision are fine (no value lost)
		{"1.5000000000", Gwei, "1500000000", false},
		{"0.000000001000", Gwei, "1", false},
		// errors
		{"", Eth, "", true},
		{"-1", Eth, "", true},
		{"abc", Eth, "", true},
		{"1.2.3", Eth, "", true},
		{"0.0000000001", Gwei, "", true},         // 10 frac digits > 9 (sub-wei) nonzero
		{"0.0000000000000000001", Eth, "", true}, // 19 frac digits > 18 nonzero
		{"1.x", Eth, "", true},
		{".", Eth, "", true},
	}
	for _, tc := range tests {
		got, err := ParseAmount(tc.decimal, tc.unit)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseAmount(%q,%v) err=%v wantErr=%v", tc.decimal, tc.unit, err, tc.wantErr)
			continue
		}
		if err == nil && got.String() != tc.want {
			t.Errorf("ParseAmount(%q,%v) = %s, want %s", tc.decimal, tc.unit, got, tc.want)
		}
	}
}

func TestFormatAmount(t *testing.T) {
	tests := []struct {
		wei  string
		unit Unit
		want string
	}{
		{"1", Wei, "1"},
		{"0", Wei, "0"},
		{"1000000000", Gwei, "1"},
		{"30000000000", Gwei, "30"},
		{"1500000000", Gwei, "1.5"},
		{"1", Gwei, "0.000000001"},
		{"1000000000000000000", Eth, "1"},
		{"1500000000000000000", Eth, "1.5"},
		{"500000000000000000", Eth, "0.5"},
		{"1", Eth, "0.000000000000000001"},
		{"0", Eth, "0"},
		{"1230000000000000000", Eth, "1.23"}, // trailing zeros trimmed
	}
	for _, tc := range tests {
		wei, _ := new(big.Int).SetString(tc.wei, 10)
		got := FormatAmount(wei, tc.unit)
		if got != tc.want {
			t.Errorf("FormatAmount(%s,%v) = %q, want %q", tc.wei, tc.unit, got, tc.want)
		}
	}
}

// TestRoundTrip verifies parse∘format == identity (canonical form) and
// format∘parse == identity for representative values across all units.
func TestRoundTrip(t *testing.T) {
	canonical := []struct {
		s    string
		unit Unit
	}{
		{"1", Wei},
		{"123456789", Wei},
		{"1", Gwei},
		{"1.5", Gwei},
		{"0.000000001", Gwei},
		{"30", Gwei},
		{"1", Eth},
		{"1.5", Eth},
		{"0.5", Eth},
		{"0.000000000000000001", Eth},
		{"123.456", Eth},
	}
	for _, tc := range canonical {
		wei, err := ParseAmount(tc.s, tc.unit)
		if err != nil {
			t.Fatalf("ParseAmount(%q,%v): %v", tc.s, tc.unit, err)
		}
		back := FormatAmount(wei, tc.unit)
		if back != tc.s {
			t.Errorf("round-trip %q in %v -> wei %s -> %q", tc.s, tc.unit, wei, back)
		}
	}
}

// TestCrossUnitNoFloatDrift converts across units and asserts exactness — the
// classic float pitfall (0.1+0.2) cannot occur because everything is integer.
func TestCrossUnitNoFloatDrift(t *testing.T) {
	// 1 eth == 1e9 gwei == 1e18 wei.
	wei, err := ParseAmount("1", Eth)
	if err != nil {
		t.Fatal(err)
	}
	if got := FormatAmount(wei, Gwei); got != "1000000000" {
		t.Errorf("1 eth in gwei = %q, want 1000000000", got)
	}
	if got := FormatAmount(wei, Wei); got != "1000000000000000000" {
		t.Errorf("1 eth in wei = %q, want 1e18", got)
	}
	// 30000000000 wei == 30 gwei (the demo case).
	w2, _ := new(big.Int).SetString("30000000000", 10)
	if got := FormatAmount(w2, Gwei); got != "30" {
		t.Errorf("30000000000 wei in gwei = %q, want 30", got)
	}
}

func TestTokenAmount(t *testing.T) {
	tests := []struct {
		decimal  string
		decimals uint8
		wantBase string
	}{
		{"1", 6, "1000000"},   // 1 USDC
		{"1.5", 6, "1500000"}, // 1.5 USDC
		{"0.000001", 6, "1"},  // smallest USDC unit
		{"1", 18, "1000000000000000000"},
		{"100", 0, "100"}, // 0-decimal token
		{"123.456", 3, "123456"},
	}
	for _, tc := range tests {
		base, err := ParseTokenAmount(tc.decimal, tc.decimals)
		if err != nil {
			t.Errorf("ParseTokenAmount(%q,%d): %v", tc.decimal, tc.decimals, err)
			continue
		}
		if base.String() != tc.wantBase {
			t.Errorf("ParseTokenAmount(%q,%d) = %s, want %s", tc.decimal, tc.decimals, base, tc.wantBase)
		}
		// Round-trip back: all inputs here are already in canonical form (no
		// trailing zeros), so format∘parse must reproduce them exactly.
		if back := FormatTokenAmount(base, tc.decimals); back != tc.decimal {
			t.Errorf("FormatTokenAmount round-trip: %q -> %s -> %q", tc.decimal, base, back)
		}
	}
}

func TestTokenAmountErrors(t *testing.T) {
	if _, err := ParseTokenAmount("0.0000001", 6); err == nil {
		t.Error("expected error for 7 fractional digits on a 6-decimal token")
	}
	if _, err := ParseTokenAmount("-1", 6); err == nil {
		t.Error("expected error for negative token amount")
	}
	if _, err := ParseTokenAmount("", 6); err == nil {
		t.Error("expected error for empty token amount")
	}
}

func TestFormatNilBase(t *testing.T) {
	if got := FormatAmount(nil, Eth); got != "0" {
		t.Errorf("FormatAmount(nil) = %q, want 0", got)
	}
}
