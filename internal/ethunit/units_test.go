package ethunit

import (
	"math/big"
	"testing"
)

func TestParseUnit(t *testing.T) {
	tests := []struct {
		in      string
		want    Unit
		wantErr bool
	}{
		{"wei", Wei, false},
		{"WEI", Wei, false},
		{"Wei", Wei, false},
		{"gwei", Gwei, false},
		{"GWEI", Gwei, false},
		{"eth", Eth, false},
		{"ETH", Eth, false},
		{"ether", Eth, false},
		{"  eth  ", Eth, false},
		{"", Wei, true},
		{"finney", Wei, true},
		{"szabo", Wei, true},
		{"foo", Wei, true},
	}
	for _, tc := range tests {
		got, err := ParseUnit(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseUnit(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("ParseUnit(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestUnitString(t *testing.T) {
	tests := []struct {
		u    Unit
		want string
	}{
		{Wei, "wei"},
		{Gwei, "gwei"},
		{Eth, "eth"},
		{Unit(99), "unit(99)"},
	}
	for _, tc := range tests {
		if got := tc.u.String(); got != tc.want {
			t.Errorf("Unit(%d).String() = %q, want %q", int(tc.u), got, tc.want)
		}
	}
}

func TestWeiPer(t *testing.T) {
	tests := []struct {
		u    Unit
		want string
	}{
		{Wei, "1"},
		{Gwei, "1000000000"},
		{Eth, "1000000000000000000"},
	}
	for _, tc := range tests {
		got := tc.u.WeiPer()
		if got.String() != tc.want {
			t.Errorf("%v.WeiPer() = %s, want %s", tc.u, got, tc.want)
		}
	}
	// Returned value must be a fresh copy each call (no shared aliasing).
	a := Eth.WeiPer()
	b := Eth.WeiPer()
	a.Add(a, big.NewInt(1))
	if b.Cmp(tenPow(18)) != 0 {
		t.Errorf("WeiPer() returned an aliased value; mutation of one affected another")
	}
}
