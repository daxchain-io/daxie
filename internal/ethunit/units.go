// Package ethunit is pure, float-free unit math for Ether denominations and
// decimal-aware token amounts. Every conversion is exact over math/big; there is
// no float64 anywhere in this package, so there is no rounding drift. It performs
// no I/O and imports nothing internal — it is the engine behind `daxie convert`
// (§2.1, §2.9).
package ethunit

import (
	"fmt"
	"math/big"
	"strings"
)

// Unit is an Ether denomination. The zero value is Wei (the base unit), which is
// the safe default if a Unit is ever left unset.
type Unit int

const (
	// Wei is the base unit (10^0).
	Wei Unit = iota
	// Gwei is 10^9 wei.
	Gwei
	// Eth is 10^18 wei.
	Eth
)

// decimals returns the number of decimal places the unit carries relative to wei.
func (u Unit) decimals() (uint8, bool) {
	switch u {
	case Wei:
		return 0, true
	case Gwei:
		return 9, true
	case Eth:
		return 18, true
	default:
		return 0, false
	}
}

// String returns the canonical lowercase unit name. An unknown Unit renders as
// "unit(N)" so a programming error is visible rather than silently empty.
func (u Unit) String() string {
	switch u {
	case Wei:
		return "wei"
	case Gwei:
		return "gwei"
	case Eth:
		return "eth"
	default:
		return fmt.Sprintf("unit(%d)", int(u))
	}
}

// ParseUnit accepts "eth", "gwei", or "wei" case-insensitively (surrounding
// whitespace is trimmed). The common alias "ether" is also accepted for Eth.
// Anything else is a usage-class error.
func ParseUnit(s string) (Unit, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "wei":
		return Wei, nil
	case "gwei":
		return Gwei, nil
	case "eth", "ether":
		return Eth, nil
	default:
		return Wei, fmt.Errorf("ethunit: unknown unit %q (want eth, gwei, or wei)", s)
	}
}

// WeiPer returns 10^decimals for the unit as a fresh *big.Int (wei=1, gwei=1e9,
// eth=1e18). The returned value is owned by the caller. An unknown unit returns
// 1 (the wei scale) but callers should validate with ParseUnit first.
func (u Unit) WeiPer() *big.Int {
	d, ok := u.decimals()
	if !ok {
		return big.NewInt(1)
	}
	return tenPow(d)
}
