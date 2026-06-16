package ethunit

import (
	"fmt"
	"math/big"
	"strings"
)

var bigTen = big.NewInt(10)

// tenPow returns 10^n as a fresh *big.Int.
func tenPow(n uint8) *big.Int {
	return new(big.Int).Exp(bigTen, big.NewInt(int64(n)), nil)
}

// SplitAmountUnit splits a combined amount/unit token into its decimal value and
// its (lowercased) unit suffix. The split point is the first character that is
// not part of a decimal number (digits, a single leading sign, or a dot).
//
//	"1.5eth" -> ("1.5", "eth")
//	"100"    -> ("100", "")
//	"  5 gwei" with internal space is NOT split here — callers that allow a space
//	    between value and unit pass the two tokens separately.
//
// Surrounding whitespace on the whole input is trimmed; the returned unit is
// lowercased and trimmed.
func SplitAmountUnit(s string) (value, unit string) {
	s = strings.TrimSpace(s)
	i := 0
	for i < len(s) {
		c := s[i]
		isNum := (c >= '0' && c <= '9') || c == '.' || ((c == '+' || c == '-') && i == 0)
		if !isNum {
			break
		}
		i++
	}
	value = strings.TrimSpace(s[:i])
	unit = strings.ToLower(strings.TrimSpace(s[i:]))
	return value, unit
}

// ParseAmount parses a decimal string in the given unit into exact wei. It
// rejects:
//   - empty / malformed numbers,
//   - negative values (Ether amounts are non-negative),
//   - more fractional digits than the unit can represent without going sub-wei
//     (e.g. "0.0000000001gwei" has 10 fractional digits but gwei only carries 9,
//     so it would require a fractional wei — an error, not a silent truncation).
//
// No float is used anywhere; the value is assembled with *big.Int only.
func ParseAmount(decimal string, u Unit) (*big.Int, error) {
	d, ok := u.decimals()
	if !ok {
		return nil, fmt.Errorf("ethunit: invalid unit %v", u)
	}
	return parseDecimalToBase(decimal, d)
}

// FormatAmount renders wei into the target unit as an exact decimal string with
// no trailing fractional zeros and no scientific notation. A value with no
// fractional part renders as a plain integer (e.g. "30", not "30.0").
func FormatAmount(wei *big.Int, u Unit) string {
	d, ok := u.decimals()
	if !ok {
		return wei.String()
	}
	return formatBase(wei, d)
}

// ParseTokenAmount parses a decimal string into an exact base-unit integer for a
// token with the given number of decimals (e.g. 6 for USDC, 18 for most ERC-20).
// Same rules as ParseAmount: non-negative, no more fractional digits than the
// token carries.
func ParseTokenAmount(decimal string, decimals uint8) (*big.Int, error) {
	return parseDecimalToBase(decimal, decimals)
}

// FormatTokenAmount renders a base-unit integer into a human decimal string for a
// token with the given decimals, with no trailing fractional zeros and no
// scientific notation.
func FormatTokenAmount(base *big.Int, decimals uint8) string {
	return formatBase(base, decimals)
}

// parseDecimalToBase converts a non-negative decimal string into an integer
// scaled by 10^scale, exactly, rejecting excess fractional precision.
func parseDecimalToBase(decimal string, scale uint8) (*big.Int, error) {
	s := strings.TrimSpace(decimal)
	if s == "" {
		return nil, fmt.Errorf("ethunit: empty amount")
	}
	// A leading "+" is tolerated; a leading "-" is rejected (no negative values).
	switch s[0] {
	case '+':
		s = s[1:]
	case '-':
		return nil, fmt.Errorf("ethunit: negative amount %q not allowed", decimal)
	}
	if s == "" {
		return nil, fmt.Errorf("ethunit: malformed amount %q", decimal)
	}

	intPart, fracPart, hasDot := s, "", false
	if i := strings.IndexByte(s, '.'); i >= 0 {
		hasDot = true
		intPart = s[:i]
		fracPart = s[i+1:]
		if strings.IndexByte(fracPart, '.') >= 0 {
			return nil, fmt.Errorf("ethunit: malformed amount %q (multiple decimal points)", decimal)
		}
	}
	// "" int part is allowed only as ".5"; "5." is allowed as "5".
	if intPart == "" && fracPart == "" {
		return nil, fmt.Errorf("ethunit: malformed amount %q", decimal)
	}
	if intPart == "" {
		intPart = "0"
	}
	if !isDigits(intPart) || (hasDot && fracPart != "" && !isDigits(fracPart)) {
		return nil, fmt.Errorf("ethunit: malformed amount %q (non-digit characters)", decimal)
	}
	// Compare lengths in int space (scale is small; no narrowing conversion).
	scaleN := int(scale)
	if len(fracPart) > scaleN {
		// Allow trailing zeros beyond scale (they carry no value); reject only a
		// non-zero digit past the unit's precision.
		excess := fracPart[scaleN:]
		if strings.Trim(excess, "0") != "" {
			return nil, fmt.Errorf("ethunit: amount %q has more precision than the unit supports (%d decimals)", decimal, scale)
		}
		fracPart = fracPart[:scaleN]
	}
	// Right-pad the fractional part to exactly `scale` digits, then concatenate.
	padded := fracPart
	for len(padded) < scaleN {
		padded += "0"
	}
	combined := intPart + padded
	// Strip a leading run of zeros to keep SetString happy on "000...".
	combined = strings.TrimLeft(combined, "0")
	if combined == "" {
		combined = "0"
	}
	out, ok := new(big.Int).SetString(combined, 10)
	if !ok {
		return nil, fmt.Errorf("ethunit: malformed amount %q", decimal)
	}
	return out, nil
}

// formatBase renders a base-unit integer scaled by 10^scale into a trimmed
// decimal string.
func formatBase(base *big.Int, scale uint8) string {
	if base == nil {
		return "0"
	}
	neg := base.Sign() < 0
	abs := new(big.Int).Abs(base)
	if scale == 0 {
		s := abs.String()
		if neg {
			return "-" + s
		}
		return s
	}
	divisor := tenPow(scale)
	q := new(big.Int)
	r := new(big.Int)
	q.QuoRem(abs, divisor, r)

	intStr := q.String()
	if r.Sign() == 0 {
		if neg {
			return "-" + intStr
		}
		return intStr
	}
	// Left-pad the remainder to `scale` digits, then trim trailing zeros.
	fracStr := r.String()
	for len(fracStr) < int(scale) {
		fracStr = "0" + fracStr
	}
	fracStr = strings.TrimRight(fracStr, "0")
	out := intStr + "." + fracStr
	if neg {
		return "-" + out
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
