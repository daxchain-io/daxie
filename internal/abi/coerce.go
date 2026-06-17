package abi

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	gethabi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// coerce.go is the §2.5 "parse once" arg coercer: positional user STRINGS → the
// native Go values gethabi.Pack consumes, driven entirely by the declared ABI type
// (the ABI is the parser). It also exposes ParseLiteral, the type-directed recursive
// grammar for compound literals (arrays, tuples, nesting, double-quoted elements).
// Pure: no chain, no state. Every malformed input is usage.bad_arg (exit 2) NAMING
// the offending arg index + the expected solidity type, so an agent gets an
// actionable error.

// AddrProvenance records one resolved address-typed arg's provenance, so service can
// echo it before signing (§4 always-echo) and feed pin-drift if it came from
// ENS/contact. Empty (zero) for non-address args. Mirrors domain.Dest's Via/ENSName
// vocabulary ("ens" | "contact" | "literal" | "").
type AddrProvenance struct {
	Input   string         // exactly what the user typed for this arg
	Addr    common.Address // the resolved address
	Via     string         // "ens" | "contact" | "literal" | ""
	ENSName string         // the ENS name when Via=="ens"
}

// AddrResolver resolves an address-typed arg string (account ref / contact / ENS /
// raw 0x) to a common.Address + provenance — the SAME domain.ParseAccountRef + Dest
// resolution any --to uses. Service passes its resolver; CoerceArgs calls it for
// every address-typed scalar so the resolved Dest[] can be echoed before signing.
type AddrResolver func(s string) (common.Address, AddrProvenance, error)

// errBadArg is a malformed positional arg (count/shape/value). It names the arg
// INDEX and the expected solidity type so the error is actionable (§2.5).
func errBadArg(index int, solType, detail string) error {
	return domain.Newf("usage.bad_arg", "arg %d (%s): %s", index, solType, detail)
}

// errArgCount is a positional-arg count mismatch for the method.
func errArgCount(method string, want, got int) error {
	return domain.Newf("usage.bad_arg", "method %q expects %d arg(s), got %d", method, want, got)
}

// CoerceArgs coerces positional user strings to the declared input types of method,
// returning the []any gethabi.Pack consumes plus the resolved AddrProvenance for
// every address-typed scalar (in arg order; the zero value for non-address args).
// addrResolve resolves an address-typed scalar string; pass nil to treat address
// literals as raw 0x only (the pure encode/decode paths that never sign). A wrong
// count or a malformed literal is usage.bad_arg (exit 2) naming the offending index
// + expected solidity type.
func (Codec) CoerceArgs(parsed *gethabi.ABI, method string, args []string, addrResolve AddrResolver) ([]any, []AddrProvenance, error) {
	m, ok := parsed.Methods[method]
	if !ok {
		return nil, nil, errUnknownMethod(method)
	}
	if len(args) != len(m.Inputs) {
		return nil, nil, errArgCount(method, len(m.Inputs), len(args))
	}

	out := make([]any, len(m.Inputs))
	prov := make([]AddrProvenance, len(m.Inputs))
	c := &coercer{resolve: addrResolve}
	for i, in := range m.Inputs {
		// len(args)==len(m.Inputs) is enforced above, so args[i] is always in range.
		v, err := c.coerce(in.Type, args[i], i) // #nosec G602 -- len-checked equal to m.Inputs above
		if err != nil {
			return nil, nil, err
		}
		out[i] = v
		// A top-level address-typed scalar's provenance is surfaced for the echo.
		if in.Type.T == gethabi.AddressTy {
			prov[i] = c.lastTopLevelAddr
		}
	}
	return out, prov, nil
}

// coercer carries the address resolver + the provenance of the most recently coerced
// TOP-LEVEL address scalar (so CoerceArgs can attach it to the right index without
// threading provenance through the recursive descent — only top-level address args
// are echoed; nested address resolution still uses the resolver but its provenance is
// not separately surfaced in v1).
type coercer struct {
	resolve          AddrResolver
	lastTopLevelAddr AddrProvenance
}

// coerce converts one user string `s` to the native Go value for solidity type t,
// recursively (type-directed descent). index is the top-level arg index for error
// messages.
func (c *coercer) coerce(t gethabi.Type, s string, index int) (any, error) {
	switch t.T {
	case gethabi.IntTy, gethabi.UintTy:
		return c.coerceInt(t, s, index)
	case gethabi.BoolTy:
		return coerceBool(s, t, index)
	case gethabi.AddressTy:
		return c.coerceAddr(s, t, index)
	case gethabi.StringTy:
		return s, nil // verbatim
	case gethabi.BytesTy:
		return coerceDynBytes(s, t, index)
	case gethabi.FixedBytesTy:
		return coerceFixedBytes(t, s, index)
	case gethabi.SliceTy, gethabi.ArrayTy:
		return c.coerceArray(t, s, index)
	case gethabi.TupleTy:
		return c.coerceTuple(t, s, index)
	default:
		return nil, errBadArg(index, t.String(), "unsupported solidity type")
	}
}

// coerceInt coerces a decimal OR 0x-hex base-unit integer string into the native Go
// integer type Pack expects (a *big.Int for >64-bit, the sized int/uint otherwise).
// NO implicit decimal scaling (daxie convert does 10^n). A value out of range for the
// declared bit-size, or a non-integer, is usage.bad_arg. Large uints (> int64) are
// fully supported via *big.Int — the ergonomic the plan calls out.
func (c *coercer) coerceInt(t gethabi.Type, s string, index int) (any, error) {
	v, ok := parseBigInt(s)
	if !ok {
		return nil, errBadArg(index, t.String(), fmt.Sprintf("%q is not a decimal or 0x-hex integer", s))
	}
	// Range-check against the declared bit-size + signedness.
	if err := checkIntRange(v, t, index); err != nil {
		return nil, err
	}
	// Pack expects the precise reflect type GetType() returns for the size. Build it
	// from the big.Int so a uint8…uint256 / int8…int256 all pack correctly.
	return convertToReflectInt(v, t)
}

// coerceAddr resolves an address-typed scalar via the resolver (account ref / contact
// / ENS / raw 0x) when one is provided; otherwise it accepts a raw 0x address only
// (the pure paths). It records the provenance for the top-level echo.
func (c *coercer) coerceAddr(s string, t gethabi.Type, index int) (common.Address, error) {
	if c.resolve != nil {
		addr, prov, err := c.resolve(s)
		if err != nil {
			return common.Address{}, errBadArg(index, t.String(), err.Error())
		}
		if prov.Input == "" {
			prov.Input = s
		}
		if prov.Addr == (common.Address{}) {
			prov.Addr = addr
		}
		c.lastTopLevelAddr = prov
		return addr, nil
	}
	// Pure path: raw 0x address only.
	s = strings.TrimSpace(s)
	if !common.IsHexAddress(s) {
		return common.Address{}, errBadArg(index, t.String(), fmt.Sprintf("%q is not a 0x address", s))
	}
	addr := common.HexToAddress(s)
	c.lastTopLevelAddr = AddrProvenance{Input: s, Addr: addr, Via: "literal"}
	return addr, nil
}

// coerceArray coerces a "[a,b,c]" literal into a slice/array of the element type.
func (c *coercer) coerceArray(t gethabi.Type, s string, index int) (any, error) {
	elems, err := splitLiteral(s, '[', ']')
	if err != nil {
		return nil, errBadArg(index, t.String(), err.Error())
	}
	if t.T == gethabi.ArrayTy && len(elems) != t.Size {
		return nil, errBadArg(index, t.String(), fmt.Sprintf("fixed array expects %d element(s), got %d", t.Size, len(elems)))
	}
	rt := t.GetType()
	var rv reflect.Value
	if t.T == gethabi.SliceTy {
		rv = reflect.MakeSlice(rt, len(elems), len(elems))
	} else {
		rv = reflect.New(rt).Elem()
	}
	for i, el := range elems {
		ev, err := c.coerce(*t.Elem, el, index)
		if err != nil {
			return nil, err
		}
		rv.Index(i).Set(reflect.ValueOf(ev))
	}
	return rv.Interface(), nil
}

// coerceTuple coerces a "(a,b,c)" literal into the struct Pack expects for the tuple
// (a reflect.StructOf whose fields are the tuple components in order).
func (c *coercer) coerceTuple(t gethabi.Type, s string, index int) (any, error) {
	elems, err := splitLiteral(s, '(', ')')
	if err != nil {
		return nil, errBadArg(index, t.String(), err.Error())
	}
	if len(elems) != len(t.TupleElems) {
		return nil, errBadArg(index, t.String(), fmt.Sprintf("tuple expects %d component(s), got %d", len(t.TupleElems), len(elems)))
	}
	rv := reflect.New(t.GetType()).Elem()
	for i, comp := range t.TupleElems {
		cv, err := c.coerce(*comp, elems[i], index)
		if err != nil {
			return nil, err
		}
		rv.Field(i).Set(reflect.ValueOf(cv))
	}
	return rv.Interface(), nil
}

// ParseLiteral parses ONE user literal into the native Go value gethabi.Pack wants
// for solidity type t, recursively (the exported entry to the same descent CoerceArgs
// uses). Address-typed scalars are accepted as raw 0x only (ParseLiteral is the pure,
// resolver-free entry — service uses CoerceArgs with a resolver for the signing
// paths). A malformed literal is usage.bad_arg (exit 2) naming the expected type.
func (Codec) ParseLiteral(t gethabi.Type, literal string) (any, error) {
	c := &coercer{resolve: nil}
	return c.coerce(t, literal, 0)
}

// ── scalar coercers ────────────────────────────────────────────────────────────────

// coerceBool accepts exactly "true"/"false".
func coerceBool(s string, t gethabi.Type, index int) (bool, error) {
	switch strings.TrimSpace(s) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, errBadArg(index, t.String(), fmt.Sprintf("%q is not true/false", s))
	}
}

// coerceDynBytes accepts a 0x hex string (any even length) → []byte. The empty
// encoding "0x" → empty slice.
func coerceDynBytes(s string, t gethabi.Type, index int) ([]byte, error) {
	b, err := parseHexBytes(s)
	if err != nil {
		return nil, errBadArg(index, t.String(), err.Error())
	}
	return b, nil
}

// coerceFixedBytes accepts a 0x hex string of EXACTLY t.Size bytes → [Size]byte. A
// wrong length is usage.bad_arg (length-checked, §2.5).
func coerceFixedBytes(t gethabi.Type, s string, index int) (any, error) {
	b, err := parseHexBytes(s)
	if err != nil {
		return nil, errBadArg(index, t.String(), err.Error())
	}
	if len(b) != t.Size {
		return nil, errBadArg(index, t.String(), fmt.Sprintf("expected %d bytes, got %d", t.Size, len(b)))
	}
	arr := reflect.New(t.GetType()).Elem()
	reflect.Copy(arr, reflect.ValueOf(b))
	return arr.Interface(), nil
}

// ── numeric helpers ──────────────────────────────────────────────────────────────

// parseBigInt parses a decimal or 0x-hex integer string (optionally signed). It
// supports arbitrary precision (a uint256 far exceeds int64). Whitespace is trimmed.
func parseBigInt(s string) (*big.Int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	var v *big.Int
	var ok bool
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, ok = new(big.Int).SetString(s[2:], 16)
	} else {
		v, ok = new(big.Int).SetString(s, 10)
	}
	if !ok || v == nil {
		return nil, false
	}
	if neg {
		v.Neg(v)
	}
	return v, true
}

// checkIntRange verifies v fits the declared (signed/unsigned, bit-size) integer.
func checkIntRange(v *big.Int, t gethabi.Type, index int) error {
	bits := t.Size
	if bits <= 0 || bits > 256 {
		return errBadArg(index, t.String(), "unsupported integer size")
	}
	if t.T == gethabi.UintTy {
		if v.Sign() < 0 {
			return errBadArg(index, t.String(), "negative value for an unsigned type")
		}
		// max = 2^bits - 1
		max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
		if v.Cmp(max) > 0 {
			return errBadArg(index, t.String(), "value exceeds the type's maximum")
		}
		return nil
	}
	// signed: range [-2^(bits-1), 2^(bits-1)-1]
	max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), big.NewInt(1))
	min := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)))
	if v.Cmp(max) > 0 || v.Cmp(min) < 0 {
		return errBadArg(index, t.String(), "value out of range for the signed type")
	}
	return nil
}

// convertToReflectInt builds the native Go integer value Pack expects for type t.
// geth's GetType returns *big.Int for sizes > 64 bits and the sized (u)int otherwise;
// we produce a value assignable to exactly that reflect type so Pack/Set never panics.
//
// The sized truncations below are SAFE: coerceInt calls checkIntRange BEFORE this, so
// v is already proven to fit the declared (signedness, bit-size). The #nosec G115
// annotations record that the bound is enforced one frame up (the same pattern erc/
// metadata.go uses for its decimals() read).
func convertToReflectInt(v *big.Int, t gethabi.Type) (any, error) {
	rt := t.GetType()
	switch rt.Kind() {
	case reflect.Pointer:
		// *big.Int
		return new(big.Int).Set(v), nil
	case reflect.Uint8:
		return uint8(v.Uint64()), nil // #nosec G115 -- range-checked by checkIntRange above
	case reflect.Uint16:
		return uint16(v.Uint64()), nil // #nosec G115 -- range-checked by checkIntRange above
	case reflect.Uint32:
		return uint32(v.Uint64()), nil // #nosec G115 -- range-checked by checkIntRange above
	case reflect.Uint64:
		return v.Uint64(), nil
	case reflect.Int8:
		return int8(v.Int64()), nil // #nosec G115 -- range-checked by checkIntRange above
	case reflect.Int16:
		return int16(v.Int64()), nil // #nosec G115 -- range-checked by checkIntRange above
	case reflect.Int32:
		return int32(v.Int64()), nil // #nosec G115 -- range-checked by checkIntRange above
	case reflect.Int64:
		return v.Int64(), nil
	default:
		// Any other size geth represents as *big.Int.
		return new(big.Int).Set(v), nil
	}
}

// parseHexBytes parses a 0x-prefixed even-length hex string into bytes. "0x" → empty.
// A missing 0x prefix, odd length, or non-hex char is an error.
func parseHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return nil, fmt.Errorf("%q must be a 0x hex string", s)
	}
	body := s[2:]
	if len(body)%2 != 0 {
		return nil, fmt.Errorf("hex string has an odd length")
	}
	b, err := hex.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %v", err)
	}
	return b, nil
}

// ── compound-literal splitter (the array/tuple grammar) ──────────────────────────

// splitLiteral parses a bracketed compound literal into its top-level element
// strings. open/close are the delimiters ('[' / ']' for arrays, '(' / ')' for
// tuples). It honors nesting (a bracket depth counter) and double-quoted elements
// (a delimiter inside "…" with \" and \\ escapes is literal, never a separator).
// "[]" / "()" yield zero elements. A mismatched/unbalanced literal is an error.
//
// The grammar (one cast-compatible form, §2.5):
//
//	array  t[]/t[N] : "[a,b,c]"   nesting allowed: "[[1,2],[3]]"
//	tuple  (T1,..)  : "(a,b,c)"   nesting allowed: "([0x..,5],true)"
//	a delimiter-containing element is double-quoted: "\"a,b\"" with \" / \\ escapes
func splitLiteral(s string, open, close byte) ([]string, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != open || s[len(s)-1] != close {
		return nil, fmt.Errorf("expected %c…%c, got %q", open, close, s)
	}
	inner := s[1 : len(s)-1]
	if strings.TrimSpace(inner) == "" {
		return nil, nil // empty literal
	}

	var (
		elems []string
		buf   strings.Builder
		depth int  // bracket/paren nesting depth
		inStr bool // inside a double-quoted element
		esc   bool // previous char was a backslash (inside a string)
	)
	for i := 0; i < len(inner); i++ {
		ch := inner[i]
		if inStr {
			if esc {
				// An escaped char is literal; only \" and \\ are meaningful, but we
				// keep any escaped char verbatim (the unescaper runs in unquote()).
				buf.WriteByte(ch)
				esc = false
				continue
			}
			switch ch {
			case '\\':
				esc = true
				buf.WriteByte(ch)
			case '"':
				inStr = false
				buf.WriteByte(ch)
			default:
				buf.WriteByte(ch)
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
			buf.WriteByte(ch)
		case '[', '(':
			depth++
			buf.WriteByte(ch)
		case ']', ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced %q", s)
			}
			buf.WriteByte(ch)
		case ',':
			if depth == 0 {
				elems = append(elems, strings.TrimSpace(buf.String()))
				buf.Reset()
			} else {
				buf.WriteByte(ch)
			}
		default:
			buf.WriteByte(ch)
		}
	}
	if inStr {
		return nil, fmt.Errorf("unterminated quoted element in %q", s)
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced brackets in %q", s)
	}
	elems = append(elems, strings.TrimSpace(buf.String()))

	// Unquote any fully double-quoted element (the delimiter-escape form) so the
	// inner scalar coercer sees the raw value.
	for i, e := range elems {
		if uq, ok := unquote(e); ok {
			elems[i] = uq
		}
	}
	return elems, nil
}

// unquote removes the surrounding double-quotes from a fully-quoted element and
// resolves \" and \\ escapes. Returns ok=false (and the input unchanged) when the
// element is not a fully double-quoted string, so unquoted scalars pass through.
func unquote(s string) (string, bool) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s, false
	}
	body := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) {
			next := body[i+1]
			if next == '"' || next == '\\' {
				b.WriteByte(next)
				i++
				continue
			}
		}
		b.WriteByte(body[i])
	}
	return b.String(), true
}
