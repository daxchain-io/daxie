package domain

import (
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// RefKind enumerates the five account-reference shapes (cli-spec §1).
type RefKind int

const (
	// RefHDIndex is an HD account by numeric index: "treasury/3".
	RefHDIndex RefKind = iota + 1
	// RefHDAlias is an HD account by alias: "treasury/payroll".
	RefHDAlias
	// RefNamed is a standalone imported account (shares the wallet namespace):
	// "ops-key".
	RefNamed
	// RefAddress is a raw 0x address (read-only ops only): "0x52ae…".
	RefAddress
	// RefENS is an ENS name (destinations + read-only): "vitalik.eth".
	RefENS
)

// String returns a stable lowercase tag for the kind, used in messages and tests.
func (k RefKind) String() string {
	switch k {
	case RefHDIndex:
		return "hd-index"
	case RefHDAlias:
		return "hd-alias"
	case RefNamed:
		return "named"
	case RefAddress:
		return "address"
	case RefENS:
		return "ens"
	default:
		return "unknown"
	}
}

// AccountRef is a parsed (not yet resolved) account reference. M0 parses the
// shape and validates address hex; alias/index/ENS resolution against the
// keystore and chain is M1+ (it fills Addr later).
type AccountRef struct {
	Raw    string         // the original input
	Kind   RefKind        // which shape it parsed to
	Wallet string         // RefHDIndex / RefHDAlias: the wallet segment
	Index  uint32         // RefHDIndex: the numeric index
	Name   string         // RefHDAlias alias / RefNamed name / RefENS label
	Addr   common.Address // RefAddress (parsed now); other kinds: filled after resolution
}

// ParseAccountRef classifies a user account reference into one of the five
// RefKinds. It returns a usage.* error for a malformed input and a ref.ambiguous
// error for input whose shape could be read two ways (§5.7).
//
// Classification order (each shape is mutually exclusive by construction):
//   - contains "/"  -> HD ref: numeric tail => RefHDIndex, else RefHDAlias
//   - "0x"-prefixed -> must be a valid 20-byte hex address => RefAddress
//   - ends ".eth"   -> RefENS (label = the part before ".eth")
//   - otherwise     -> RefNamed
//
// Resolution (alias->index, ENS->address, name->account) is M1; M0 only needs
// the shape so commands can echo and route.
func ParseAccountRef(s string) (AccountRef, error) {
	raw := s
	s = strings.TrimSpace(s)
	if s == "" {
		return AccountRef{}, New(CodeUsage+".empty_account_ref", "account reference is empty")
	}

	// ── HD reference: "<wallet>/<index-or-alias>" ──
	if i := strings.IndexByte(s, '/'); i >= 0 {
		wallet := s[:i]
		tail := s[i+1:]
		if wallet == "" {
			return AccountRef{}, Newf(CodeUsage+".bad_account_ref",
				"account reference %q has an empty wallet name before '/'", raw)
		}
		if tail == "" {
			return AccountRef{}, Newf(CodeUsage+".bad_account_ref",
				"account reference %q has an empty index/alias after '/'", raw)
		}
		if strings.ContainsRune(tail, '/') {
			return AccountRef{}, Newf(CodeUsage+".bad_account_ref",
				"account reference %q has more than one '/'", raw)
		}
		// A wallet segment that is itself address- or ENS-shaped is ambiguous:
		// the operator may have meant a raw address but typed a path.
		if looksLikeAddress(wallet) || looksLikeENS(wallet) {
			return AccountRef{}, Newf(CodeRefAmbiguous,
				"account reference %q: wallet segment looks like an address/ENS name", raw)
		}
		if idx, ok := parseIndex(tail); ok {
			return AccountRef{Raw: raw, Kind: RefHDIndex, Wallet: wallet, Index: idx}, nil
		}
		// Non-numeric tail is an alias.
		if !validNameSegment(tail) {
			return AccountRef{}, Newf(CodeUsage+".bad_account_ref",
				"account reference %q has an invalid alias segment", raw)
		}
		return AccountRef{Raw: raw, Kind: RefHDAlias, Wallet: wallet, Name: tail}, nil
	}

	// ── Raw address: "0x…" ──
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if !common.IsHexAddress(s) {
			// 0x-prefixed but not a 20-byte address: a malformed address, not a
			// name (names never start with 0x in practice). usage, not ambiguous.
			return AccountRef{}, Newf(CodeUsage+".bad_address",
				"account reference %q starts with 0x but is not a 20-byte address", raw)
		}
		return AccountRef{Raw: raw, Kind: RefAddress, Addr: common.HexToAddress(s)}, nil
	}

	// ── ENS name: "<label>.eth" ──
	if looksLikeENS(s) {
		// The ".eth" suffix is matched case-insensitively (looksLikeENS folds
		// case), so trim by length rather than a literal lowercase suffix; this
		// keeps the label's original case (ENS normalization is M1+).
		label := s[:len(s)-len(".eth")]
		if label == "" || strings.HasPrefix(label, ".") || strings.HasSuffix(label, ".") {
			return AccountRef{}, Newf(CodeUsage+".bad_ens",
				"account reference %q is not a valid ENS name", raw)
		}
		return AccountRef{Raw: raw, Kind: RefENS, Name: label}, nil
	}

	// ── Bare standalone name ──
	if !validNameSegment(s) {
		return AccountRef{}, Newf(CodeUsage+".bad_account_ref",
			"account reference %q is not a valid name", raw)
	}
	return AccountRef{Raw: raw, Kind: RefNamed, Name: s}, nil
}

// looksLikeAddress reports a 0x-prefixed valid 20-byte hex address.
func looksLikeAddress(s string) bool {
	return (strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X")) && common.IsHexAddress(s)
}

// looksLikeENS reports a ".eth"-suffixed name (case-folded suffix).
func looksLikeENS(s string) bool {
	return strings.HasSuffix(strings.ToLower(s), ".eth")
}

// parseIndex parses an unsigned decimal HD index (no sign, no leading zeros
// beyond a lone "0", fits uint32). Returns ok=false for any non-index tail.
func parseIndex(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	// Reject leading zeros (e.g. "01") to keep the canonical form unambiguous,
	// except a single "0".
	if len(s) > 1 && s[0] == '0' {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		v = v*10 + uint64(s[i]-'0')
		if v > 0xFFFFFFFF { // BIP-32 non-hardened index ceiling for our purposes
			return 0, false
		}
	}
	return uint32(v), true
}

// validNameSegment accepts a conservative name charset (alnum plus '-', '_',
// '.') with no whitespace. Resolution against the namespace is M1; this only
// rejects obviously malformed inputs.
func validNameSegment(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}
