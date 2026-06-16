package domain

import (
	"errors"
	"testing"
)

// This file is the M1 §3.2 grammar coverage for ParseAccountRef, complementing the
// M0 account_ref_test.go (which it does not modify). It pins, table-driven, the
// reference-shape routing every RefKind, the reserved-char rejection (/, #, .),
// the address/ENS ambiguity edges, and the index-vs-alias boundary that makes
// "aliases are never purely numeric" structurally true.
//
// SCOPE NOTE (parse vs. resolve). ParseAccountRef lives in domain and only
// classifies the SHAPE so commands can route; it deliberately does NOT enforce the
// §3.1 STORAGE name grammar [a-z0-9][a-z0-9_-]{0,63} (uppercase, length, leading/
// trailing '-' are accepted here). That stricter grammar — plus the reject-0x-shape
// and not-purely-numeric-alias rules at CREATE time, and the RefAddress/ENS/
// bare-wallet rejection in a SIGNING context — is enforced by the keys provider
// (LookupSigning / create / import, Group B), where it can consult the namespace.
// The cases below assert exactly what the PARSE layer guarantees.

// TestParseAccountRefRefKinds covers every RefKind once (the §3.2 shape table).
func TestParseAccountRefRefKinds(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantKind RefKind
	}{
		{"hd index", "treasury/3", RefHDIndex},
		{"hd index zero", "treasury/0", RefHDIndex},
		{"hd alias", "treasury/payroll", RefHDAlias},
		{"named", "ops-key", RefNamed},
		{"address", "0x52908400098527886E0F7030069857D2E4169EE7", RefAddress},
		{"ens", "vitalik.eth", RefENS},
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
		})
	}
}

// TestParseAccountRefReservedHash asserts the reserved '#' separator fails closed
// in every position (it is a future asset/token separator, never a name char).
func TestParseAccountRefReservedHash(t *testing.T) {
	for _, in := range []string{"a#b", "treasury#3", "treasury/pay#roll", "#x", "x#"} {
		t.Run(in, func(t *testing.T) {
			_, err := ParseAccountRef(in)
			if err == nil {
				t.Fatalf("ParseAccountRef(%q) with reserved '#' must error", in)
			}
			assertCode(t, err, CodeUsage+".bad_account_ref")
		})
	}
}

// TestParseAccountRefReservedSlash asserts '/' is the HD separator: a single '/'
// splits, a second '/' is rejected, and an empty side is rejected.
func TestParseAccountRefReservedSlash(t *testing.T) {
	cases := []struct {
		in       string
		wantCode string
	}{
		{"a/b/c", CodeUsage + ".bad_account_ref"},     // two separators
		{"/3", CodeUsage + ".bad_account_ref"},        // empty wallet
		{"treasury/", CodeUsage + ".bad_account_ref"}, // empty tail
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			_, err := ParseAccountRef(c.in)
			if err == nil {
				t.Fatalf("ParseAccountRef(%q) must error", c.in)
			}
			assertCode(t, err, c.wantCode)
		})
	}
}

// TestParseAccountRefAddressShape: a 0x-prefixed input is the address shape — a
// VALID 20-byte address parses as RefAddress; a malformed 0x input is a usage
// error (never silently treated as a name). The signing-context REJECTION of a
// RefAddress is keys.LookupSigning's job, not the parser's.
func TestParseAccountRefAddressShape(t *testing.T) {
	const addr = "0x52908400098527886E0F7030069857D2E4169EE7"
	ref, err := ParseAccountRef(addr)
	if err != nil {
		t.Fatalf("valid address must parse: %v", err)
	}
	if ref.Kind != RefAddress {
		t.Fatalf("kind = %v, want RefAddress", ref.Kind)
	}
	for _, bad := range []string{"0x1234", "0xZZ908400098527886E0F7030069857D2E4169EE7"} {
		if _, err := ParseAccountRef(bad); err == nil {
			t.Errorf("malformed address %q must error, not parse as a name", bad)
		} else {
			assertCode(t, err, CodeUsage+".bad_address")
		}
	}
}

// TestParseAccountRefAmbiguity: an address- or ENS-shaped WALLET segment in an HD
// ref is ref.ambiguous (the operator may have meant a raw address but typed a
// path). This is the one place the parser raises ambiguity rather than usage.
func TestParseAccountRefAmbiguity(t *testing.T) {
	for _, in := range []string{
		"0x52908400098527886E0F7030069857D2E4169EE7/3",
		"vitalik.eth/3",
	} {
		t.Run(in, func(t *testing.T) {
			_, err := ParseAccountRef(in)
			if err == nil {
				t.Fatalf("ParseAccountRef(%q) must be ambiguous", in)
			}
			assertCode(t, err, CodeRefAmbiguous)
		})
	}
}

// TestParseAccountRefAliasNeverPurelyNumeric is the structural guarantee behind
// "aliases are never purely numeric" (§3.1): a purely-numeric tail ALWAYS routes
// to RefHDIndex, so an alias (RefHDAlias) can never carry a purely-numeric Name at
// the parse layer — except a digit string too long/leading-zeroed to be a
// canonical index, which routes to RefHDAlias (resolution then fails to find it,
// which is the correct closed behavior; a digit-only ALIAS can never be CREATED,
// enforced by keys).
func TestParseAccountRefAliasNeverPurelyNumeric(t *testing.T) {
	// Canonical numeric tails -> index, never alias.
	for _, in := range []string{"w/0", "w/3", "w/4294967295"} {
		ref, err := ParseAccountRef(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if ref.Kind != RefHDIndex {
			t.Errorf("%q routed to %v, want RefHDIndex (numeric tail is always an index)", in, ref.Kind)
		}
	}
	// Non-canonical digit tails (leading zero, > uint32) fall to alias SHAPE; keys
	// rejects creating such an alias and resolution will not find it.
	for _, in := range []string{"w/01", "w/4294967296"} {
		ref, err := ParseAccountRef(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if ref.Kind != RefHDAlias {
			t.Errorf("%q routed to %v, want RefHDAlias shape", in, ref.Kind)
		}
	}
}

// TestParseAccountRefDottedBareNameIsNamed documents a parse-layer divergence from
// §3.1's "'.' is reserved" intent that the M0 parser deliberately keeps: a bare
// dotted name that does NOT end in ".eth" routes to RefNamed (e.g. "ops.key"),
// not ENS. This is load-bearing for the M0 contract (it has a passing test for it)
// and is harmless because keys' §3.1 create grammar forbids '.' in a stored name,
// so such a ref can be PARSED but never RESOLVED to a created object.
func TestParseAccountRefDottedBareNameIsNamed(t *testing.T) {
	ref, err := ParseAccountRef("ops.key")
	if err != nil {
		t.Fatalf("ops.key: %v", err)
	}
	if ref.Kind != RefNamed || ref.Name != "ops.key" {
		t.Errorf("ops.key = {%v, %q}, want {RefNamed, ops.key}", ref.Kind, ref.Name)
	}
	// A ".eth" suffix is the ENS branch.
	ens, err := ParseAccountRef("ops.eth")
	if err != nil {
		t.Fatalf("ops.eth: %v", err)
	}
	if ens.Kind != RefENS {
		t.Errorf("ops.eth kind = %v, want RefENS", ens.Kind)
	}
}

// TestParseAccountRefEmpty: an empty (or whitespace-only) ref is its own usage code.
func TestParseAccountRefEmpty(t *testing.T) {
	for _, in := range []string{"", "   "} {
		_, err := ParseAccountRef(in)
		if err == nil {
			t.Fatalf("ParseAccountRef(%q) must error", in)
		}
		assertCode(t, err, CodeUsage+".empty_account_ref")
	}
}

// assertCode fails unless err is a *domain.Error carrying want.
func assertCode(t *testing.T, err error, want string) {
	t.Helper()
	var de *Error
	if !errors.As(err, &de) {
		t.Fatalf("error is not *domain.Error: %T (%v)", err, err)
	}
	if de.Code != want {
		t.Errorf("code = %q, want %q", de.Code, want)
	}
}
