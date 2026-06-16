package keys

import (
	"context"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
)

func TestNamespaceCollisionRejection(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "treasury", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()

	// standalone named "treasury" collides with the wallet. (The name grammar is
	// lowercase-only, so "Treasury"/"TREASURY" are rejected as invalid names BEFORE
	// the collision check — the case-insensitive collision rule only bites for the
	// equal-case form here, which is the exact-collision case.)
	key := secret.NewString("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	_, _, e0 := s.ImportStandalone(context.Background(), "treasury", key, pass)
	key.Zero()
	if !codeIs(e0, CodeUsageNameCollision) {
		t.Fatalf("standalone \"treasury\" vs wallet: got %v, want %s", e0, CodeUsageNameCollision)
	}

	// Reverse: a wallet colliding with an existing standalone.
	k := secret.NewString("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	if _, _, e := s.ImportStandalone(context.Background(), "ops", k, pass); e != nil {
		t.Fatal(e)
	}
	k.Zero()
	if _, e := s.CreateWallet(context.Background(), "ops", 12, pass); !codeIs(e, CodeUsageNameCollision) {
		t.Fatalf("wallet vs standalone: got %v", e)
	}

	// Rename onto an existing name collides.
	cr2, _ := s.CreateWallet(context.Background(), "cold", 12, pass)
	cr2.Mnemonic.Zero()
	cr2.BIP39Pass.Zero()
	if _, e := s.RenameWallet(context.Background(), "cold", "treasury"); !codeIs(e, CodeUsageNameCollision) {
		t.Fatalf("rename collision: got %v", e)
	}
}

func TestInvalidNamesRejected(t *testing.T) {
	s, pass := initStore(t)
	bad := []string{
		"with/slash", "with#hash", "with.dot",
		"0x52ae0000000000000000000000000000000000a1", // address shape
		"-leadingdash", "_leadingunderscore",
		"UPPER", // grammar is lowercase
		"",
		strings.Repeat("a", 65),
	}
	for _, n := range bad {
		if _, e := s.CreateWallet(context.Background(), n, 12, pass); !codeIs(e, CodeUsageInvalidName) {
			t.Errorf("name %q: got %v, want %s", n, e, CodeUsageInvalidName)
		}
	}
}

func TestLookupSigningRejectsReadOnlyShapes(t *testing.T) {
	s, pass := initStore(t)
	importAbandon(t, s, pass, "tre")

	// Raw address in a SIGNING position is rejected.
	addr, _ := domain.ParseAccountRef("0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
	if _, e := s.LookupSigning(addr); !codeIs(e, CodeUsageReadOnlyContext) {
		t.Fatalf("address signing: got %v, want %s", e, CodeUsageReadOnlyContext)
	}
	// ENS in a signing position is rejected.
	ens, _ := domain.ParseAccountRef("vitalik.eth")
	if _, e := s.LookupSigning(ens); !codeIs(e, CodeUsageReadOnlyContext) {
		t.Fatalf("ens signing: got %v", e)
	}
	// A BARE WALLET name in a signing context is ref.not_found with a hint.
	bare, _ := domain.ParseAccountRef("tre")
	_, e := s.LookupSigning(bare)
	if !codeIs(e, CodeRefNotFound) {
		t.Fatalf("bare wallet signing: got %v, want %s", e, CodeRefNotFound)
	}
	if !strings.Contains(e.Error(), "tre/0") {
		t.Fatalf("expected a 'did you mean tre/0' hint, got: %v", e)
	}
}

func TestLookupSigningDistinctNotFound(t *testing.T) {
	s, pass := initStore(t)
	importAbandon(t, s, pass, "tre")

	// Unknown wallet.
	r1, _ := domain.ParseAccountRef("nope/0")
	if _, e := s.LookupSigning(r1); !codeIs(e, CodeRefNotFound) || !strings.Contains(e.Error(), "no wallet") {
		t.Fatalf("unknown wallet: %v", e)
	}
	// Unknown index.
	r2, _ := domain.ParseAccountRef("tre/99")
	if _, e := s.LookupSigning(r2); !codeIs(e, CodeRefNotFound) || !strings.Contains(e.Error(), "index") {
		t.Fatalf("unknown index: %v", e)
	}
	// Unknown alias.
	r3, _ := domain.ParseAccountRef("tre/ghost")
	if _, e := s.LookupSigning(r3); !codeIs(e, CodeRefNotFound) || !strings.Contains(e.Error(), "alias") {
		t.Fatalf("unknown alias: %v", e)
	}
}

func TestAddressOfDestinationContext(t *testing.T) {
	s, pass := initStore(t)
	importAbandon(t, s, pass, "tre")

	// Raw address resolves to itself (destination context).
	addr, _ := domain.ParseAccountRef("0x9858EfFD232B4033E47d90003D41EC34EcaEda94")
	got, err := s.AddressOf(addr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(got.Hex(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94") {
		t.Fatalf("AddressOf(address) = %s", got.Hex())
	}
	// HD ref resolves to its cached address WITHOUT unlock (no passphrase passed).
	hd, _ := domain.ParseAccountRef("tre/0")
	a0, err := s.AddressOf(hd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(a0.Hex(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94") {
		t.Fatalf("AddressOf(tre/0) = %s", a0.Hex())
	}
	// ENS is not the keystore's job.
	ens, _ := domain.ParseAccountRef("vitalik.eth")
	if _, e := s.AddressOf(ens); !codeIs(e, CodeUsageReadOnlyContext) {
		t.Fatalf("AddressOf(ens): got %v", e)
	}
}
