package keys

import (
	"context"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
)

// importAbandon creates a wallet from the known abandon… mnemonic so derived
// addresses are the iancoleman vectors.
func importAbandon(t *testing.T, s *Store, pass *secret.Bytes, name string) {
	t.Helper()
	mn := secret.NewString(abandonMnemonic)
	defer mn.Zero()
	b39 := secret.NewString("")
	defer b39.Zero()
	if _, _, err := s.ImportWallet(context.Background(), name, mn, b39, pass); err != nil {
		t.Fatalf("import %s: %v", name, err)
	}
}

func TestDeriveNextAndIndexMatchVectors(t *testing.T) {
	s, pass := initStore(t)
	importAbandon(t, s, pass, "tre")

	// next index after auto-0 is 1, matching the vector.
	idx, addr, err := s.DeriveNext(context.Background(), "tre", pass)
	if err != nil {
		t.Fatal(err)
	}
	if idx != 1 || !strings.EqualFold(addr.Hex(), "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0") {
		t.Fatalf("DeriveNext = %d/%s", idx, addr.Hex())
	}
	// DeriveIndex(0) is idempotent (cached) and matches the vector.
	a0, err := s.DeriveIndex(context.Background(), "tre", 0, pass)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(a0.Hex(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94") {
		t.Fatalf("DeriveIndex(0) = %s", a0.Hex())
	}
}

func TestAliasUnalias(t *testing.T) {
	s, pass := initStore(t)
	importAbandon(t, s, pass, "tre")
	if _, _, err := s.DeriveNext(context.Background(), "tre", pass); err != nil { // index 1
		t.Fatal(err)
	}
	if err := s.Alias(context.Background(), "tre", 1, "payroll"); err != nil {
		t.Fatal(err)
	}
	// Resolve by alias.
	ref, _ := domain.ParseAccountRef("tre/payroll")
	info, err := s.ShowAccount(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if info.Index != 1 || info.Alias != "payroll" {
		t.Fatalf("alias resolve = %+v", info)
	}
	// Numeric alias rejected.
	if err := s.Alias(context.Background(), "tre", 1, "42"); !codeIs(err, CodeUsageInvalidName) {
		t.Fatalf("numeric alias: got %v", err)
	}
	// Unalias.
	removed, err := s.Unalias(context.Background(), "tre", 1)
	if err != nil || removed != "payroll" {
		t.Fatalf("unalias = %q, %v", removed, err)
	}
	if _, e := s.ShowAccount(context.Background(), ref); !codeIs(e, CodeRefNotFound) {
		t.Fatal("alias should be gone")
	}
}

func TestImportStandaloneStockGethFile(t *testing.T) {
	s, pass := initStore(t)
	// A known key -> known address.
	key := secret.NewString("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	defer key.Zero()
	id, addr, err := s.ImportStandalone(context.Background(), "ops", key, pass)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("empty account id")
	}
	// Known address for that key (the go-ethereum canonical test key).
	want := "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
	if !strings.EqualFold(addr.Hex(), want) {
		t.Fatalf("standalone addr = %s, want %s", addr.Hex(), want)
	}
	// Duplicate name rejected.
	key2 := secret.NewString("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer key2.Zero()
	if _, _, e := s.ImportStandalone(context.Background(), "ops", key2, pass); !codeIs(e, CodeUsageNameCollision) {
		t.Fatalf("dup name: got %v", e)
	}
	// Duplicate ADDRESS (same key, different name) rejected.
	keyDup := secret.NewString("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	defer keyDup.Zero()
	if _, _, e := s.ImportStandalone(context.Background(), "other", keyDup, pass); !codeIs(e, CodeUsageNameCollision) {
		t.Fatalf("dup address: got %v", e)
	}
}

func TestImportStandaloneRejectsOutOfRangeKey(t *testing.T) {
	s, pass := initStore(t)
	zero := secret.NewString("0x0000000000000000000000000000000000000000000000000000000000000000")
	defer zero.Zero()
	if _, _, e := s.ImportStandalone(context.Background(), "z", zero, pass); !codeIs(e, CodeUsageBadKey) {
		t.Fatalf("zero key: got %v, want %s", e, CodeUsageBadKey)
	}
}

func TestListAccounts(t *testing.T) {
	s, pass := initStore(t)
	importAbandon(t, s, pass, "tre")
	if _, _, err := s.DeriveNext(context.Background(), "tre", pass); err != nil {
		t.Fatal(err)
	}
	key := secret.NewString("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	defer key.Zero()
	if _, _, err := s.ImportStandalone(context.Background(), "ops", key, pass); err != nil {
		t.Fatal(err)
	}

	all, err := s.ListAccounts(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	// 2 HD (index 0,1) + 1 standalone = 3.
	if len(all) != 3 {
		t.Fatalf("ListAccounts = %d entries, want 3", len(all))
	}
	// Filter to the wallet excludes standalone.
	filt, _ := s.ListAccounts(context.Background(), "tre")
	if len(filt) != 2 {
		t.Fatalf("filtered list = %d, want 2", len(filt))
	}
	for _, a := range filt {
		if a.Kind != "hd" {
			t.Fatalf("wallet filter returned a %s account", a.Kind)
		}
	}
}

func TestSetDefaultAndResolution(t *testing.T) {
	s, pass := initStore(t)
	importAbandon(t, s, pass, "bot")
	ref, _ := domain.ParseAccountRef("bot/0")
	if err := s.SetDefault(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	def, ok := s.DefaultAccount(context.Background())
	if !ok || def != "bot/0" {
		t.Fatalf("default = %q, ok=%v", def, ok)
	}
	// A bare wallet cannot be the default.
	bare, _ := domain.ParseAccountRef("bot")
	if err := s.SetDefault(context.Background(), bare); err == nil {
		t.Fatal("a bare wallet should not be settable as default")
	}
	// An address ref cannot be the default.
	addrRef, _ := domain.ParseAccountRef("0x2f015c60e0be116b1f0cd534704db9c92118fb6a")
	if err := s.SetDefault(context.Background(), addrRef); !codeIs(err, CodeUsageReadOnlyContext) {
		t.Fatalf("address default: got %v", err)
	}
}

func TestDeleteStandaloneRemovesFile(t *testing.T) {
	s, pass := initStore(t)
	key := secret.NewString("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	defer key.Zero()
	if _, _, err := s.ImportStandalone(context.Background(), "ops", key, pass); err != nil {
		t.Fatal(err)
	}
	ref, _ := domain.ParseAccountRef("ops")
	mode, err := s.DeleteAccount(context.Background(), ref)
	if err != nil || mode != "remove" {
		t.Fatalf("delete standalone: mode=%s err=%v", mode, err)
	}
	if _, e := s.ShowAccount(context.Background(), ref); !codeIs(e, CodeRefNotFound) {
		t.Fatal("standalone not removed")
	}
}

func TestExportStandaloneRoundTrip(t *testing.T) {
	s, pass := initStore(t)
	rawHex := "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	key := secret.NewString(rawHex)
	defer key.Zero()
	if _, _, err := s.ImportStandalone(context.Background(), "ops", key, pass); err != nil {
		t.Fatal(err)
	}
	ref, _ := domain.ParseAccountRef("ops")
	out, err := s.ExportStandalone(context.Background(), ref, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Zero()
	if !strings.EqualFold(string(out.Reveal()), rawHex) {
		t.Fatalf("exported key = %s, want %s", out.Reveal(), rawHex)
	}
	// Exporting an HD ref this way is rejected.
	importAbandon(t, s, pass, "hd")
	hdRef, _ := domain.ParseAccountRef("hd/0")
	if _, e := s.ExportStandalone(context.Background(), hdRef, pass); !codeIs(e, CodeRefNotFound) {
		t.Fatalf("HD export via standalone path: got %v", e)
	}
}
