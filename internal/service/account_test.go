package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// account_test.go drives the M1 account use cases (HD derive/alias/unalias/use/
// list/show/delete + standalone import/export) against a real light-KDF keystore.

// seedWallet creates a wallet named `name` and returns the service.
func seedWallet(t *testing.T, svc *Service, name string) {
	t.Helper()
	if _, err := svc.WalletCreate(context.Background(), domain.LocalCLI(),
		domain.WalletCreateRequest{Name: name, Yes: true}, WalletCreateInput{}, nil); err != nil {
		t.Fatalf("seed wallet %q: %v", name, err)
	}
}

func TestAccountDeriveAndAlias(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()
	seedWallet(t, svc, "treasury")

	// derive next (index 0 already materialized by create → next is 1).
	d1, err := svc.AccountDerive(ctx, p, domain.AccountDeriveRequest{Wallet: "treasury", Yes: true}, AccountDeriveInput{}, nil)
	if err != nil {
		t.Fatalf("derive next: %v", err)
	}
	if d1.Index != 1 {
		t.Errorf("first derive-next index = %d, want 1 (0 is auto-derived on create)", d1.Index)
	}

	// derive explicit index with an inline alias.
	idx := uint32(3)
	d3, err := svc.AccountDerive(ctx, p,
		domain.AccountDeriveRequest{Wallet: "treasury", Index: &idx, Name: "payroll", Yes: true},
		AccountDeriveInput{}, nil)
	if err != nil {
		t.Fatalf("derive index 3: %v", err)
	}
	if d3.Index != 3 || d3.Alias != "payroll" || d3.Ref != "treasury/payroll" {
		t.Errorf("derive+alias result = %+v, want index 3 alias payroll", d3)
	}

	// show by alias resolves the same address.
	show, err := svc.AccountShow(ctx, p, domain.AccountShowRequest{Ref: "treasury/payroll"})
	if err != nil {
		t.Fatalf("show by alias: %v", err)
	}
	if !strings.EqualFold(show.Address, d3.Address) {
		t.Errorf("show-by-alias address %q != derive address %q", show.Address, d3.Address)
	}
	if show.Kind != "hd" || show.Index == nil || *show.Index != 3 {
		t.Errorf("show kind/index = %q/%v, want hd/3", show.Kind, show.Index)
	}

	// unalias by alias ref removes it; the index survives.
	un, err := svc.AccountUnalias(ctx, p, domain.AccountUnaliasRequest{Ref: "treasury/payroll"})
	if err != nil {
		t.Fatalf("unalias: %v", err)
	}
	if un.Index != 3 || un.RemovedAlias != "payroll" {
		t.Errorf("unalias = %+v, want index 3 removed payroll", un)
	}
	if _, err := svc.AccountShow(ctx, p, domain.AccountShowRequest{Ref: "treasury/3"}); err != nil {
		t.Errorf("index 3 should survive unalias: %v", err)
	}
}

func TestAccountAliasAfterTheFact(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()
	seedWallet(t, svc, "w")

	res, err := svc.AccountAlias(ctx, p, domain.AccountAliasRequest{Ref: "w/0", Alias: "main"})
	if err != nil {
		t.Fatalf("alias: %v", err)
	}
	if res.Alias != "main" || res.Ref != "w/main" {
		t.Errorf("alias result = %+v", res)
	}
}

func TestStandaloneImportExport(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()

	// A known secp256k1 private key and its address.
	const rawKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	kfile := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(kfile, []byte(rawKey+"\n"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	imp, err := svc.AccountImport(ctx, p, domain.AccountImportRequest{Name: "ops-key", Yes: true},
		AccountImportInput{KeyFile: kfile}, nil)
	if err != nil {
		t.Fatalf("import standalone: %v", err)
	}
	if imp.Name != "ops-key" || !strings.HasPrefix(imp.Address, "0x") {
		t.Errorf("import result = %+v", imp)
	}

	// export round-trips the same key.
	exp, err := svc.AccountExport(ctx, p, domain.AccountExportRequest{Ref: "ops-key", Yes: true},
		AccountExportInput{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !exp.Sensitive {
		t.Error("export must mark sensitive")
	}
	if !strings.EqualFold(strings.TrimPrefix(exp.PrivateKey, "0x"), rawKey) {
		t.Errorf("exported key %q != imported %q", exp.PrivateKey, rawKey)
	}
}

func TestAccountListWithDefault(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()
	seedWallet(t, svc, "a")
	seedWallet(t, svc, "b")

	if _, err := svc.AccountUse(ctx, p, domain.AccountUseRequest{Ref: "a/0"}); err != nil {
		t.Fatalf("use: %v", err)
	}

	list, err := svc.AccountList(ctx, p, domain.AccountListRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Accounts) < 2 {
		t.Fatalf("expected >= 2 accounts, got %d", len(list.Accounts))
	}
	// Stable sort: a/0 before b/0.
	if list.Accounts[0].Wallet != "a" {
		t.Errorf("accounts not sorted by wallet: first = %q", list.Accounts[0].Wallet)
	}
	if list.Default != "a/0" {
		t.Errorf("default = %q, want a/0", list.Default)
	}
	foundDefault := false
	for _, acc := range list.Accounts {
		if acc.Ref == "a/0" && acc.Default {
			foundDefault = true
		}
	}
	if !foundDefault {
		t.Error("a/0 should be marked Default in the list")
	}

	// filter to one wallet.
	filtered, err := svc.AccountList(ctx, p, domain.AccountListRequest{Wallet: "b"})
	if err != nil {
		t.Fatalf("list --wallet: %v", err)
	}
	for _, acc := range filtered.Accounts {
		if acc.Wallet != "b" {
			t.Errorf("filter leaked wallet %q", acc.Wallet)
		}
	}
}

func TestHDDeleteIsForgetAndNoIndexReuse(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()
	seedWallet(t, svc, "w")

	// derive 1 and 2 (0 is auto).
	if _, err := svc.AccountDerive(ctx, p, domain.AccountDeriveRequest{Wallet: "w", Yes: true}, AccountDeriveInput{}, nil); err != nil {
		t.Fatalf("derive 1: %v", err)
	}
	if _, err := svc.AccountDerive(ctx, p, domain.AccountDeriveRequest{Wallet: "w", Yes: true}, AccountDeriveInput{}, nil); err != nil {
		t.Fatalf("derive 2: %v", err)
	}

	// delete index 1 — HD delete is a forget.
	del, err := svc.AccountDelete(ctx, p, domain.AccountDeleteRequest{Ref: "w/1", Yes: true})
	if err != nil {
		t.Fatalf("delete w/1: %v", err)
	}
	if del.Mode != "forget" {
		t.Errorf("HD delete mode = %q, want forget", del.Mode)
	}

	// next derive must be 3 (never reuse 1, §3.3 monotonic allocator).
	next, err := svc.AccountDerive(ctx, p, domain.AccountDeriveRequest{Wallet: "w", Yes: true}, AccountDeriveInput{}, nil)
	if err != nil {
		t.Fatalf("derive after delete: %v", err)
	}
	if next.Index != 3 {
		t.Errorf("derive-next after deleting index 1 = %d, want 3 (no reuse)", next.Index)
	}
}
