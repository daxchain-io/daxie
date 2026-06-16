package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
)

// wallet_test.go drives the M1 wallet use cases against a real (light-KDF) temp
// keystore — the §2.9 "keys" seam exercised through the service boundary. It uses
// the env-file secret channel (DAXIE_PASSPHRASE_FILE) so no TTY is needed, and a
// light-created keystore (DAXIE_KDF_LIGHT=1) so scrypt is fast.
//
// These tests are the service half of the use-case coverage; the cli half lives in
// internal/cli/*_test.go and the crypto vectors in internal/keys/*_test.go.

// openTestService builds an isolated service rooted at temp dirs, with a fixed
// clock and an injected secret environment, ready to exercise wallet/account use
// cases. passFile is a file holding the keystore passphrase; the returned service
// reads it via DAXIE_PASSPHRASE_FILE.
func openTestService(t *testing.T) *Service {
	t.Helper()
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("schema = 1\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	ksDir := t.TempDir()

	passFile := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(passFile, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatalf("seed passfile: %v", err)
	}

	env := map[string]string{
		"DAXIE_PASSPHRASE_FILE":         passFile,
		"DAXIE_PASSPHRASE_CONFIRM_FILE": passFile, // first-init confirm matches
		"DAXIE_KDF_LIGHT":               "1",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	fixed := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	svc, err := Open(context.Background(), Options{
		Config:   cfgDir,
		Keystore: ksDir,
		Clock:    func() time.Time { return fixed },
		Secret: SecretIO{
			LookupEnv: lookup,
			IsTTY:     func() bool { return false },
		},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// openTTYService builds a service whose keystore is UNINITIALIZED, with the
// keystore passphrase supplied via DAXIE_PASSPHRASE_FILE but NO confirm channel,
// IsTTY=true, and an injected prompt stub. This is the §3.3 interactive first-
// init double-entry shape: the confirm must come from a real second prompt, not
// from a non-interactive channel. promptReturn is what the injected prompt yields
// for every prompt (the second-entry confirmation). The returned passFile holds
// the keystore passphrase so the test can point the confirm at a match/mismatch.
func openTTYService(t *testing.T, passphrase string, prompt func(label string) ([]byte, error)) *Service {
	t.Helper()
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("schema = 1\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	ksDir := t.TempDir()

	passFile := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(passFile, []byte(passphrase+"\n"), 0o600); err != nil {
		t.Fatalf("seed passfile: %v", err)
	}

	// NOTE: deliberately NO DAXIE_PASSPHRASE_CONFIRM_FILE — the confirm must come
	// from the interactive prompt at the TTY (the bug this guards against returned
	// confirm_required here instead of prompting).
	env := map[string]string{
		"DAXIE_PASSPHRASE_FILE": passFile,
		"DAXIE_KDF_LIGHT":       "1",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	fixed := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	svc, err := Open(context.Background(), Options{
		Config:   cfgDir,
		Keystore: ksDir,
		Clock:    func() time.Time { return fixed },
		Secret: SecretIO{
			LookupEnv: lookup,
			IsTTY:     func() bool { return true },
			Prompt:    prompt,
		},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

// TestFirstInitInteractiveDoubleEntrySucceeds is the §3.3 regression guard: the
// very first `wallet create` on a fresh keystore at an interactive TTY, with NO
// non-interactive confirm channel, must issue a real second prompt and succeed
// when the re-entry matches — NOT fail keystore.confirm_required. The bug:
// ensureInitialized routed through acquireOptional, which returned an empty
// confirm without prompting for a bare TTY, so a human could never create a first
// wallet without setting the confirm env/flag.
func TestFirstInitInteractiveDoubleEntrySucceeds(t *testing.T) {
	const passphrase = "correct horse battery staple"
	promptCalls := 0
	// The prompt stub returns the MATCHING passphrase as the second entry.
	svc := openTTYService(t, passphrase, func(label string) ([]byte, error) {
		promptCalls++
		return []byte(passphrase), nil
	})

	ctx := context.Background()
	p := domain.LocalCLI()
	res, err := svc.WalletCreate(ctx, p,
		domain.WalletCreateRequest{Name: "first", Words: 12, Yes: true},
		WalletCreateInput{}, nil)
	if err != nil {
		t.Fatalf("first-init create at a TTY (matching double-entry) failed: %v", err)
	}
	if res.WalletID == "" || res.Mnemonic == "" {
		t.Fatalf("unexpected create result: %+v", res)
	}
	if promptCalls == 0 {
		t.Fatal("the interactive double-entry prompt was never invoked (the bug: short-circuited to confirm_required)")
	}
}

// TestFirstInitInteractiveDoubleEntryMismatchFails asserts the typo guard still
// holds interactively: when the re-entered confirmation does NOT match, first init
// fails keystore.confirm_required (exit 4) and writes nothing.
func TestFirstInitInteractiveDoubleEntryMismatchFails(t *testing.T) {
	svc := openTTYService(t, "the real passphrase", func(label string) ([]byte, error) {
		return []byte("a typo'd confirmation"), nil // mismatch
	})

	ctx := context.Background()
	p := domain.LocalCLI()
	_, err := svc.WalletCreate(ctx, p,
		domain.WalletCreateRequest{Name: "first", Words: 12, Yes: true},
		WalletCreateInput{}, nil)
	if err == nil {
		t.Fatal("a mismatched interactive confirmation must abort first init")
	}
	var de *domain.Error
	if !asErr(err, &de) || de.Code != "keystore.confirm_required" {
		t.Fatalf("error = %v, want keystore.confirm_required (exit 4)", err)
	}
}

// TestFirstInitNoTTYNoConfirmFailsClosed asserts the fail-closed contract: no TTY
// AND no explicit confirm channel → keystore.confirm_required, never a silent
// commit to the (unconfirmed) passphrase and never a prompt hang.
func TestFirstInitNoTTYNoConfirmFailsClosed(t *testing.T) {
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("schema = 1\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	passFile := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(passFile, []byte("pw\n"), 0o600); err != nil {
		t.Fatalf("seed pass: %v", err)
	}
	env := map[string]string{"DAXIE_PASSPHRASE_FILE": passFile, "DAXIE_KDF_LIGHT": "1"}
	fixed := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	svc, err := Open(context.Background(), Options{
		Config: cfgDir, Keystore: t.TempDir(),
		Clock: func() time.Time { return fixed },
		Secret: SecretIO{
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			IsTTY:     func() bool { return false }, // non-interactive
			Prompt:    func(string) ([]byte, error) { t.Fatal("prompt must NOT be called with no TTY"); return nil, nil },
		},
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })

	_, err = svc.WalletCreate(context.Background(), domain.LocalCLI(),
		domain.WalletCreateRequest{Name: "first", Words: 12, Yes: true},
		WalletCreateInput{}, nil)
	if err == nil {
		t.Fatal("first init with no TTY and no confirm channel must fail closed")
	}
	var de *domain.Error
	if !asErr(err, &de) || de.Code != "keystore.confirm_required" {
		t.Fatalf("error = %v, want keystore.confirm_required", err)
	}
}

func TestWalletCreateShowList(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()

	res, err := svc.WalletCreate(ctx, p, domain.WalletCreateRequest{Name: "treasury", Words: 12, Yes: true}, WalletCreateInput{}, nil)
	if err != nil {
		t.Fatalf("WalletCreate: %v", err)
	}
	if res.Name != "treasury" || res.WalletID == "" {
		t.Fatalf("unexpected create result: %+v", res)
	}
	if res.Account0 != "treasury/0" {
		t.Errorf("account0 = %q, want treasury/0", res.Account0)
	}
	if !res.Sensitive || res.Mnemonic == "" {
		t.Error("create must return the mnemonic once with sensitive=true")
	}
	words := strings.Fields(res.Mnemonic)
	if len(words) != 12 {
		t.Errorf("default mnemonic length = %d words, want 12", len(words))
	}
	if !strings.HasPrefix(res.Account0Address, "0x") {
		t.Errorf("account0 address %q not 0x-prefixed", res.Account0Address)
	}

	// show
	show, err := svc.WalletShow(ctx, p, domain.WalletShowRequest{Name: "treasury"})
	if err != nil {
		t.Fatalf("WalletShow: %v", err)
	}
	if show.WalletID != res.WalletID {
		t.Errorf("show wallet_id = %q, want %q", show.WalletID, res.WalletID)
	}
	if len(show.Accounts) < 1 {
		t.Error("a fresh wallet should have index 0 materialized")
	}

	// list
	list, err := svc.WalletList(ctx, p, domain.WalletListRequest{})
	if err != nil {
		t.Fatalf("WalletList: %v", err)
	}
	if len(list.Wallets) != 1 || list.Wallets[0].Name != "treasury" {
		t.Errorf("list = %+v, want one wallet 'treasury'", list.Wallets)
	}
	if list.Wallets[0].CreatedAt == "" {
		t.Error("created_at should be a non-empty RFC3339 string (no time.Time on the wire)")
	}
}

func TestWalletExportRoundTrip(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()

	created, err := svc.WalletCreate(ctx, p, domain.WalletCreateRequest{Name: "w", Words: 24, Yes: true}, WalletCreateInput{}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	exp, err := svc.WalletExport(ctx, p, domain.WalletExportRequest{Name: "w", Yes: true}, WalletExportInput{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !exp.Sensitive {
		t.Error("export must mark sensitive=true")
	}
	if exp.Mnemonic != created.Mnemonic {
		t.Error("exported mnemonic must equal the created one (the same secret of truth)")
	}
}

func TestWalletImportThenDerive(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()

	// The canonical Trezor all-zero-entropy 12-word mnemonic.
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	mfile := filepath.Join(t.TempDir(), "m")
	if err := os.WriteFile(mfile, []byte(mnemonic+"\n"), 0o600); err != nil {
		t.Fatalf("seed mnemonic file: %v", err)
	}

	res, err := svc.WalletImport(ctx, p, domain.WalletImportRequest{Name: "imp", Yes: true},
		WalletImportInput{MnemonicFile: mfile}, nil)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	// The well-known m/44'/60'/0'/0/0 address for this mnemonic.
	const wantAddr0 = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
	if !strings.EqualFold(res.Account0Address, wantAddr0) {
		t.Errorf("imported index-0 address = %q, want %q (BIP-44 vector)", res.Account0Address, wantAddr0)
	}
}

func TestWalletRenameDelete(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()

	if _, err := svc.WalletCreate(ctx, p, domain.WalletCreateRequest{Name: "old", Yes: true}, WalletCreateInput{}, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	rn, err := svc.WalletRename(ctx, p, domain.WalletRenameRequest{Old: "old", New: "new"})
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if rn.New != "new" {
		t.Errorf("rename new = %q", rn.New)
	}
	if _, err := svc.WalletShow(ctx, p, domain.WalletShowRequest{Name: "old"}); err == nil {
		t.Error("old name should no longer resolve after rename")
	}
	del, err := svc.WalletDelete(ctx, p, domain.WalletDeleteRequest{Name: "new", Yes: true})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !del.Deleted {
		t.Error("delete should report Deleted=true")
	}
}

// A second wallet under a WRONG passphrase must fail keystore.bad_passphrase
// (exit 4) and write nothing — the one-passphrase-per-keystore guard (§3.3).
func TestSecondWalletWrongPassphraseFailsAuth(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()

	if _, err := svc.WalletCreate(ctx, p, domain.WalletCreateRequest{Name: "first", Yes: true}, WalletCreateInput{}, nil); err != nil {
		t.Fatalf("first create: %v", err)
	}

	// Point the passphrase env at a DIFFERENT value via a file flag override.
	wrong := filepath.Join(t.TempDir(), "wrong")
	if err := os.WriteFile(wrong, []byte("not the passphrase\n"), 0o600); err != nil {
		t.Fatalf("seed wrong: %v", err)
	}
	_, err := svc.WalletCreate(ctx, p, domain.WalletCreateRequest{Name: "second", Yes: true},
		WalletCreateInput{PassphraseFile: wrong}, nil)
	if err == nil {
		t.Fatal("expected bad_passphrase on a forked passphrase")
	}
	var de *domain.Error
	if !asErr(err, &de) || de.Exit != domain.ExitAuth {
		t.Errorf("error = %v, want exit 4 (AUTH)", err)
	}
}

// asErr is a tiny errors.As wrapper local to the test (avoids importing errors in
// every test file).
func asErr(err error, target **domain.Error) bool {
	for err != nil {
		if e, ok := err.(*domain.Error); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
