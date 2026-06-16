package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
)

// keystore_test.go drives KeystoreInfo and KeystoreChangePassphrase against a real
// light-KDF keystore. The crash matrix itself lives in internal/keys/passphrase_test.go
// (§2.9); here we prove the service orchestration (resolve old+new, rotate,
// re-verify) is wired correctly and that the new passphrase unlocks afterward.

// openTTYServiceInitialized builds an INITIALIZED keystore (one wallet) reachable
// via DAXIE_PASSPHRASE_FILE (the old passphrase) with IsTTY=true and an injected
// prompt for the rotation's new-passphrase confirm. First-init uses the
// DAXIE_PASSPHRASE_CONFIRM_FILE channel (no prompt needed); the rotation has NO
// DAXIE_NEW_PASSPHRASE_CONFIRM_FILE, so its confirm comes from the injected
// prompt — exercising the §3.8 interactive double-entry.
func openTTYServiceInitialized(t *testing.T, prompt func(label string) ([]byte, error)) *Service {
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
		"DAXIE_PASSPHRASE_CONFIRM_FILE": passFile, // first-init confirm (non-interactive)
		"DAXIE_KDF_LIGHT":               "1",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	fixed := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	mk := func() *Service {
		svc, err := Open(context.Background(), Options{
			Config: cfgDir, Keystore: ksDir,
			Clock: func() time.Time { return fixed },
			Secret: SecretIO{
				LookupEnv: lookup,
				IsTTY:     func() bool { return true },
				Prompt:    prompt,
			},
		})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		return svc
	}
	// First service: initialize the keystore (first-init uses the confirm file).
	init := mk()
	if _, err := init.WalletCreate(context.Background(), domain.LocalCLI(),
		domain.WalletCreateRequest{Name: "w", Words: 12, Yes: true}, WalletCreateInput{}, nil); err != nil {
		t.Fatalf("seed wallet: %v", err)
	}
	_ = init.Close()

	// Second service over the SAME keystore, for the rotation under test.
	svc := mk()
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func TestKeystoreInfo(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()

	// Fresh keystore: not initialized, zero counts.
	info, err := svc.KeystoreInfo(ctx, p)
	if err != nil {
		t.Fatalf("info (fresh): %v", err)
	}
	if info.Initialized {
		t.Error("fresh keystore should report initialized=false")
	}
	if info.Path == "" {
		t.Error("info.Path empty")
	}

	seedWallet(t, svc, "w")
	info2, err := svc.KeystoreInfo(ctx, p)
	if err != nil {
		t.Fatalf("info (after create): %v", err)
	}
	if !info2.Initialized {
		t.Error("after create, initialized should be true")
	}
	if info2.Wallets != 1 {
		t.Errorf("wallets = %d, want 1", info2.Wallets)
	}
	if info2.ScryptN == 0 || info2.KDF == "" {
		t.Errorf("kdf template missing: %+v", info2)
	}
}

func TestKeystoreChangePassphrase(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()
	seedWallet(t, svc, "w")

	newFile := filepath.Join(t.TempDir(), "newpass")
	if err := os.WriteFile(newFile, []byte("a brand new passphrase\n"), 0o600); err != nil {
		t.Fatalf("seed new pass: %v", err)
	}

	res, err := svc.KeystoreChangePassphrase(ctx, p,
		domain.KeystoreChangePassphraseRequest{Yes: true},
		KeystoreChangePassphraseInput{
			NewFile:        newFile,
			NewConfirmFile: newFile, // double-entry matches
		}, nil)
	if err != nil {
		t.Fatalf("change-passphrase: %v", err)
	}
	if res.RotatedFiles < 1 {
		t.Errorf("rotated files = %d, want >= 1 (verifier + wallet blob)", res.RotatedFiles)
	}

	// The OLD passphrase must now FAIL; the NEW one must work. Re-open the store
	// pointing the keystore passphrase at the new file and export the wallet.
	exp, err := svc.WalletExport(ctx, p, domain.WalletExportRequest{Name: "w", Yes: true},
		WalletExportInput{PassphraseFile: newFile})
	if err != nil {
		t.Fatalf("export under new passphrase: %v", err)
	}
	if exp.Mnemonic == "" {
		t.Error("export under new passphrase returned empty mnemonic")
	}

	// The old passphrase (the env DAXIE_PASSPHRASE_FILE) must now be rejected.
	_, err = svc.WalletExport(ctx, p, domain.WalletExportRequest{Name: "w", Yes: true},
		WalletExportInput{}) // falls back to the OLD env passphrase
	if err == nil {
		t.Fatal("old passphrase should be rejected after rotation")
	}
	var de *domain.Error
	if !asErr(err, &de) || de.Exit != domain.ExitAuth {
		t.Errorf("old-passphrase error = %v, want exit 4 (AUTH)", err)
	}
}

// TestChangePassphraseNoConfirmNoTTYFailsClosed is the §3.8 fail-closed guard: a
// rotation with a new-passphrase SOURCE but NO confirm channel and NO TTY must
// error (keystore.confirm_required, exit 4) rather than silently re-encrypting the
// entire keystore onto an unconfirmed (possibly typo'd) passphrase. The old
// passphrase must still work afterward (nothing rotated).
func TestChangePassphraseNoConfirmNoTTYFailsClosed(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()
	seedWallet(t, svc, "w")

	newFile := filepath.Join(t.TempDir(), "newpass")
	if err := os.WriteFile(newFile, []byte("a brand new passphrase\n"), 0o600); err != nil {
		t.Fatalf("seed new pass: %v", err)
	}

	// NewFile set, but NO NewConfirm* and the test service is IsTTY=false.
	_, err := svc.KeystoreChangePassphrase(ctx, p,
		domain.KeystoreChangePassphraseRequest{Yes: true},
		KeystoreChangePassphraseInput{NewFile: newFile}, nil)
	if err == nil {
		t.Fatal("rotation with no confirm channel and no TTY must fail closed, not rotate")
	}
	var de *domain.Error
	if !asErr(err, &de) || de.Code != "keystore.confirm_required" || de.Exit != domain.ExitAuth {
		t.Fatalf("error = %v, want keystore.confirm_required (exit 4)", err)
	}

	// Nothing was rotated: the ORIGINAL passphrase (the env DAXIE_PASSPHRASE_FILE)
	// must still export the wallet.
	if _, eerr := svc.WalletExport(ctx, p, domain.WalletExportRequest{Name: "w", Yes: true},
		WalletExportInput{}); eerr != nil {
		t.Fatalf("original passphrase should still work (nothing rotated): %v", eerr)
	}
}

// TestChangePassphraseInteractiveDoubleEntry drives the rotation interactively: at
// a TTY with no confirm channel, the new passphrase is confirmed by a real second
// prompt. A matching re-entry rotates; a mismatched re-entry fails closed.
func TestChangePassphraseInteractiveDoubleEntry(t *testing.T) {
	const newPassphrase = "the rotated passphrase"

	t.Run("matching re-entry rotates", func(t *testing.T) {
		// The new passphrase comes from a file; the confirm comes from the prompt.
		newFile, prompted := t.TempDir(), 0
		nf := filepath.Join(newFile, "n")
		if err := os.WriteFile(nf, []byte(newPassphrase+"\n"), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		svc := openTTYServiceInitialized(t, func(label string) ([]byte, error) {
			prompted++
			return []byte(newPassphrase), nil // matching second entry
		})
		ctx := context.Background()
		p := domain.LocalCLI()

		res, err := svc.KeystoreChangePassphrase(ctx, p,
			domain.KeystoreChangePassphraseRequest{Yes: true},
			KeystoreChangePassphraseInput{NewFile: nf}, nil)
		if err != nil {
			t.Fatalf("interactive matching rotation: %v", err)
		}
		if res.RotatedFiles < 1 {
			t.Errorf("rotated = %d, want >= 1", res.RotatedFiles)
		}
		if prompted == 0 {
			t.Error("the interactive confirm prompt was never invoked")
		}
	})

	t.Run("mismatched re-entry fails closed", func(t *testing.T) {
		nf := filepath.Join(t.TempDir(), "n")
		if err := os.WriteFile(nf, []byte(newPassphrase+"\n"), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
		svc := openTTYServiceInitialized(t, func(label string) ([]byte, error) {
			return []byte("a typo'd confirmation"), nil // mismatch
		})
		ctx := context.Background()
		p := domain.LocalCLI()

		_, err := svc.KeystoreChangePassphrase(ctx, p,
			domain.KeystoreChangePassphraseRequest{Yes: true},
			KeystoreChangePassphraseInput{NewFile: nf}, nil)
		if err == nil {
			t.Fatal("a mismatched interactive confirm must abort the rotation")
		}
		var de *domain.Error
		if !asErr(err, &de) || de.Code != "keystore.confirm_required" {
			t.Fatalf("error = %v, want keystore.confirm_required", err)
		}
	})
}

// A mismatched new-passphrase confirmation fails keystore.confirm_required (exit 4)
// and rotates nothing.
func TestChangePassphraseConfirmMismatch(t *testing.T) {
	svc := openTestService(t)
	ctx := context.Background()
	p := domain.LocalCLI()
	seedWallet(t, svc, "w")

	newF := filepath.Join(t.TempDir(), "n1")
	mismatchF := filepath.Join(t.TempDir(), "n2")
	_ = os.WriteFile(newF, []byte("new one\n"), 0o600)
	_ = os.WriteFile(mismatchF, []byte("different\n"), 0o600)

	_, err := svc.KeystoreChangePassphrase(ctx, p,
		domain.KeystoreChangePassphraseRequest{Yes: true},
		KeystoreChangePassphraseInput{NewFile: newF, NewConfirmFile: mismatchF}, nil)
	if err == nil {
		t.Fatal("expected confirm mismatch error")
	}
	var de *domain.Error
	if !asErr(err, &de) || de.Code != "keystore.confirm_required" {
		t.Errorf("error = %v, want keystore.confirm_required", err)
	}
}
