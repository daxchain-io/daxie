package keys

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
)

// errInjected is the simulated crash returned by a fault hook.
var errInjected = errors.New("injected fault")

// setupRotatable builds a keystore with 1 wallet + 2 standalone accounts so a
// rotation touches the verifier + a wallet blob + multiple key files (a real
// multi-file swap). Returns the store and the new passphrase buffer.
func setupRotatable(t *testing.T) (*Store, *secret.Bytes, *secret.Bytes) {
	t.Helper()
	s, oldPass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "tre", 12, oldPass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()
	for i, raw := range []string{
		"0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318",
		"0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		k := secret.NewString(raw)
		if _, _, e := s.ImportStandalone(context.Background(), "ops"+string(rune('a'+i)), k, oldPass); e != nil {
			t.Fatal(e)
		}
		k.Zero()
	}
	newPass := secret.NewString("the new passphrase value")
	t.Cleanup(func() { newPass.Zero() })
	return s, oldPass, newPass
}

// assertSinglePassphrase verifies EVERY secret file decrypts under exactly ONE
// passphrase (never a mix), by reopening the store and verifying + reading every
// object. wantPass is the passphrase that must work; otherPass must fail.
func assertSinglePassphrase(t *testing.T, dir string, wantPass, otherPass string) {
	t.Helper()
	s, err := Open(context.Background(), Options{Dir: dir, Clock: fixedClock(), Light: true})
	if err != nil {
		t.Fatalf("reopen after crash: %v", err)
	}
	defer func() { _ = s.Close() }()

	good := secret.NewString(wantPass)
	defer good.Zero()
	bad := secret.NewString(otherPass)
	defer bad.Zero()

	// Verifier accepts wantPass, rejects otherPass.
	if e := s.VerifyPassphrase(context.Background(), good); e != nil {
		t.Fatalf("verifier rejects the expected passphrase after recovery: %v", e)
	}
	if e := s.VerifyPassphrase(context.Background(), bad); !codeIs(e, CodeKeystoreBadPassphrase) {
		t.Fatalf("verifier accepts the wrong passphrase after recovery: %v", e)
	}

	// EVERY wallet blob + standalone file decrypts under wantPass.
	m, _ := s.loadMeta()
	for id := range m.Wallets {
		plain, e := s.readWalletPlaintext(id, good.Reveal())
		if e != nil {
			t.Fatalf("wallet %s does not decrypt under the expected passphrase: %v", id, e)
		}
		zeroBytes(plain)
		// And must NOT decrypt under the other passphrase (no mixed state).
		if _, e := s.readWalletPlaintext(id, bad.Reveal()); !codeIs(e, CodeKeystoreBadPassphrase) {
			t.Fatalf("MIXED STATE: wallet %s decrypts under the wrong passphrase", id)
		}
	}
	for _, a := range m.Accounts {
		priv, e := s.readStandaloneKey(a.File, good.Reveal())
		if e != nil {
			t.Fatalf("standalone %s does not decrypt under the expected passphrase: %v", a.Name, e)
		}
		zeroECDSA(priv)
	}

	// No rotation artifacts left behind.
	assertNoArtifacts(t, dir)
}

func assertNoArtifacts(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, rotateMarkerName)); !os.IsNotExist(err) {
		t.Error("ROTATE-COMMIT marker still present after recovery")
	}
	for _, sub := range []string{".", "wallets", "accounts"} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), stagedSuffix) {
				t.Errorf("staged artifact left behind: %s/%s", sub, e.Name())
			}
		}
	}
}

func TestChangePassphraseHappyPath(t *testing.T) {
	s, oldPass, newPass := setupRotatable(t)
	rotated, fp, err := s.ChangePassphrase(context.Background(), oldPass, newPass)
	if err != nil {
		t.Fatal(err)
	}
	if rotated < 4 { // verifier + 1 wallet + 2 standalone = 4
		t.Fatalf("rotated %d files, want >= 4", rotated)
	}
	if fp == "" {
		t.Fatal("empty fingerprint")
	}
	// New passphrase works for everything; old one no longer.
	assertSinglePassphrase(t, s.dir, "the new passphrase value", testPass)
}

func TestChangePassphraseWrongOld(t *testing.T) {
	s, _, newPass := setupRotatable(t)
	wrong := secret.NewString("not the old one")
	defer wrong.Zero()
	if _, _, e := s.ChangePassphrase(context.Background(), wrong, newPass); !codeIs(e, CodeKeystoreBadPassphrase) {
		t.Fatalf("wrong old pass: got %v", e)
	}
	// Nothing changed: old passphrase still works.
	assertSinglePassphrase(t, s.dir, testPass, "the new passphrase value")
}

// TestChangePassphraseCrashMatrix injects a fault at each phase and asserts Open
// recovers to a SINGLE-passphrase consistent state (never mixed), §3.8.
func TestChangePassphraseCrashMatrix(t *testing.T) {
	cases := []struct {
		point      string
		recoversTo string // which passphrase works after recovery
		otherFails string
	}{
		// Fault during STAGE (before commit): roll BACK; OLD pass works.
		{"after_stage_manifest", testPass, "the new passphrase value"},
		{"before_commit", testPass, "the new passphrase value"},
		// Fault right after COMMIT (marker written, no swaps yet): roll FORWARD; NEW works.
		{"after_commit", "the new passphrase value", testPass},
		// Fault after swaps, before marker delete: roll FORWARD (idempotent); NEW works.
		{"after_swap_before_marker_delete", "the new passphrase value", testPass},
	}
	for _, c := range cases {
		t.Run(c.point, func(t *testing.T) {
			s, oldPass, newPass := setupRotatable(t)
			dir := s.dir

			faultHook = func(point string) error {
				if point == c.point {
					return errInjected
				}
				return nil
			}

			_, _, err := s.ChangePassphrase(context.Background(), oldPass, newPass)
			// Clear the fault BEFORE any recovery/post-recovery rotation runs, so the
			// fault fires only for the simulated crash above.
			faultHook = nil
			if !errors.Is(err, errInjected) {
				t.Fatalf("expected the injected fault at %q, got %v", c.point, err)
			}

			// Open recovers; assert single-passphrase consistency.
			assertSinglePassphrase(t, dir, c.recoversTo, c.otherFails)

			// After recovery, a fresh rotation with the recovered passphrase succeeds
			// (the keystore is fully usable, not wedged).
			ns, oerr := Open(context.Background(), Options{Dir: dir, Clock: fixedClock(), Light: true})
			if oerr != nil {
				t.Fatal(oerr)
			}
			defer func() { _ = ns.Close() }()
			recovered := secret.NewString(c.recoversTo)
			defer recovered.Zero()
			again := secret.NewString("yet another passphrase")
			defer again.Zero()
			if _, _, e := ns.ChangePassphrase(context.Background(), recovered, again); e != nil {
				t.Fatalf("post-recovery rotation failed: %v", e)
			}
			assertSinglePassphrase(t, dir, "yet another passphrase", c.recoversTo)
		})
	}
}

// TestStagedRollbackOnDecryptFailure: if staging a file fails, the whole rotation
// aborts and Open rolls back; the old passphrase still works.
func TestRotationAbortLeavesNothing(t *testing.T) {
	s, oldPass, newPass := setupRotatable(t)
	dir := s.dir

	// Corrupt one wallet blob so its decrypt during staging fails.
	m, _ := s.loadMeta()
	var wid string
	for id := range m.Wallets {
		wid = id
	}
	// Truncate the blob (still valid JSON shape after we rewrite a broken crypto).
	if err := os.WriteFile(s.walletBlobPath(wid), []byte(`{"daxie_wallet":1,"type":"mnemonic","id":"`+wid+`","version":3,"crypto":{"cipher":"aes-128-ctr","ciphertext":"00","cipherparams":{"iv":"00000000000000000000000000000000"},"kdf":"scrypt","kdfparams":{"n":4096,"r":8,"p":1,"dklen":32,"salt":"00"},"mac":"00"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err := s.ChangePassphrase(context.Background(), oldPass, newPass)
	if err == nil {
		t.Fatal("expected the rotation to abort on a decrypt failure")
	}
	// No artifacts; the standalone files + verifier still use the OLD pass.
	assertNoArtifacts(t, dir)
	ns, _ := Open(context.Background(), Options{Dir: dir, Clock: fixedClock(), Light: true})
	defer func() { _ = ns.Close() }()
	good := secret.NewString(testPass)
	defer good.Zero()
	if e := ns.VerifyPassphrase(context.Background(), good); e != nil {
		t.Fatalf("verifier changed despite an aborted rotation: %v", e)
	}
	nm, _ := ns.loadMeta()
	for _, a := range nm.Accounts {
		priv, e := ns.readStandaloneKey(a.File, good.Reveal())
		if e != nil {
			t.Fatalf("standalone changed despite an aborted rotation: %v", e)
		}
		zeroECDSA(priv)
	}
}

// TestSignAfterRotation: a derived address still signs after a successful rotation
// (the mnemonic survived re-encryption byte-for-byte).
func TestSignAfterRotation(t *testing.T) {
	s, oldPass, newPass := setupRotatable(t)
	if _, _, err := s.ChangePassphrase(context.Background(), oldPass, newPass); err != nil {
		t.Fatal(err)
	}
	ns := reopen(t, s)
	ref, _ := domain.ParseAccountRef("tre/0")
	sg, err := ns.LookupSigning(ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, e := sg.SignHash(context.Background(), [32]byte{1, 2, 3}, testUnlocker{pass: "the new passphrase value"}); e != nil {
		t.Fatalf("sign after rotation: %v", e)
	}
}
