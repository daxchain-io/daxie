package keys

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
)

func TestOpenFreshIsUninitialized(t *testing.T) {
	s := newLightStore(t)
	if s.Initialized() {
		t.Fatal("a fresh store should be uninitialized")
	}
	// Lazy: nothing provisioned on disk yet.
	if _, err := os.Stat(s.manifestPath()); !os.IsNotExist(err) {
		t.Fatal("Open must not provision the manifest lazily")
	}
}

func TestEnsureInitializedFirstInitConfirm(t *testing.T) {
	s := newLightStore(t)
	pass := secret.NewString(testPass)
	defer pass.Zero()

	// Missing confirm on first init => confirm_required (exit 4), no verifier.
	if _, err := s.EnsureInitialized(context.Background(), pass, nil); !codeIs(err, CodeKeystoreConfirmRequired) {
		t.Fatalf("missing confirm: got %v, want %s", err, CodeKeystoreConfirmRequired)
	}
	if s.Initialized() {
		t.Fatal("verifier must not be written when confirmation is missing")
	}

	// Mismatched confirm => confirm_required.
	bad := secret.NewString("typo")
	defer bad.Zero()
	if _, err := s.EnsureInitialized(context.Background(), pass, bad); !codeIs(err, CodeKeystoreConfirmRequired) {
		t.Fatalf("mismatched confirm: got %v, want %s", err, CodeKeystoreConfirmRequired)
	}
	if s.Initialized() {
		t.Fatal("verifier must not be written on a confirm mismatch")
	}

	// Matching confirm => verifier written, stable fingerprint returned.
	confirm := secret.NewString(testPass)
	defer confirm.Zero()
	fp1, err := s.EnsureInitialized(context.Background(), pass, confirm)
	if err != nil {
		t.Fatalf("matching confirm: %v", err)
	}
	if !s.Initialized() {
		t.Fatal("verifier should be written after a matching confirm")
	}
	if fp1 == "" {
		t.Fatal("expected a non-empty fingerprint")
	}
	// Re-verify yields the SAME fingerprint (stable for orchestrator assertions).
	fp2, err := s.EnsureInitialized(context.Background(), pass, nil)
	if err != nil {
		t.Fatalf("re-verify: %v", err)
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprint not stable: %s vs %s", fp1, fp2)
	}
}

func TestVerifyWrongPassphrase(t *testing.T) {
	s, _ := initStore(t)
	wrong := secret.NewString("wrong passphrase")
	defer wrong.Zero()
	if err := s.VerifyPassphrase(context.Background(), wrong); !codeIs(err, CodeKeystoreBadPassphrase) {
		t.Fatalf("wrong passphrase: got %v, want %s", err, CodeKeystoreBadPassphrase)
	}
}

func TestSecondWalletWrongPassphraseWritesNothing(t *testing.T) {
	// One-passphrase-per-keystore: a SECOND create under a wrong passphrase fails
	// bad_passphrase and writes nothing (cannot fork the keystore, §3.3).
	s, pass := initStore(t)
	if _, err := s.CreateWallet(context.Background(), "treasury", 12, pass); err != nil {
		t.Fatalf("first create: %v", err)
	}
	wrong := secret.NewString("not the passphrase")
	defer wrong.Zero()
	_, err := s.CreateWallet(context.Background(), "second", 12, wrong)
	if !codeIs(err, CodeKeystoreBadPassphrase) {
		t.Fatalf("second create wrong pass: got %v, want %s", err, CodeKeystoreBadPassphrase)
	}
	// "second" must not exist.
	if _, err := s.ShowWallet(context.Background(), "second"); !codeIs(err, CodeRefNotFound) {
		t.Fatal("a wrong-passphrase create must write nothing")
	}
}

func TestDerivationWatermarkFailClosed(t *testing.T) {
	s, pass := initStore(t)
	cr, cerr := s.CreateWallet(context.Background(), "wm", 12, pass)
	if cerr != nil {
		t.Fatal(cerr)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()

	// Materialize index 1,2,3 then hand-corrupt next_index to 2 (below index 3).
	for i := 0; i < 3; i++ {
		if _, _, e := s.DeriveNext(context.Background(), "wm", pass); e != nil {
			t.Fatal(e)
		}
	}
	// Corrupt meta.json: set next_index below a materialized index.
	corruptNextIndex(t, s, "wm", 2)

	// Reopen must fail closed with derivation_watermark (exit 11).
	_, err := Open(context.Background(), Options{Dir: s.dir, Clock: fixedClock(), Light: true})
	if !codeIs(err, CodeKeystoreDerivationWatermark) {
		t.Fatalf("watermark: got %v, want %s", err, CodeKeystoreDerivationWatermark)
	}
}

func TestWatermarkConsistentOpensClean(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "ok", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()
	if _, _, e := s.DeriveNext(context.Background(), "ok", pass); e != nil {
		t.Fatal(e)
	}
	// A consistent watermark reopens clean.
	_ = reopen(t, s)
}

func TestNextIndexNeverReusedAfterForget(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "w", 12, pass) // index 0 auto
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()
	// Derive 1 and 2.
	i1, _, _ := s.DeriveNext(context.Background(), "w", pass)
	i2, _, _ := s.DeriveNext(context.Background(), "w", pass)
	if i1 != 1 || i2 != 2 {
		t.Fatalf("derive sequence = %d,%d want 1,2", i1, i2)
	}
	// Forget index 1.
	ref, _ := domain.ParseAccountRef("w/1")
	mode, derr := s.DeleteAccount(context.Background(), ref)
	if derr != nil || mode != "forget" {
		t.Fatalf("forget: mode=%s err=%v", mode, derr)
	}
	// Next derive is 3, NOT a reuse of 1.
	i3, _, _ := s.DeriveNext(context.Background(), "w", pass)
	if i3 != 3 {
		t.Fatalf("next index after forget = %d, want 3 (no reuse)", i3)
	}
}

// ── helpers ────────────────────────────────────────────────────────────────────

func codeIs(err error, code string) bool {
	if err == nil {
		return false
	}
	var de *domain.Error
	if errors.As(err, &de) {
		return de.Code == code
	}
	return false
}

func corruptNextIndex(t *testing.T, s *Store, walletName string, newNext uint32) {
	t.Helper()
	b, err := os.ReadFile(s.metaPath())
	if err != nil {
		t.Fatal(err)
	}
	var m metaFile
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	_, w := m.findWalletByName(walletName)
	if w == nil {
		t.Fatalf("wallet %q not found in meta", walletName)
	}
	w.NextIndex = newNext
	out, _ := json.MarshalIndent(&m, "", "  ")
	if err := os.WriteFile(s.metaPath(), out, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = filepath.Dir(s.metaPath())
}
