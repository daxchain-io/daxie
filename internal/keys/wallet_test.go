package keys

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/secret"
)

func TestCreateWalletAutoDerivesIndex0(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "treasury", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer cr.Mnemonic.Zero()
	defer cr.BIP39Pass.Zero()

	if cr.WalletID == "" {
		t.Fatal("empty wallet id")
	}
	if cr.PathPrefix != defaultPathPrefix {
		t.Fatalf("path prefix = %q", cr.PathPrefix)
	}
	if cr.Index0Addr == [20]byte{} {
		t.Fatal("index 0 address not derived")
	}
	// 12 words, valid.
	if n := len(strings.Fields(string(cr.Mnemonic.Reveal()))); n != 12 {
		t.Fatalf("mnemonic has %d words", n)
	}

	// Wallet shows index 0 materialized, next_index 1.
	w, err := s.ShowWallet(context.Background(), "treasury")
	if err != nil {
		t.Fatal(err)
	}
	if w.NextIndex != 1 {
		t.Fatalf("next_index = %d, want 1", w.NextIndex)
	}
	if a, ok := w.Accounts[0]; !ok || a.Address != cr.Index0Addr {
		t.Fatal("index 0 not materialized to the create address")
	}

	// The blob file exists with 0600 perms.
	assertPerm(t, s.walletBlobPath(cr.WalletID), 0o600)
}

func TestImportWalletRoundTripsKnownAddress(t *testing.T) {
	s, pass := initStore(t)
	mn := secret.NewString(abandonMnemonic)
	defer mn.Zero()
	b39 := secret.NewString("")
	defer b39.Zero()

	_, addr0, err := s.ImportWallet(context.Background(), "imp", mn, b39, pass)
	if err != nil {
		t.Fatal(err)
	}
	// Known vector: abandon… index 0.
	want := "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
	if !strings.EqualFold(addr0.Hex(), want) {
		t.Fatalf("imported index0 = %s, want %s", addr0.Hex(), want)
	}

	// Export round-trips the exact mnemonic.
	mnOut, b39Out, eerr := s.ExportWallet(context.Background(), "imp", pass)
	if eerr != nil {
		t.Fatal(eerr)
	}
	defer mnOut.Zero()
	defer b39Out.Zero()
	if string(mnOut.Reveal()) != abandonMnemonic {
		t.Fatalf("exported mnemonic mismatch: %q", mnOut.Reveal())
	}
	if b39Out.Len() != 0 {
		t.Fatal("expected empty bip39 passphrase")
	}
}

func TestImportWalletWithBIP39Passphrase(t *testing.T) {
	s, pass := initStore(t)
	mn := secret.NewString(abandonMnemonic)
	defer mn.Zero()
	b39 := secret.NewString("TREZOR")
	defer b39.Zero()
	_, addr0, err := s.ImportWallet(context.Background(), "t25", mn, b39, pass)
	if err != nil {
		t.Fatal(err)
	}
	// The 25th word changes the derived address — must differ from the empty-pass
	// index 0.
	emptyPassAddr := "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
	if strings.EqualFold(addr0.Hex(), emptyPassAddr) {
		t.Fatal("bip39 passphrase did not change the derived address")
	}
	// Export returns the 25th word under its own label.
	_, b39Out, eerr := s.ExportWallet(context.Background(), "t25", pass)
	if eerr != nil {
		t.Fatal(eerr)
	}
	defer b39Out.Zero()
	if string(b39Out.Reveal()) != "TREZOR" {
		t.Fatalf("exported bip39 passphrase = %q", b39Out.Reveal())
	}
}

func TestImportWalletRejectsBadMnemonic(t *testing.T) {
	s, pass := initStore(t)
	bad := secret.NewString("abandon abandon abandon")
	defer bad.Zero()
	empty := secret.NewString("")
	defer empty.Zero()
	_, _, err := s.ImportWallet(context.Background(), "bad", bad, empty, pass)
	if !codeIs(err, CodeUsageBadMnemonic) {
		t.Fatalf("bad mnemonic: got %v, want %s", err, CodeUsageBadMnemonic)
	}
}

func TestRenameWallet(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "old", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()

	id, rerr := s.RenameWallet(context.Background(), "old", "new")
	if rerr != nil {
		t.Fatal(rerr)
	}
	if id != cr.WalletID {
		t.Fatal("rename changed the wallet UUID")
	}
	if _, e := s.ShowWallet(context.Background(), "new"); e != nil {
		t.Fatalf("renamed wallet not found: %v", e)
	}
	if _, e := s.ShowWallet(context.Background(), "old"); !codeIs(e, CodeRefNotFound) {
		t.Fatal("old name should be gone")
	}
	// The blob file is unchanged (same UUID stem).
	assertPerm(t, s.walletBlobPath(id), 0o600)
}

func TestDeleteWalletRemovesBlobAndMeta(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "gone", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()
	blob := s.walletBlobPath(cr.WalletID)

	id, derr := s.DeleteWallet(context.Background(), "gone")
	if derr != nil {
		t.Fatal(derr)
	}
	if id != cr.WalletID {
		t.Fatal("wrong id returned")
	}
	if _, e := os.Stat(blob); !os.IsNotExist(e) {
		t.Fatal("blob file not removed")
	}
	if _, e := s.ShowWallet(context.Background(), "gone"); !codeIs(e, CodeRefNotFound) {
		t.Fatal("meta entry not removed")
	}
}

func TestWalletExportFreshlyAuthed(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "w", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()
	// A wrong passphrase fails before any blob read.
	wrong := secret.NewString("nope")
	defer wrong.Zero()
	if _, _, e := s.ExportWallet(context.Background(), "w", wrong); !codeIs(e, CodeKeystoreBadPassphrase) {
		t.Fatalf("export wrong pass: got %v", e)
	}
}

func TestCreateMnemonicRedactsUntilReveal(t *testing.T) {
	// CreateResult.Mnemonic is a *secret.Bytes that redacts under %v / JSON.
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "r", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer cr.Mnemonic.Zero()
	defer cr.BIP39Pass.Zero()
	plain := string(cr.Mnemonic.Reveal())
	if s := cr.Mnemonic.String(); strings.Contains(s, plain) || !strings.Contains(s, "redacted") {
		t.Fatalf("mnemonic String() leaked: %q", s)
	}
	jb, _ := cr.Mnemonic.MarshalJSON()
	if strings.Contains(string(jb), plain) {
		t.Fatalf("mnemonic MarshalJSON leaked: %s", jb)
	}
}
