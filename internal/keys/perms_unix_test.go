//go:build !windows

package keys

import (
	"context"
	"os"
	"testing"

	"github.com/daxchain-io/daxie/internal/secret"
)

// assertPerm checks a file's POSIX mode is exactly want (owner-only). On Windows
// this is a no-op (the DACL test covers that case).
func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s mode = %o, want %o", path, got, want)
	}
}

func TestPOSIXKeystorePerms(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "treasury", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()
	key := secret.NewString("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer key.Zero()
	id, _, ierr := s.ImportStandalone(context.Background(), "ops", key, pass)
	if ierr != nil {
		t.Fatal(ierr)
	}
	_ = id

	// keystore.json / meta.json / wallet blob 0600; dir 0700.
	assertPerm(t, s.manifestPath(), 0o600)
	assertPerm(t, s.metaPath(), 0o600)
	assertPerm(t, s.walletBlobPath(cr.WalletID), 0o600)
	if fi, _ := os.Stat(s.dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("keystore dir mode = %o, want 0700", fi.Mode().Perm())
	}
	// Standalone file 0600.
	m, _ := s.loadMeta()
	for _, a := range m.Accounts {
		assertPerm(t, s.dir+"/"+a.File, 0o600)
	}
}

func TestPOSIXWorldReadableFails(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "w", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()
	// Tamper: make the manifest world-readable. A subsequent perm-checked read
	// (e.g. VerifyPassphrase) must surface keystore.perms_insecure (exit 12).
	if err := os.Chmod(s.manifestPath(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyPassphrase(context.Background(), pass); !codeIs(err, CodeKeystorePermsInsecure) {
		t.Fatalf("world-readable manifest: got %v, want %s", err, CodeKeystorePermsInsecure)
	}
}
