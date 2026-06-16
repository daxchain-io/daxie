//go:build windows

package keys

import (
	"context"
	"os"
	"testing"
)

// assertPerm is a no-op on Windows (POSIX modes are not meaningful); the DACL is
// what matters, asserted via fsx.CheckPerms in TestWindowsKeystoreDACL.
func assertPerm(t *testing.T, path string, want os.FileMode) { t.Helper() }

// TestWindowsKeystoreDACL asserts the keystore files keys creates pass
// fsx.CheckPerms (owner-only DACL) on Windows — the §2.9 "Windows DACL" row.
func TestWindowsKeystoreDACL(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "treasury", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()

	// keystore.json / meta.json / wallet blob must each pass the DACL check that
	// keys runs on read (perm-checked load paths).
	for _, p := range []string{s.manifestPath(), s.metaPath(), s.walletBlobPath(cr.WalletID)} {
		if err := checkPerms(p); err != nil {
			t.Errorf("DACL check failed for %s: %v", p, err)
		}
	}
	// VerifyPassphrase exercises the manifest perm-check end to end.
	if err := s.VerifyPassphrase(context.Background(), pass); err != nil {
		t.Fatalf("VerifyPassphrase on a freshly-created Windows keystore: %v", err)
	}
}
