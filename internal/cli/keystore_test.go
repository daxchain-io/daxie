package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// keystore_test.go is the command-level coverage for `daxie keystore` info +
// change-passphrase.

func TestKeystoreInfoCLI(t *testing.T) {
	isolateKeystore(t)

	// Fresh keystore: initialized=false.
	out, _, code := execCLI(t, "keystore", "info", "--json")
	if code != 0 {
		t.Fatalf("info exit %d", code)
	}
	var info domain.KeystoreInfoResult
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("info json: %v (%q)", err, out)
	}
	if info.Initialized {
		t.Error("fresh keystore should be uninitialized")
	}

	mustCreateWallet(t, "w")
	out, _, code = execCLI(t, "keystore", "info", "--json")
	if code != 0 {
		t.Fatalf("info exit %d", code)
	}
	_ = json.Unmarshal([]byte(out), &info)
	if !info.Initialized || info.Wallets != 1 {
		t.Errorf("after create: %+v", info)
	}
}

func TestKeystoreChangePassphraseCLI(t *testing.T) {
	isolateKeystore(t)
	mustCreateWallet(t, "w")

	newF := filepath.Join(t.TempDir(), "newpass")
	if err := os.WriteFile(newF, []byte("rotated passphrase\n"), 0o600); err != nil {
		t.Fatalf("seed new: %v", err)
	}

	_, _, code := execCLI(t, "keystore", "change-passphrase",
		"--new-passphrase-file", newF, "--new-passphrase-confirm-file", newF, "--yes")
	if code != 0 {
		t.Fatalf("change-passphrase exit %d", code)
	}

	// After rotation, export under the new passphrase works.
	if _, _, code := execCLI(t, "wallet", "export", "w", "--passphrase-file", newF, "--yes"); code != 0 {
		t.Fatalf("export under new passphrase exit %d", code)
	}
}
