package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// wallet_test.go is the §2.9 command-level table coverage for `daxie wallet`:
// human + --json, the non-interactive secret path (DAXIE_PASSPHRASE_FILE +
// confirm), and the documented exit codes. It uses the same execCLI funnel as the
// M0 tests (it exercises the real error→exit mapping).

// isolateKeystore points every state class at temp dirs AND wires a non-
// interactive keystore passphrase (file channel) + its first-init confirm, plus
// the light KDF so scrypt is fast. It returns the keystore dir.
func isolateKeystore(t *testing.T) string {
	t.Helper()
	cfgDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("schema = 1\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	ks := t.TempDir()
	passFile := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(passFile, []byte("unit test passphrase\n"), 0o600); err != nil {
		t.Fatalf("seed pass: %v", err)
	}
	t.Setenv("DAXIE_CONFIG", cfgDir)
	t.Setenv("DAXIE_KEYSTORE", ks)
	t.Setenv("DAXIE_STATE_DIR", t.TempDir())
	t.Setenv("DAXIE_CACHE_DIR", t.TempDir())
	t.Setenv("DAXIE_PASSPHRASE_FILE", passFile)
	t.Setenv("DAXIE_PASSPHRASE_CONFIRM_FILE", passFile)
	t.Setenv("DAXIE_KDF_LIGHT", "1")
	return ks
}

func TestWalletCreateCLI(t *testing.T) {
	isolateKeystore(t)

	t.Run("human shows mnemonic once", func(t *testing.T) {
		out, _, code := execCLI(t, "wallet", "create", "treasury", "--yes")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if !strings.Contains(out, "RECORD THIS MNEMONIC") {
			t.Errorf("create output missing the record-it notice:\n%s", out)
		}
		// The mnemonic words must be present (12 by default).
		if len(strings.Fields(lastMnemonicLine(out))) < 12 {
			t.Errorf("create output does not contain a 12-word mnemonic:\n%s", out)
		}
	})

	t.Run("json carries sensitive mnemonic", func(t *testing.T) {
		out, _, code := execCLI(t, "wallet", "create", "ops", "--json", "--yes")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		var res domain.WalletCreateResult
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("create --json invalid: %v (%q)", err, out)
		}
		if !res.Sensitive || res.Mnemonic == "" {
			t.Errorf("json create must carry sensitive mnemonic: %+v", res)
		}
		if res.Account0 != "ops/0" {
			t.Errorf("account0 = %q, want ops/0", res.Account0)
		}
	})

	t.Run("no --yes and no TTY refuses (confirmation_required, exit 2)", func(t *testing.T) {
		// §3.5: a fresh mnemonic must not be dumped to a non-interactive stream
		// without --yes (and there is no TTY to run the recorded-it proof on). The
		// test process stdin is not a terminal, so this is the no-TTY/no-yes branch.
		_, _, code := execCLI(t, "wallet", "create", "noyes")
		if code != int(domain.ExitUsage) {
			t.Fatalf("create without --yes/TTY exit = %d, want 2 (USAGE confirmation_required)", code)
		}
	})

	t.Run("24 words", func(t *testing.T) {
		out, _, code := execCLI(t, "wallet", "create", "big", "--words", "24", "--json", "--yes")
		if code != 0 {
			t.Fatalf("exit = %d", code)
		}
		var res domain.WalletCreateResult
		_ = json.Unmarshal([]byte(out), &res)
		if n := len(strings.Fields(res.Mnemonic)); n != 24 {
			t.Errorf("mnemonic length = %d, want 24", n)
		}
	})
}

func TestWalletListShowCLI(t *testing.T) {
	isolateKeystore(t)
	if _, _, code := execCLI(t, "wallet", "create", "treasury", "--yes"); code != 0 {
		t.Fatalf("create exit %d", code)
	}

	out, _, code := execCLI(t, "wallet", "list", "--json")
	if code != 0 {
		t.Fatalf("list exit %d", code)
	}
	var lr domain.WalletListResult
	if err := json.Unmarshal([]byte(out), &lr); err != nil {
		t.Fatalf("list json: %v (%q)", err, out)
	}
	if len(lr.Wallets) != 1 || lr.Wallets[0].Name != "treasury" {
		t.Errorf("list = %+v", lr.Wallets)
	}

	out, _, code = execCLI(t, "wallet", "show", "treasury", "--json")
	if code != 0 {
		t.Fatalf("show exit %d", code)
	}
	var sr domain.WalletShowResult
	if err := json.Unmarshal([]byte(out), &sr); err != nil {
		t.Fatalf("show json: %v", err)
	}
	if sr.PathPrefix != "m/44'/60'/0'/0" {
		t.Errorf("path prefix = %q", sr.PathPrefix)
	}
}

func TestWalletImportCLI(t *testing.T) {
	isolateKeystore(t)
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	mfile := filepath.Join(t.TempDir(), "m")
	if err := os.WriteFile(mfile, []byte(mnemonic+"\n"), 0o600); err != nil {
		t.Fatalf("seed mnemonic: %v", err)
	}

	out, _, code := execCLI(t, "wallet", "import", "imp", "--mnemonic-file", mfile, "--json", "--yes")
	if code != 0 {
		t.Fatalf("import exit = %d:\n%s", code, out)
	}
	var res domain.WalletImportResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("import json: %v (%q)", err, out)
	}
	const wantAddr = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
	if !strings.EqualFold(res.Account0Address, wantAddr) {
		t.Errorf("imported index-0 = %q, want %q", res.Account0Address, wantAddr)
	}
}

func TestWalletExportConfirmGate(t *testing.T) {
	isolateKeystore(t)
	if _, _, code := execCLI(t, "wallet", "create", "w", "--yes"); code != 0 {
		t.Fatalf("create exit %d", code)
	}

	// Without --yes and with no TTY, export must fail confirmation_required (exit 2).
	_, _, code := execCLI(t, "wallet", "export", "w")
	if code != int(domain.ExitUsage) {
		t.Fatalf("export without --yes/TTY exit = %d, want 2 (USAGE)", code)
	}

	// With --yes it succeeds and prints the mnemonic.
	out, _, code := execCLI(t, "wallet", "export", "w", "--yes")
	if code != 0 {
		t.Fatalf("export --yes exit = %d", code)
	}
	if len(strings.Fields(out)) < 12 {
		t.Errorf("export did not print a mnemonic:\n%s", out)
	}
}

func TestWalletShowUnknownExit10(t *testing.T) {
	isolateKeystore(t)
	if _, _, code := execCLI(t, "wallet", "create", "w", "--yes"); code != 0 {
		t.Fatalf("create exit %d", code)
	}
	_, _, code := execCLI(t, "wallet", "show", "nope")
	if code != int(domain.ExitNotFound) {
		t.Fatalf("show unknown exit = %d, want 10 (NOT_FOUND)", code)
	}
}

// lastMnemonicLine returns the longest whitespace-rich line of create output (the
// mnemonic line), used to count words without depending on exact formatting.
func lastMnemonicLine(out string) string {
	best := ""
	for _, ln := range strings.Split(out, "\n") {
		if len(strings.Fields(ln)) > len(strings.Fields(best)) {
			best = ln
		}
	}
	return best
}
