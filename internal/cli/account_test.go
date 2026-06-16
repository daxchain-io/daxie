package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// account_test.go is the command-level coverage for `daxie account`: derive,
// alias/unalias, import/export, use/list/show (incl. --qr), delete — human +
// --json + exit codes.

func mustCreateWallet(t *testing.T, name string) {
	t.Helper()
	if _, _, code := execCLI(t, "wallet", "create", name, "--yes"); code != 0 {
		t.Fatalf("create wallet %q exit %d", name, code)
	}
}

func TestAccountDeriveAliasCLI(t *testing.T) {
	isolateKeystore(t)
	mustCreateWallet(t, "treasury")

	// derive next (0 auto → next is 1).
	out, _, code := execCLI(t, "account", "derive", "treasury", "--json")
	if code != 0 {
		t.Fatalf("derive exit %d:\n%s", code, out)
	}
	var d domain.AccountDeriveResult
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("derive json: %v", err)
	}
	if d.Index != 1 {
		t.Errorf("derive index = %d, want 1", d.Index)
	}

	// derive + alias in one step.
	out, _, code = execCLI(t, "account", "derive", "treasury", "--index", "3", "--name", "payroll", "--json")
	if code != 0 {
		t.Fatalf("derive index exit %d", code)
	}
	_ = json.Unmarshal([]byte(out), &d)
	if d.Alias != "payroll" {
		t.Errorf("alias = %q, want payroll", d.Alias)
	}

	// alias after the fact.
	if _, _, code := execCLI(t, "account", "alias", "treasury/1", "hot"); code != 0 {
		t.Fatalf("alias exit %d", code)
	}
	// unalias.
	if _, _, code := execCLI(t, "account", "unalias", "treasury/hot"); code != 0 {
		t.Fatalf("unalias exit %d", code)
	}
}

func TestAccountImportExportCLI(t *testing.T) {
	isolateKeystore(t)
	const rawKey = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	kfile := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(kfile, []byte(rawKey+"\n"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	out, _, code := execCLI(t, "account", "import", "ops-key", "--key-file", kfile, "--json", "--yes")
	if code != 0 {
		t.Fatalf("import exit %d:\n%s", code, out)
	}
	var imp domain.AccountImportResult
	_ = json.Unmarshal([]byte(out), &imp)
	if imp.Name != "ops-key" {
		t.Errorf("import name = %q", imp.Name)
	}

	// export without --yes → confirmation_required (exit 2).
	if _, _, code := execCLI(t, "account", "export", "ops-key"); code != int(domain.ExitUsage) {
		t.Fatalf("export without --yes exit = %d, want 2", code)
	}

	// export --yes → prints the key.
	out, _, code = execCLI(t, "account", "export", "ops-key", "--yes", "--json")
	if code != 0 {
		t.Fatalf("export exit %d", code)
	}
	var exp domain.AccountExportResult
	_ = json.Unmarshal([]byte(out), &exp)
	if !strings.EqualFold(strings.TrimPrefix(exp.PrivateKey, "0x"), rawKey) {
		t.Errorf("exported key mismatch: %q", exp.PrivateKey)
	}
}

func TestAccountUseListCLI(t *testing.T) {
	isolateKeystore(t)
	mustCreateWallet(t, "a")

	if _, _, code := execCLI(t, "account", "use", "a/0"); code != 0 {
		t.Fatalf("use exit %d", code)
	}
	out, _, code := execCLI(t, "account", "list", "--json")
	if code != 0 {
		t.Fatalf("list exit %d", code)
	}
	var lr domain.AccountListResult
	if err := json.Unmarshal([]byte(out), &lr); err != nil {
		t.Fatalf("list json: %v", err)
	}
	if lr.Default != "a/0" {
		t.Errorf("default = %q, want a/0", lr.Default)
	}
}

func TestAccountShowQRCLI(t *testing.T) {
	isolateKeystore(t)
	mustCreateWallet(t, "w")

	// human + --qr: the address line is present and the QR block has block glyphs.
	out, _, code := execCLI(t, "account", "show", "w/0", "--qr")
	if code != 0 {
		t.Fatalf("show --qr exit %d", code)
	}
	if !strings.Contains(out, "0x") {
		t.Errorf("show output missing address:\n%s", out)
	}
	if !strings.ContainsAny(out, "█▀▄") {
		t.Errorf("show --qr produced no QR block:\n%s", out)
	}

	// --quiet --qr: the address still prints, the QR is suppressed.
	out, _, code = execCLI(t, "account", "show", "w/0", "--qr", "--quiet")
	if code != 0 {
		t.Fatalf("show --qr --quiet exit %d", code)
	}
	if !strings.Contains(out, "0x") {
		t.Error("address must print even under --quiet (essential output)")
	}
	if strings.ContainsAny(out, "█▀▄") {
		t.Error("--quiet must suppress the QR block")
	}

	// --json: structured, no QR in the payload.
	out, _, code = execCLI(t, "account", "show", "w/0", "--qr", "--json")
	if code != 0 {
		t.Fatalf("show --json exit %d", code)
	}
	var sr domain.AccountShowResult
	if err := json.Unmarshal([]byte(out), &sr); err != nil {
		t.Fatalf("show json invalid (QR must not pollute JSON): %v (%q)", err, out)
	}
	if sr.Kind != "hd" {
		t.Errorf("kind = %q, want hd", sr.Kind)
	}
}

func TestAccountDeleteForgetCLI(t *testing.T) {
	isolateKeystore(t)
	mustCreateWallet(t, "w")
	// derive index 1 then delete it (HD forget), with --yes.
	if _, _, code := execCLI(t, "account", "derive", "w", "--yes"); code != 0 {
		t.Fatalf("derive exit %d", code)
	}
	out, _, code := execCLI(t, "account", "delete", "w/1", "--yes", "--json")
	if code != 0 {
		t.Fatalf("delete exit %d", code)
	}
	var del domain.AccountDeleteResult
	_ = json.Unmarshal([]byte(out), &del)
	if del.Mode != "forget" {
		t.Errorf("delete mode = %q, want forget", del.Mode)
	}
}
