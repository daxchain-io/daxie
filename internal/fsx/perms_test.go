package fsx

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// writeFileMode writes a file at an exact mode (chmod after create to defeat
// umask), returning its path.
func writeFileMode(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckPerms0600OK(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode semantics; Windows uses DACL inspection")
	}
	dir := t.TempDir()
	p := writeFileMode(t, dir, "k.json", 0o600)
	if err := CheckPerms(p); err != nil {
		t.Errorf("CheckPerms(0600) = %v, want nil", err)
	}
}

func TestCheckPermsWorldOrGroupWriteFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode semantics")
	}
	dir := t.TempDir()
	cases := []struct {
		name string
		mode os.FileMode
	}{
		{"world-read", 0o604},
		{"world-write", 0o602},
		{"world-rwx", 0o607},
		{"group-write", 0o620},
		{"group-exec", 0o610},
		{"world-and-group", 0o666},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFileMode(t, dir, tc.name, tc.mode)
			err := CheckPerms(p)
			if err == nil {
				t.Fatalf("CheckPerms(%#o) = nil, want a hard error", tc.mode)
			}
			var de *domain.Error
			if !errors.As(err, &de) {
				t.Fatalf("error is not *domain.Error: %T", err)
			}
			if de.Code != "keystore.perms_insecure" {
				t.Errorf("code = %q, want keystore.perms_insecure", de.Code)
			}
		})
	}
}

func TestCheckPermsGroupReadCarveOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode semantics")
	}
	dir := t.TempDir()
	p := writeFileMode(t, dir, "fsgroup.json", 0o640)

	// Capture the warning sink so a "foreign group" warning does not pollute test
	// output, and so we can assert silence when the group is ours.
	var warn bytes.Buffer
	orig := permWarnSink
	permWarnSink = &warn
	t.Cleanup(func() { permWarnSink = orig })

	// 0640: group-read set, the file's group is (in a TempDir) the process's
	// primary group, so it must pass — and pass SILENTLY (the fsGroup shape).
	if err := CheckPerms(p); err != nil {
		t.Fatalf("CheckPerms(0640, own group) = %v, want nil", err)
	}
	if warn.Len() != 0 {
		t.Errorf("expected silent acceptance for own-group read, got warning: %q", warn.String())
	}
}

func TestCheckPermsSkipEnv(t *testing.T) {
	dir := t.TempDir()
	// A wide-open file would normally fail; with the skip env it passes on all
	// platforms (the env check is platform-independent in perms.go).
	p := filepath.Join(dir, "wide.json")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, 0o666); err != nil {
			t.Fatal(err)
		}
	}

	orig := lookupEnvFn
	lookupEnvFn = func(k string) (string, bool) {
		if k == skipPermCheckEnv {
			return "1", true
		}
		return "", false
	}
	t.Cleanup(func() { lookupEnvFn = orig })

	if err := CheckPerms(p); err != nil {
		t.Errorf("CheckPerms with DAXIE_SKIP_PERM_CHECK=1 = %v, want nil", err)
	}
}

func TestCheckPermsMissingFile(t *testing.T) {
	err := CheckPerms(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("CheckPerms on a missing file should error")
	}
}
