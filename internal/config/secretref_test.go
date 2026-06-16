package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

func TestResolveSecretRefsEnv(t *testing.T) {
	withEnv(t, map[string]string{"ALCHEMY_API_KEY": "abc123"})
	got, err := ResolveSecretRefs("https://x/v2/${env:ALCHEMY_API_KEY}")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://x/v2/abc123" {
		t.Errorf("got %q", got)
	}
}

func TestResolveSecretRefsEnvMissing(t *testing.T) {
	withEnv(t, map[string]string{})
	_, err := ResolveSecretRefs("${env:NOPE}")
	assertCode(t, err, domain.CodeSecretUnresolved)
}

func TestResolveSecretRefsFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "secret")
	if err := os.WriteFile(f, []byte("topsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{"DAXIE_SKIP_PERM_CHECK": "1"})
	got, err := ResolveSecretRefs("Bearer ${file:" + f + "}")
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one trailing newline stripped.
	if got != "Bearer topsecret" {
		t.Errorf("got %q, want \"Bearer topsecret\"", got)
	}
}

func TestResolveSecretRefsFileHome(t *testing.T) {
	home := t.TempDir()
	f := filepath.Join(home, "tok")
	if err := os.WriteFile(f, []byte("hometoken"), 0o600); err != nil {
		t.Fatal(err)
	}
	withEnv(t, map[string]string{"HOME": home, "DAXIE_SKIP_PERM_CHECK": "1"})
	got, err := ResolveSecretRefs("${file:~/tok}")
	if err != nil {
		t.Fatal(err)
	}
	if got != "hometoken" {
		t.Errorf("got %q, want hometoken", got)
	}
}

func TestResolveSecretRefsEscape(t *testing.T) {
	withEnv(t, map[string]string{})
	got, err := ResolveSecretRefs("price is $${not-a-ref}")
	if err != nil {
		t.Fatal(err)
	}
	if got != "price is ${not-a-ref}" {
		t.Errorf("escape failed: %q", got)
	}
}

func TestResolveSecretRefsUnknownScheme(t *testing.T) {
	withEnv(t, map[string]string{})
	_, err := ResolveSecretRefs("${vault:secret/path}")
	assertCode(t, err, domain.CodeSecretUnresolved)
}

func TestResolveSecretRefsNoScheme(t *testing.T) {
	withEnv(t, map[string]string{})
	_, err := ResolveSecretRefs("${justaname}")
	assertCode(t, err, domain.CodeSecretUnresolved)
}

func TestResolveSecretRefsUnterminated(t *testing.T) {
	withEnv(t, map[string]string{})
	_, err := ResolveSecretRefs("${env:FOO")
	assertCode(t, err, domain.CodeSecretUnresolved)
}

func TestResolveSecretRefsNoRefPassthrough(t *testing.T) {
	withEnv(t, map[string]string{})
	got, err := ResolveSecretRefs("https://plain.example/rpc")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://plain.example/rpc" {
		t.Errorf("plain string changed: %q", got)
	}
}

func TestStripOneTrailingNewline(t *testing.T) {
	cases := map[string]string{
		"a\n":   "a",
		"a\r\n": "a",
		"a\n\n": "a\n", // only ONE stripped
		"a":     "a",
		"a\nb":  "a\nb",
	}
	for in, want := range cases {
		if got := stripOneTrailingNewline(in); got != want {
			t.Errorf("stripOneTrailingNewline(%q) = %q, want %q", in, got, want)
		}
	}
}
