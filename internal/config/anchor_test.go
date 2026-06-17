package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// anchor_test.go covers the §4.6 config-class anchor I/O: a round-trip, the
// missing-anchor (opt-in) signal, the read-only-mount mapping, and the Viper
// carve-out regression (no flag / DAXIE_* env can reach the anchor).

func TestAnchorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, _ := ResolvePaths(FlagValues{Config: dir})

	// No anchor yet ⇒ (nil, false, nil), never an error (the opt-in case).
	raw, found, err := p.ReadAnchor()
	if err != nil {
		t.Fatalf("ReadAnchor before write: %v", err)
	}
	if found || raw != nil {
		t.Fatalf("ReadAnchor before write: found=%v raw=%q, want not-found/nil", found, raw)
	}

	want := []byte(`{"verify_key":"ed25519:AAAA","salt":"BBBB","scrypt":{"n":131072,"r":8,"p":1},"nonce_watermark":0}`)
	if err := p.WriteAnchor(want); err != nil {
		t.Fatalf("WriteAnchor: %v", err)
	}

	got, found, err := p.ReadAnchor()
	if err != nil {
		t.Fatalf("ReadAnchor after write: %v", err)
	}
	if !found {
		t.Fatal("ReadAnchor after write: found=false, want true")
	}
	if string(got) != string(want) {
		t.Errorf("anchor round-trip mismatch:\n got %q\nwant %q", got, want)
	}

	// It must live at <ConfigDir>/policy-anchor.json, NOT in config.toml.
	if p.AnchorPath() != filepath.Join(dir, "policy-anchor.json") {
		t.Errorf("AnchorPath = %q, want <dir>/policy-anchor.json", p.AnchorPath())
	}
	if _, err := os.Stat(filepath.Join(dir, "policy-anchor.json")); err != nil {
		t.Errorf("anchor file not at the config-class path: %v", err)
	}
}

// TestAnchorReadOnlyMount: a write against a read-only config dir maps to
// config.read_only (exit 10), so the caller can fall back to emitting the anchor
// JSON to stdout / --anchor-out (the K8s ConfigMap path).
func TestAnchorReadOnlyMount(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX read-only-dir perms (chmod 0o500) do not block writes on Windows; the config.read_only mapping is exercised on POSIX")
	}
	if os.Getuid() == 0 {
		t.Skip("read-only mount check is meaningless as root")
	}
	dir := t.TempDir()
	withEnv(t, map[string]string{"HOME": t.TempDir(), "DAXIE_CONFIG": dir})
	p, _ := ResolvePaths(FlagValues{Config: dir})

	// Make the config dir read-only so the atomic temp+rename fails EACCES/EROFS.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := p.WriteAnchor([]byte(`{"verify_key":"ed25519:x"}`))
	if err == nil {
		t.Fatal("WriteAnchor on a read-only dir: want error, got nil")
	}
	assertCode(t, err, domain.CodeConfigReadOnly)
	if !AnchorIsReadOnly(err) {
		t.Errorf("AnchorIsReadOnly(%v) = false, want true", err)
	}
}

// TestAnchorCarveOut is the regression that pins the §4.6 Viper carve-out: NO
// flag and NO DAXIE_* env var can change which file the anchor is read from or
// inject anchor contents. The anchor path is derived ONLY from the resolved
// ConfigDir; DAXIE_POLICY_* / a hypothetical --policy-* flag have zero effect.
func TestAnchorCarveOut(t *testing.T) {
	dir := t.TempDir()
	// Set a battery of policy-shaped env vars an attacker might hope leak through
	// Viper precedence. None may influence ReadAnchor.
	withEnv(t, map[string]string{
		"HOME":                    t.TempDir(),
		"DAXIE_CONFIG":            dir,
		"DAXIE_POLICY_VERIFY_KEY": "ed25519:ATTACKER",
		"DAXIE_POLICY_ANCHOR":     "/tmp/attacker-anchor.json",
		"DAXIE_POLICY_MAX_TX":     "1000000000000000000000",
	})
	p, _ := ResolvePaths(FlagValues{Config: dir})

	// The anchor path is the config-class file, never the env-named one.
	if p.AnchorPath() != filepath.Join(dir, "policy-anchor.json") {
		t.Fatalf("DAXIE_POLICY_ANCHOR leaked into AnchorPath: %q", p.AnchorPath())
	}

	// With no on-disk anchor, ReadAnchor reports not-found regardless of the env —
	// the attacker's DAXIE_POLICY_VERIFY_KEY does NOT synthesize an anchor.
	raw, found, err := p.ReadAnchor()
	if err != nil {
		t.Fatalf("ReadAnchor: %v", err)
	}
	if found || raw != nil {
		t.Fatalf("env-injected anchor leaked: found=%v raw=%q", found, raw)
	}

	// And `config get`/`set`/`list` never expose the anchor or any policy.* key.
	cfg, _, err := Load(FlagValues{Config: dir})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, gerr := cfg.GetKey("policy.verify_key"); gerr == nil {
		t.Error("config get policy.verify_key did not reject — Viper carve-out broken")
	}
	for _, kv := range cfg.ListKeys() {
		if isPolicyKey(kv.Key) {
			t.Errorf("config list exposed a policy key %q — carve-out broken", kv.Key)
		}
	}
}
