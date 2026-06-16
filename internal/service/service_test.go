package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// isolate points the config dir at a temp dir holding a minimal config.toml so
// Open succeeds independent of the config package's fresh-empty-dir handling. The
// pure lazy-empty-env path is covered by TestOpenFreshDir.
func isolate(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("schema = 1\n"), 0o600); err != nil {
		t.Fatalf("seed config.toml: %v", err)
	}
	t.Setenv("DAXIE_CONFIG", dir)
	t.Setenv("DAXIE_KEYSTORE", t.TempDir())
	t.Setenv("DAXIE_STATE_DIR", t.TempDir())
	t.Setenv("DAXIE_CACHE_DIR", t.TempDir())
}

// Open must be lazy: it provisions no directories and dials nothing. With a
// present config.toml an empty environment composes the core cleanly (§7.3).
func TestOpenLazyEmptyEnv(t *testing.T) {
	isolate(t)

	svc, err := Open(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Open on empty env: %v", err)
	}
	if svc == nil {
		t.Fatal("Open returned nil service without error")
	}
	if err := svc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// Close is idempotent and never errors in M0.
func TestCloseIdempotent(t *testing.T) {
	isolate(t)
	svc, err := Open(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := svc.Close(); err != nil {
			t.Fatalf("Close call %d: %v", i, err)
		}
	}
}

// The injected clock is what Now reads — never a package-level time.Now.
func TestClockInjected(t *testing.T) {
	isolate(t)
	fixed := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	svc, err := Open(context.Background(), Options{Clock: func() time.Time { return fixed }})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := svc.Now(); !got.Equal(fixed) {
		t.Fatalf("Now() = %v, want injected %v", got, fixed)
	}
}

// A nil clock falls back to the determinism-safe zero clock (Open must not call
// time.Now itself, §2.3).
func TestNilClockFallback(t *testing.T) {
	isolate(t)
	svc, err := Open(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := svc.Now(); !got.IsZero() {
		t.Fatalf("nil-clock fallback Now() = %v, want zero time", got)
	}
}
