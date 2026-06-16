package keys

import (
	"context"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/secret"
)

// testPass is the fixed keystore passphrase used across tests.
const testPass = "correct horse battery staple"

// fixedClock returns a deterministic monotonically-stepping clock so CreatedAt and
// the UTC key-file names are stable and unique within a test.
func fixedClock() func() time.Time {
	base := time.Date(2026, 6, 12, 9, 21, 33, 0, time.UTC)
	var n int64
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}

// newLightStore opens a fresh light keystore in a temp dir (fast scrypt).
func newLightStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(context.Background(), Options{Dir: dir, Clock: fixedClock(), Light: true})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// initStore opens a light keystore AND establishes the verifier under testPass
// (the first-init double-entry), returning the store and a live passphrase buffer.
func initStore(t *testing.T) (*Store, *secret.Bytes) {
	t.Helper()
	s := newLightStore(t)
	pass := secret.NewString(testPass)
	confirm := secret.NewString(testPass)
	t.Cleanup(func() { pass.Zero(); confirm.Zero() })
	if _, err := s.EnsureInitialized(context.Background(), pass, confirm); err != nil {
		t.Fatalf("EnsureInitialized: %v", err)
	}
	return s, pass
}

// reopen reopens an existing store dir with a fresh handle (running crash recovery
// + watermark), preserving the light flag.
func reopen(t *testing.T, s *Store) *Store {
	t.Helper()
	ns, err := Open(context.Background(), Options{Dir: s.dir, Clock: fixedClock(), Light: true})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	return ns
}

// testUnlocker is a domain.Unlocker backed by a fixed passphrase string, for the
// signing tests (the service owns the real one).
type testUnlocker struct{ pass string }

func (u testUnlocker) Passphrase(ctx context.Context) ([]byte, error) {
	return []byte(u.pass), nil
}
