package fsx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestWriteAtomicCreatesFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.txt")
	if err := WriteAtomic(p, []byte("hello"), 0o600); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("content = %q, want hello", got)
	}
}

func TestWriteAtomicReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.txt")
	if err := WriteAtomic(p, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(p, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != "replacement" {
		t.Fatalf("content = %q, want replacement", got)
	}
	// No temp files left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" || hasTmpPrefix(e.Name()) {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func hasTmpPrefix(name string) bool {
	// our temp files are "<base>.tmp-<hex>"
	for i := 0; i+4 < len(name); i++ {
		if name[i:i+5] == ".tmp-" {
			return true
		}
	}
	return false
}

// TestWriteAtomicOldOrNewNeverTorn simulates a failure after the temp is written
// but before the rename by checking that a write failure leaves the ORIGINAL
// intact and no torn data. We trigger the failure by making the target a path
// whose rename will fail (temp written, but rename into a read-only dir fails).
func TestWriteAtomicLeavesOriginalOnRenameFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX read-only-dir perms (chmod 0o500) do not block writes on Windows; the read-only mapping is exercised on POSIX")
	}
	if os.Getuid() == 0 {
		t.Skip("running as root: directory perms do not block writes")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "data.txt")
	if err := WriteAtomic(p, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Make the directory read-only so the temp create / rename fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := WriteAtomic(p, []byte("replacement"), 0o600)
	if err == nil {
		t.Fatal("expected WriteAtomic to fail on a read-only directory")
	}
	if !IsReadOnly(err) {
		t.Errorf("IsReadOnly(err) = false, want true for err=%v", err)
	}
	// The original content must be intact (never torn).
	_ = os.Chmod(dir, 0o700)
	got, rerr := os.ReadFile(p)
	if rerr != nil {
		t.Fatalf("original gone after failed write: %v", rerr)
	}
	if string(got) != "original" {
		t.Fatalf("original content corrupted: %q", got)
	}
}

func TestMkdirAll(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b", "c")
	if err := MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	fi, err := os.Stat(nested)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("%s is not a directory", nested)
	}
}

func TestLockExclusion(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resource")

	ctx := context.Background()
	unlock, err := Lock(ctx, p)
	if err != nil {
		t.Fatalf("first Lock: %v", err)
	}

	// A second exclusive lock must time out while the first is held.
	tctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err2 := Lock(tctx, p)
	if err2 == nil {
		t.Fatal("second Lock acquired while first held; expected timeout")
	}

	// After unlocking, a new lock must succeed.
	unlock()
	unlock() // idempotent; must not panic
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	unlock3, err3 := Lock(ctx2, p)
	if err3 != nil {
		t.Fatalf("Lock after unlock: %v", err3)
	}
	unlock3()
}

func TestLockUsesSiblingNotDataFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.txt")
	if err := WriteAtomic(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	unlock, err := Lock(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	// The lock file is the sibling, not the data file.
	if _, err := os.Stat(p + ".lock"); err != nil {
		t.Errorf("expected sibling lock file %s.lock: %v", p, err)
	}
	// The data file is untouched and readable while locked.
	got, _ := os.ReadFile(p)
	if string(got) != "x" {
		t.Errorf("data file changed by locking: %q", got)
	}
}

func TestRLockSharedAllowsConcurrent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resource")

	u1, err := RLock(context.Background(), p)
	if err != nil {
		t.Fatalf("first RLock: %v", err)
	}
	// A second shared lock should also succeed concurrently.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	u2, err := RLock(ctx, p)
	if err != nil {
		t.Fatalf("second concurrent RLock failed: %v", err)
	}
	u1()
	u2()
}

func TestLockContextCancelled(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resource")
	unlock, err := Lock(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	_, err2 := Lock(ctx, p)
	if err2 == nil {
		t.Fatal("expected error on a cancelled context")
	}
	if !errors.Is(err2, context.Canceled) && !errors.Is(err2, context.DeadlineExceeded) {
		t.Errorf("err = %v, want a context error", err2)
	}
}

// TestConcurrentWritersSerialized confirms WriteAtomic + Lock keep concurrent
// writers from tearing each other's output.
func TestConcurrentWritersSerialized(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "counter")
	if err := WriteAtomic(p, []byte("start"), 0o600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			unlock, err := Lock(ctx, p)
			if err != nil {
				t.Errorf("Lock: %v", err)
				return
			}
			defer unlock()
			_ = WriteAtomic(p, []byte{byte('a' + n)}, 0o600)
		}(i)
	}
	wg.Wait()
	// The file must contain exactly one writer's single byte — never torn.
	got, _ := os.ReadFile(p)
	if len(got) != 1 {
		t.Fatalf("torn write: content = %q (len %d)", got, len(got))
	}
}
