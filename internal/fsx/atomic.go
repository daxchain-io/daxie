// Package fsx is the single durable-write + locking + permission helper. No
// package outside fsx hand-rolls temp+rename or platform-specific permission
// code (§7.9). WriteAtomic is a correctness guarantee on all three OSes: a
// process killed mid-write leaves either the old or the new file intact, never a
// torn one. The Windows divergence (MoveFileEx, no dir fsync, DACL inspection)
// lives behind build tags in this package and nowhere else.
//
// fsx is a provider (a leaf): it imports domain for the typed *domain.Error that
// CheckPerms returns, plus gofrs/flock and golang.org/x/sys; nothing in service
// or a frontend.
package fsx

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrReadOnly is the sentinel callers branch on to map a write failure to the
// config.read_only / keystore.read_only domain code (exit 10). WriteAtomic wraps
// it around EROFS/EACCES/EPERM-class failures; use IsReadOnly to detect it.
var ErrReadOnly = errors.New("fsx: read-only target")

// WriteAtomic writes data to path atomically: it creates a temp file in the same
// directory (so the rename is intra-filesystem), fsyncs the file, renames it over
// path via the platform replace primitive, and (POSIX) fsyncs the parent dir.
//
// On a read-only / permission-denied write it returns an error that satisfies
// IsReadOnly (and wraps ErrReadOnly) so callers can map it to config.read_only.
func WriteAtomic(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmp, terr := tempName(dir, base)
	if terr != nil {
		return classifyWrite(terr)
	}

	// Open with O_EXCL so we never clobber a concurrent writer's temp; include
	// FILE_SHARE_DELETE semantics on Windows (handled by the platform open).
	f, oerr := openTemp(tmp, mode)
	if oerr != nil {
		return classifyWrite(oerr)
	}
	// Best-effort cleanup of the temp on any failure after this point.
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()

	if _, werr := f.Write(data); werr != nil {
		return classifyWrite(werr)
	}
	if serr := f.Sync(); serr != nil {
		// On some filesystems Sync is unsupported; treat a hard error as fatal
		// but allow ENOTSUP-class to pass (rare). We keep it simple: surface it.
		return classifyWrite(serr)
	}
	if cerr := f.Close(); cerr != nil {
		return classifyWrite(cerr)
	}

	// Platform replace (rename POSIX / MoveFileEx Windows).
	if rerr := renameReplace(tmp, path); rerr != nil {
		return classifyWrite(rerr)
	}
	committed = true

	// Durability of the directory entry (POSIX only; no-op on Windows).
	if derr := fsyncDir(dir); derr != nil {
		// A dir-fsync failure does not un-commit the rename; report it but the
		// data is already in place. Callers generally treat this as success-ish;
		// we surface it so a truly broken FS is visible.
		return classifyWrite(derr)
	}
	return nil
}

// MkdirAll creates path and all parents with the given mode (0700 on POSIX;
// owner-only DACL on Windows applied by the platform layer). A read-only parent
// maps through IsReadOnly.
func MkdirAll(path string, mode os.FileMode) error {
	if err := mkdirAllPlatform(path, mode); err != nil {
		return classifyWrite(err)
	}
	return nil
}

// tempName returns a unique temp path "<base>.tmp-<rand>" in dir.
func tempName(dir, base string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return filepath.Join(dir, base+".tmp-"+hex.EncodeToString(b[:])), nil
}

// classifyWrite wraps a low-level write error so IsReadOnly can recognize the
// read-only class while preserving the original via errors.Is/As.
func classifyWrite(err error) error {
	if err == nil {
		return nil
	}
	if isReadOnlyErr(err) {
		return fmt.Errorf("%w: %v", ErrReadOnly, err)
	}
	return err
}

// IsReadOnly reports whether err is a read-only / permission-denied class write
// failure (EROFS/EACCES/EPERM on POSIX; ACCESS_DENIED/WRITE_PROTECT on Windows),
// including errors wrapped by WriteAtomic.
func IsReadOnly(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrReadOnly) {
		return true
	}
	return isReadOnlyErr(err)
}
