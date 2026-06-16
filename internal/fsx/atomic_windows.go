//go:build windows

package fsx

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// openTemp creates the temp file with O_EXCL and FILE_SHARE_DELETE so a reader
// holding it open does not block the subsequent rename, and the temp can be
// renamed/deleted while a handle is live (§7.9). It applies an OWNER-ONLY DACL at
// creation via a SecurityAttributes (§3.11): the new secret file gets an explicit
// owner-only DACL from birth rather than inheriting a possibly-permissive parent
// DACL, so it never transits a BUILTIN\Users/Everyone-readable state. The DACL
// survives the rename onto the destination (rename preserves the source's explicit
// ACL), so the final secret file is owner-only too.
func openTemp(path string, mode os.FileMode) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)

	// Owner-only DACL at creation. If we cannot build it (unusual: token read
	// failure), fall back to a nil SA (inherited DACL) rather than failing the
	// write — the read-time CheckPerms tripwire still guards exposure.
	var sa *windows.SecurityAttributes
	if got, serr := ownerOnlySecurityAttributes(); serr == nil {
		sa = got
	}

	h, err := windows.CreateFile(
		p,
		access,
		share,
		sa,
		windows.CREATE_NEW, // O_EXCL: fail if it exists
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// renameReplace performs an atomic replace via MoveFileEx with REPLACE_EXISTING |
// WRITE_THROUGH. stdlib os.Rename is not atomic-on-existing on Windows, so we go
// straight to the syscall. A sharing violation (a transient open handle on the
// destination) is retried with a short bounded backoff.
func renameReplace(tmp, dst string) error {
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	const flags = windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_WRITE_THROUGH
	const maxAttempts = 10
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		lastErr = windows.MoveFileEx(from, to, flags)
		if lastErr == nil {
			return nil
		}
		if !errors.Is(lastErr, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(lastErr, windows.ERROR_ACCESS_DENIED) {
			return lastErr
		}
		// Back off and retry: a reader without FILE_SHARE_DELETE may be closing.
		time.Sleep(time.Duration(10*(attempt+1)) * time.Millisecond)
	}
	return lastErr
}

// fsyncDir is a no-op on Windows: there is no directory fsync; WRITE_THROUGH on
// the rename approximates the flush (§7.9).
func fsyncDir(dir string) error { return nil }

// mkdirAllPlatform creates the tree, then tightens the leaf directory's DACL to
// owner-only (the platform analogue of 0700).
func mkdirAllPlatform(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return setOwnerOnlyDACL(path)
}

// isReadOnlyErr recognizes the Windows access-denied / write-protect class.
func isReadOnlyErr(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_WRITE_PROTECT) ||
		errors.Is(err, os.ErrPermission)
}
