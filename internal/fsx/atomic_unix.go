//go:build !windows

package fsx

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// openTemp creates the temp file with O_EXCL at the requested mode. The umask can
// reduce the mode; callers that require exact bits (secret files) pass 0600 and
// the perms check will still pass since 0600 has no world/group bits.
func openTemp(path string, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- path is the caller-supplied destination; writing it is the WriteAtomic contract
}

// renameReplace is rename(2): atomic against open readers on POSIX, so reads are
// lock-free (§7.9).
func renameReplace(tmp, dst string) error {
	return os.Rename(tmp, dst)
}

// fsyncDir fsyncs the directory so the rename's directory entry is durable.
func fsyncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- dir is a caller-controlled config/state path; opening it for fsync is the fsx contract
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		// Some filesystems (e.g. certain network mounts) reject dir fsync with
		// EINVAL/ENOTSUP — not a durability bug we can fix here, so tolerate it.
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) {
			return nil
		}
		return err
	}
	return nil
}

// mkdirAllPlatform creates the tree at the given mode (0700 for the keystore/
// state/config dirs).
func mkdirAllPlatform(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

// isReadOnlyErr recognizes the EROFS/EACCES/EPERM read-only/permission class.
func isReadOnlyErr(err error) bool {
	return errors.Is(err, unix.EROFS) ||
		errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EPERM) ||
		errors.Is(err, os.ErrPermission)
}
