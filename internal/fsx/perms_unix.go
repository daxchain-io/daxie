//go:build !windows

package fsx

import (
	"fmt"
	"os"
	"syscall"

	"github.com/daxchain-io/daxie/internal/domain"
	"golang.org/x/sys/unix"
)

// permErr builds the canonical hard-failure domain error naming the file and the
// remedy. It lives in the POSIX file because only the POSIX rule reports modes;
// the Windows DACL path builds its own message via winPermErr.
func permErr(path string, mode os.FileMode) error {
	return domain.WithData(
		domain.Newf(
			"keystore.perms_insecure",
			"insecure permissions on %s: mode %#o exposes the file to other users; run `chmod 0600 %s` (or set DAXIE_SKIP_PERM_CHECK=1 only on filesystems that cannot represent permissions)",
			path, mode.Perm(), path,
		),
		map[string]any{"path": path, "mode": mode.Perm().String()},
	)
}

// checkPermsPlatform implements the POSIX §7.9 rule. It returns a hard
// *domain.Error on world/group-write bits, applies the fsGroup carve-out for
// group-read, and warns (non-fatal) when group-read is granted to a group the
// process does not belong to.
func checkPermsPlatform(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := fi.Mode()

	// Hard rule: any world bit (rwx) or group-write/group-exec is insecure.
	if mode.Perm()&0o037 != 0 {
		return permErr(path, mode)
	}

	// Group-read carve-out. If group-read is not set, nothing more to check.
	if mode.Perm()&0o040 == 0 {
		return nil
	}

	// Group-read is set. Accept silently iff the file's group is one the process
	// belongs to (effective GID or a supplementary group); else warn.
	gid, ok := fileGID(fi)
	if !ok {
		// Cannot determine the file's gid (unusual FS); warn rather than fail.
		warnGroupRead(path, "could not determine file group")
		return nil
	}
	if processInGroup(gid) {
		return nil // fsGroup shape: a 0440 Secret owned by a group we belong to.
	}
	warnGroupRead(path, fmt.Sprintf("group %d is not one this process belongs to", gid))
	return nil
}

// fileGID extracts the owning gid from a FileInfo's underlying stat_t.
func fileGID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Gid, true
}

// processInGroup reports whether gid is the process's effective GID or one of its
// supplementary groups.
func processInGroup(gid uint32) bool {
	// Compare in int space: GIDs are non-negative and fit in int on all targets,
	// so widening the file's uint32 gid to int avoids a narrowing conversion.
	want := int(gid)
	if unix.Getegid() == want {
		return true
	}
	groups, err := unix.Getgroups()
	if err != nil {
		return false
	}
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}

func warnGroupRead(path, why string) {
	// Best-effort warning; a write failure to the warn sink is not actionable.
	_, _ = fmt.Fprintf(permWarnSink, "warning: %s is group-readable (%s); ensure this is intentional\n", path, why)
}
