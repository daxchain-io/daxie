//go:build !windows

package secret

import "golang.org/x/sys/unix"

// memlock best-effort pins b into RAM so it is not swapped to disk. A failure is
// non-fatal (the design treats memory locking as best-effort, §3.10/R7): we
// return false and the caller proceeds. Returns true iff the lock succeeded so
// memunlock is only called when it must be.
func memlock(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if err := unix.Mlock(b); err != nil {
		return false
	}
	return true
}

// memunlock releases a lock taken by memlock. Best-effort; errors are ignored.
func memunlock(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = unix.Munlock(b)
}
