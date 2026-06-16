//go:build windows

package secret

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// memlock best-effort pins b into the working set via VirtualLock so the page is
// not written to the pagefile. Best-effort per the design (§3.10/R7): a failure
// returns false and the caller proceeds.
func memlock(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	addr := uintptr(unsafe.Pointer(&b[0])) // #nosec G103 -- required to pass a buffer address to the VirtualLock syscall
	if err := windows.VirtualLock(addr, uintptr(len(b))); err != nil {
		return false
	}
	return true
}

// memunlock releases a VirtualLock taken by memlock. Best-effort; errors ignored.
func memunlock(b []byte) {
	if len(b) == 0 {
		return
	}
	addr := uintptr(unsafe.Pointer(&b[0])) // #nosec G103 -- required to pass a buffer address to the VirtualUnlock syscall
	_ = windows.VirtualUnlock(addr, uintptr(len(b)))
}
