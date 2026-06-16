//go:build !windows

package keys

import "os"

// chmodOwnerOnlyDir forces a directory to mode 0700 (owner-only), overriding the
// umask that os.MkdirAll honors and fixing a pre-existing dir created with looser
// bits. POSIX only; the Windows variant applies an owner-only DACL instead (DACLs
// govern there, §3.11).
func chmodOwnerOnlyDir(path string) error {
	return os.Chmod(path, 0o700) // #nosec G302 -- a directory needs the execute bit; 0700 is owner-only (§3.3)
}
