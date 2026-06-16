//go:build !windows

package keys

import "os"

// readKeystoreFile reads a keystore data file (meta.json / keystore.json /
// wallets/<uuid>.json / accounts/<key>) for the LOCK-FREE reader path (§3.3).
//
// On POSIX reads are lock-free: every write goes through fsx.WriteAtomic, and
// rename(2) is atomic against open readers, so a concurrent reader sees either the
// whole old file or the whole new file — never a torn view and never a
// pending-delete error. So this is a plain os.ReadFile; the shared-lock + retry
// the design assigns Windows readers (§3.3/§7.9) lives in the windows build.
func (s *Store) readKeystoreFile(path string) ([]byte, error) {
	return os.ReadFile(path) // #nosec G304 -- path is a keystore file under the store's own dir (callers pass store-internal paths)
}
