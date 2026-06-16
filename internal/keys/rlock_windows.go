//go:build windows

package keys

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"

	"github.com/daxchain-io/daxie/internal/fsx"
)

// readRetryAttempts / readRetryBackoff bound the ERROR_ACCESS_DENIED retry a
// Windows lock-free-ish reader does when it catches a name in pending-delete
// during a concurrent writer's atomic rename (§3.3/§7.9). A handful of short
// retries covers the rename window; past that the error is real and surfaces.
const (
	readRetryAttempts = 10
	readRetryBackoff  = 10 * time.Millisecond
)

// readKeystoreFile reads a keystore data file (meta.json / keystore.json /
// wallets/<uuid>.json / accounts/<key>) for the Windows reader path (§3.3, §7.9).
//
// Unlike POSIX (where rename(2) is atomic against open readers, so reads are
// lock-free), Windows needs the reader to (1) take the SHARED fsx.RLock on the
// keystore's sibling .lock — the same lock object every writer takes exclusively —
// so a reader holding the data file open does not break a concurrent writer's
// MoveFileEx rename, and (2) retry transient ERROR_ACCESS_DENIED, which surfaces
// when a name is in pending-delete during that rename. The shared lock is taken
// against manifestPath() so all keystore reads/writes contend on one lock object.
//
// The lock is best-effort on acquisition FAILURE that is not a timeout (e.g. a
// read-only Secret mount where the .lock cannot be created): we still perform the
// bounded retry-read, which on its own tolerates the rename race. A real timeout
// (a long-held exclusive lock) surfaces as state.lock_timeout.
func (s *Store) readKeystoreFile(path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()

	unlock, err := fsx.RLock(ctx, s.manifestPath())
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, errKeys(CodeStateLockTimeout, "timed out acquiring the keystore read lock; another daxie process may be holding it exclusively")
		}
		// Could not create/acquire the shared lock (e.g. read-only mount). Fall
		// through to the retry-read, which tolerates the rename race on its own.
		return readWithAccessDeniedRetry(path)
	}
	defer unlock()
	return readWithAccessDeniedRetry(path)
}

// readWithAccessDeniedRetry reads path, retrying a bounded number of times on
// ERROR_ACCESS_DENIED (a name in pending-delete during a concurrent atomic
// rename, §7.9). A non-ACCESS_DENIED error returns immediately.
func readWithAccessDeniedRetry(path string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < readRetryAttempts; attempt++ {
		b, err := os.ReadFile(path) // #nosec G304 -- path is a keystore file under the store's own dir
		if err == nil {
			return b, nil
		}
		lastErr = err
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, err
		}
		time.Sleep(readRetryBackoff)
	}
	return nil, lastErr
}
