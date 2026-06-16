package fsx

import (
	"context"
	"time"

	"github.com/gofrs/flock"
)

// lockRetryInterval is how often the ctx-bounded lock acquisition retries while
// waiting for the lock to become available.
const lockRetryInterval = 25 * time.Millisecond

// Lock takes the EXCLUSIVE advisory flock on the SIBLING <path>.lock file (never
// the data file itself — a temp+rename would break lock continuity, and Windows
// LockFileEx is mandatory). The wait is bounded by ctx; on ctx expiry it returns
// the ctx error (callers map this to state.lock_timeout). The returned unlock is
// safe to call exactly once; it is nil when err is non-nil.
func Lock(ctx context.Context, path string) (unlock func(), err error) {
	return acquire(ctx, path, false)
}

// RLock takes a SHARED advisory lock on the sibling <path>.lock. Required on
// Windows so a reader holding the data file open does not block a concurrent
// writer's atomic rename (§7.9). Same ctx-bounding and unlock contract as Lock.
func RLock(ctx context.Context, path string) (unlock func(), err error) {
	return acquire(ctx, path, true)
}

func acquire(ctx context.Context, path string, shared bool) (func(), error) {
	// The lock is the sibling <path>.lock, never the data file (§7.9). flock
	// creates it 0600; it carries no secret, so it is not perms-checked. The
	// parent directory is expected to exist (callers MkdirAll it first).
	lockPath := path + ".lock"

	fl := flock.New(lockPath)
	var try func(context.Context, time.Duration) (bool, error)
	if shared {
		try = fl.TryRLockContext
	} else {
		try = fl.TryLockContext
	}

	locked, err := try(ctx, lockRetryInterval)
	if err != nil {
		return nil, err
	}
	if !locked {
		// TryLockContext returns (false, nil) only when ctx is done; surface the
		// ctx error so callers can distinguish a timeout.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, context.DeadlineExceeded
	}

	once := false
	return func() {
		if once {
			return
		}
		once = true
		_ = fl.Unlock()
	}, nil
}
