// Package registry owns Daxie's local, explicit name→on-chain-object bindings:
// the contacts address book (M3), and — added by later milestones in the same
// package with the same path/lock/atomicity discipline — the per-network token
// registry (M5), NFT collections/aliases (M6), and the contract registry (M10).
// All resolution is registry-only by design (requirements §2): a name not in the
// registry is an error, never an on-chain symbol()/name() lookup, because symbol
// spoofing is free (§7.8).
//
// M3 ships ONLY contacts (contacts.json — network-agnostic, since an address is
// an address across EVM chains). The per-network token/NFT/contract files
// (registry/<network>.json) are M5/M6/M10 — this package deliberately does not
// create them yet.
//
// Dependency rules (§2.2, enforced by arch_test): registry imports fsx, domain
// (and secret, sanctioned but unused in M3). It NEVER imports service or a
// frontend. It owns NO platform-specific code — every atomic write, lock, and
// permission goes through fsx (§7.9).
package registry

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
)

// fileMode is the owner-only mode every registry file is written with (state
// class, §7.8). The contacts file carries no secret, but addresses/labels are
// integrity-bearing, so 0600 is the floor.
const fileMode = 0o600

// dirMode is the owner-only mode for the registry dir and its locks/ subdir.
const dirMode = 0o700

// registryLockTimeout bounds lock acquisition; a timeout maps to
// state.lock_timeout (exit 11) — contention, retryable.
const registryLockTimeout = 30 * time.Second

// locksDir is <registryDir>/locks — the home of every registry .lock sibling so
// all registry mutations (contacts now; tokens/NFTs/contracts later) contend on
// files under one well-known dir.
func locksDir(registryDir string) string { return filepath.Join(registryDir, "locks") }

// registryLockPath is the shared registry flock sibling base
// (<registryDir>/locks/registry → .lock added by fsx). §7.8: all registry
// mutations serialize on locks/registry.lock.
func registryLockPath(registryDir string) string {
	return filepath.Join(locksDir(registryDir), "registry")
}

// withRegistryLock runs fn while holding the exclusive registry flock, mapping a
// lock timeout to state.lock_timeout. It MkdirAll's the locks dir first (lazy,
// §7.3 — nothing exists until the first write). A read-only state mount surfaces
// as config.read_only (exit 10) via the §7.8 state-class read-only sibling rule.
func withRegistryLock(ctx context.Context, registryDir string, fn func() error) error {
	if err := fsx.MkdirAll(locksDir(registryDir), dirMode); err != nil {
		if fsx.IsReadOnly(err) {
			return errReadOnly()
		}
		return domain.Wrap("state.corrupt", "cannot create the registry locks directory", err)
	}
	lctx, cancel := context.WithTimeout(ctx, registryLockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lctx, registryLockPath(registryDir))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return domain.New(domain.CodeStateLockTimeout,
				"timed out acquiring the registry lock; another daxie process may be holding it")
		}
		return domain.New(domain.CodeStateLockTimeout, "cannot acquire the registry lock: "+err.Error())
	}
	defer unlock()
	return fn()
}

// errReadOnly is the state-class read-only sibling of config.read_only (exit 10,
// §7.8): a registry write against a read-only state mount. token add / contacts
// add fail with this so the operator knows to pre-seed the state PVC or move it
// to a writable volume.
func errReadOnly() error {
	return domain.New(domain.CodeConfigReadOnly,
		"the registry is on a read-only mount; contacts cannot be written (move the state directory or DAXIE_REGISTRY_DIR to a writable volume)")
}
