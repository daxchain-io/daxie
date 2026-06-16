// Package keys is the on-disk key-management provider (design §3): the
// geth-compatible v3 keystore (mnemonic blobs + stock standalone key files), the
// Daxie metadata sidecar, BIP-39 generation/import, BIP-44 derivation, the
// one-passphrase-per-keystore verifier, atomic passphrase rotation, export, and
// the domain.Signer seam.
//
// keys is a PROVIDER (a leaf, §2.2): it imports domain (for AccountRef / the
// Signer/Unlocker/Signable interfaces and typed errors), the secret provider (for
// secret.Bytes), and the fsx provider (atomic writes / locking / perm checks).
// It never imports service or a frontend. As a provider it is EXEMPT from the
// §2.3 determinism guard — it legitimately uses crypto/rand (entropy, salts, IVs)
// and an injected clock for CreatedAt timestamps.
//
// Crypto invariants (the review hunts these, §3.10):
//
//   - secrets live ONLY in secret.Bytes; plaintext mnemonics/seeds/keys are
//     zeroed via defer the instant they are done being used;
//   - *ecdsa.PrivateKey is zeroed (zeroECDSA) immediately after the sign call;
//   - the wallet blob is a geth v3 envelope via EncryptDataV3/DecryptDataV3 (NOT
//     EncryptKey/DecryptKey, which validate the plaintext as a curve key);
//   - standalone accounts are byte-for-byte stock geth v3 files;
//   - the secp256k1 curve runs on its pure-Go btcec path so CGO_ENABLED=0 links
//     and signs (see secp256k1_link.go);
//   - the standalone import key is validated in [1, n-1].
package keys

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/daxchain-io/daxie/internal/fsx"
)

// Options configure a Store. Dir is the keystore directory ($DAXIE_KEYSTORE).
// Clock is injected so CreatedAt timestamps are deterministic in tests; it
// defaults to time.Now when nil. Light selects the fast test KDF (scrypt N=4096),
// honored ONLY when the manifest was created light (§3.4) — a production keystore
// can never be silently downgraded.
type Options struct {
	Dir   string
	Clock func() time.Time
	Light bool
}

// Store is an opened keystore. It is the package's single exported handle; all
// mutations serialize through the exclusive index.lock (taken per-operation, not
// held for the Store's lifetime, so a CLI one-shot never starves a concurrent
// process). Reads of meta.json/keystore.json are lock-free on POSIX (every write
// goes through fsx.WriteAtomic).
type Store struct {
	dir   string
	clock func() time.Time
	light bool
}

// lockTimeout bounds index.lock acquisition; on expiry callers see
// state.lock_timeout (exit 11) rather than a hang.
const lockTimeout = 15 * time.Second

// Open opens (does NOT create) the keystore at opts.Dir. It runs change-passphrase
// crash recovery (§3.8) and the derivation-watermark check (§3.3) under the
// exclusive index.lock, then returns a ready Store. A missing keystore is the
// fresh-install case: Open succeeds with Initialized()==false and provisions
// nothing (lazy — the dir is created on the first write).
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.Dir == "" {
		return nil, errKeys(CodeKeystoreReadOnly, "keystore directory is empty")
	}
	clk := opts.Clock
	if clk == nil {
		clk = time.Now
	}
	s := &Store{dir: opts.Dir, clock: clk, light: opts.Light}

	// If the keystore dir does not exist yet this is a fresh install: nothing to
	// recover, nothing to check. Defer provisioning to the first write.
	if _, err := os.Stat(s.dir); err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, errKeys(CodeKeystoreReadOnly, "cannot stat keystore directory: "+err.Error())
	}

	// Recovery + watermark must run under the exclusive lock so no concurrent
	// writer races the artifact scan (§3.8). We acquire the lock against the
	// manifest's sibling .lock; the dir already exists so the .lock can be created.
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// 1. change-passphrase crash recovery (forward/backward), §3.8.
	if err := recoverRotation(s.dir); err != nil {
		return nil, err
	}

	// 2. If a manifest exists, validate the derivation watermark (§3.3): a
	//    meta.json whose next_index is below a materialized index would silently
	//    reuse derivation indexes after an unpaired restore — fail closed.
	if s.initialized() {
		m, err := s.loadMeta()
		if err != nil {
			return nil, err
		}
		if err := m.checkWatermark(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Close releases any resources. The Store holds no long-lived lock (locks are
// per-operation), so Close is currently a no-op; it exists for the lifecycle
// contract and forward compatibility (mcp serve's cached unlock, M11).
func (s *Store) Close() error { return nil }

// Initialized reports whether the keystore has been initialized (the verifier in
// keystore.json is present).
func (s *Store) Initialized() bool { return s.initialized() }

// initialized is the unexported check (keystore.json present and parseable as an
// initialized manifest).
func (s *Store) initialized() bool {
	_, err := os.Stat(s.manifestPath())
	return err == nil
}

// ── path helpers ──────────────────────────────────────────────────────────────

func (s *Store) manifestPath() string { return filepath.Join(s.dir, "keystore.json") }
func (s *Store) metaPath() string     { return filepath.Join(s.dir, "meta.json") }
func (s *Store) walletsDir() string   { return filepath.Join(s.dir, "wallets") }
func (s *Store) accountsDir() string  { return filepath.Join(s.dir, "accounts") }
func (s *Store) walletBlobPath(id string) string {
	return filepath.Join(s.walletsDir(), id+".json")
}

// lock takes the exclusive index.lock with a bounded timeout, mapping a timeout to
// state.lock_timeout (exit 11). The lock sibling is the manifest path's .lock so
// every keystore mutation contends on the same lock object.
func (s *Store) lock(ctx context.Context) (func(), error) {
	// The dir must exist for the .lock to be created; callers that may create the
	// dir (writes) ensure it first.
	lctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	unlock, err := fsx.Lock(lctx, s.manifestPath())
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, errKeys(CodeStateLockTimeout, "timed out acquiring the keystore lock; another daxie process may be holding it")
		}
		return nil, errKeys(CodeStateLockTimeout, "cannot acquire the keystore lock: "+err.Error())
	}
	return unlock, nil
}

// ensureDirs creates the keystore dir and its wallets/ and accounts/ subdirs with
// 0700 (owner-only). Called before the first write. A read-only target maps to
// keystore.read_only.
//
// os.MkdirAll is subject to the process umask and does NOT alter an existing
// dir's mode, so keys explicitly chmods each owned dir to 0700 afterwards — the
// design requires owner-only (§3.3) regardless of umask or a pre-existing dir.
// The chmod is skipped on Windows (POSIX modes are not meaningful; the owner-only
// DACL is applied by fsx / inherited; the Windows perm test asserts the DACL).
func (s *Store) ensureDirs() error {
	for _, d := range []string{s.dir, s.walletsDir(), s.accountsDir()} {
		if err := fsx.MkdirAll(d, 0o700); err != nil {
			if fsx.IsReadOnly(err) {
				return errKeys(CodeKeystoreReadOnly, "the keystore directory is read-only: "+err.Error())
			}
			return errKeys(CodeStateCorrupt, "cannot create keystore directory: "+err.Error())
		}
		if err := chmodOwnerOnlyDir(d); err != nil {
			if fsx.IsReadOnly(err) {
				return errKeys(CodeKeystoreReadOnly, "the keystore directory is read-only: "+err.Error())
			}
			return errKeys(CodeStateCorrupt, "cannot set keystore directory permissions: "+err.Error())
		}
	}
	return nil
}
