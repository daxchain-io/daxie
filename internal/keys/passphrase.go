package keys

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"

	"github.com/daxchain-io/daxie/internal/fsx"
	"github.com/daxchain-io/daxie/internal/secret"
)

// rotation artifact names (§3.8). The marker is the commit point: its presence
// means "roll forward"; bare .new files with no marker mean "roll back".
const (
	rotateMarkerName = "ROTATE-COMMIT"
	stagedSuffix     = ".new"
)

// rotateMarker is the committed list of staged files. Each entry is a keystore-dir
// relative path whose <path>.new must be renamed onto <path> to complete the swap.
type rotateMarker struct {
	Files []string `json:"files"`
}

// faultHook lets tests inject a crash at a named point in ChangePassphrase. In
// production it is nil. The string identifies the point; a non-nil return aborts
// the operation there (simulating a process kill that leaves on-disk artifacts in
// whatever state the prior steps produced). Test-only; never set in prod code.
var faultHook func(point string) error

func fireFault(point string) error {
	if faultHook == nil {
		return nil
	}
	return faultHook(point)
}

// ChangePassphrase re-encrypts the verifier + every wallet blob + every standalone
// key file from oldPass to newPass, atomically (§3.8). A crash never leaves a
// mixed-passphrase keystore: keys.Open's recovery rolls forward (marker present)
// or back (only .new files). Returns the count of rotated secret files and the new
// passphrase fingerprint.
func (s *Store) ChangePassphrase(ctx context.Context, oldPass, newPass *secret.Bytes) (int, string, error) {
	unlock, err := s.lock(ctx)
	if err != nil {
		return 0, "", err
	}
	defer unlock()

	// Recover any prior interrupted rotation FIRST, so we start from a clean,
	// single-passphrase state (never stack a rotation on staged artifacts).
	if rerr := recoverRotation(s.dir); rerr != nil {
		return 0, "", rerr
	}

	man, err := s.loadManifest()
	if err != nil {
		return 0, "", err
	}
	if man == nil {
		return 0, "", errKeys(CodeKeystoreBadPassphrase, "the keystore is not initialized; nothing to rotate")
	}
	// Verify the OLD passphrase against the current verifier.
	if verr := verifyAgainst(man, oldPass); verr != nil {
		return 0, "", verr
	}

	m, err := s.loadMeta()
	if err != nil {
		return 0, "", err
	}

	// The set of secret files to rotate: keystore.json (verifier) + wallet blobs +
	// standalone key files. Paths are keystore-dir relative.
	secretFiles := s.rotationFileSet(m)

	oldBytes := oldPass.Reveal()
	newBytes := newPass.Reveal()
	// Choose params: a light manifest stays light; otherwise standard (§3.4).
	n, p := s.effectiveScrypt(man)

	// ── STAGE ──: write each re-encryption as <file>.new with fresh salts/IVs. Any
	// decrypt failure aborts with nothing renamed (rollback deletes the .new files).
	staged := make([]string, 0, len(secretFiles))
	abort := func(cause error) (int, string, error) {
		// Best-effort cleanup of whatever we staged before the failure.
		for _, rel := range staged {
			_ = os.Remove(filepath.Join(s.dir, rel+stagedSuffix))
		}
		return 0, "", cause
	}

	// keystore.json: re-seal the verifier under newPass; refresh the fingerprint
	// salt so the new fingerprint is independent.
	newMan, merr := s.restageManifest(man, oldBytes, newBytes, n, p)
	if merr != nil {
		return abort(merr)
	}
	if werr := s.stageManifest(newMan); werr != nil {
		return abort(werr)
	}
	staged = append(staged, "keystore.json")
	if ferr := fireFault("after_stage_manifest"); ferr != nil {
		return abort(ferr)
	}

	for _, rel := range secretFiles {
		if rel == "keystore.json" {
			continue
		}
		if rerr := s.restageSecretFile(rel, oldBytes, newBytes, n, p); rerr != nil {
			return abort(rerr)
		}
		staged = append(staged, rel)
		if ferr := fireFault("after_stage_" + filepath.Base(rel)); ferr != nil {
			return abort(ferr)
		}
	}
	if ferr := fireFault("before_commit"); ferr != nil {
		return abort(ferr)
	}

	// ── COMMIT ──: atomic-write the marker listing every staged file. Before this
	// the rotation has not happened; after, it is irrevocable (roll forward only).
	marker := rotateMarker{Files: append([]string(nil), staged...)}
	sort.Strings(marker.Files)
	mb, _ := json.MarshalIndent(marker, "", "  ")
	if werr := fsx.WriteAtomic(s.markerPath(), mb, 0o600); werr != nil {
		if fsx.IsReadOnly(werr) {
			return abort(errKeys(CodeKeystoreReadOnly, "the keystore is read-only; cannot commit the rotation"))
		}
		return abort(errWrap(CodeStateCorrupt, "cannot write the rotation commit marker", werr))
	}
	if ferr := fireFault("after_commit"); ferr != nil {
		// Crash right after commit: the marker is on disk, so the NEXT Open rolls
		// FORWARD. We must NOT clean up here — that is the whole point.
		return 0, "", ferr
	}

	// ── SWAP ──: rename each X.new -> X, then delete the marker.
	if serr := swapStaged(s.dir, marker.Files); serr != nil {
		return 0, "", serr
	}
	if ferr := fireFault("after_swap_before_marker_delete"); ferr != nil {
		// Marker still present but all swaps done: next Open finishes (idempotent
		// rename of already-renamed files is a no-op) and deletes the marker.
		return 0, "", ferr
	}
	_ = os.Remove(s.markerPath())

	fp := fingerprint(newMan.FingerprintSalt, newPass)
	return len(secretFiles), fp, nil
}

// rotationFileSet returns the keystore-dir-relative paths of every secret file
// (verifier manifest + wallet blobs + standalone key files), sorted for
// determinism.
func (s *Store) rotationFileSet(m *metaFile) []string {
	out := []string{"keystore.json"}
	for id := range m.Wallets {
		out = append(out, filepath.ToSlash(filepath.Join("wallets", id+".json")))
	}
	for _, a := range m.Accounts {
		out = append(out, filepath.ToSlash(a.File))
	}
	sort.Strings(out)
	return out
}

func (s *Store) markerPath() string { return filepath.Join(s.dir, rotateMarkerName) }

// restageManifest builds a new manifest with the verifier re-sealed under newPass
// (decrypting the current verifier with oldPass to confirm, then sealing fresh 32
// random bytes — the verifier plaintext is arbitrary, so we mint new bytes rather
// than carry the old).
func (s *Store) restageManifest(man *manifest, oldBytes, newBytes []byte, n, p int) (*manifest, error) {
	// Confirm the old verifier decrypts (already verified by caller, but cheap and
	// keeps this function self-contained for the recovery audit).
	plain, derr := gethkeystore.DecryptDataV3(man.Verifier.Crypto, string(oldBytes))
	if derr != nil {
		return nil, errKeys(CodeKeystoreBadPassphrase, "wrong keystore passphrase")
	}
	zeroBytes(plain)

	// Mint fresh verifier plaintext + fingerprint salt for the rotated passphrase.
	tmp := &Store{dir: s.dir, clock: s.clock, light: man.Light}
	nm, ierr := tmp.initManifestWith(newBytes, man, n, p)
	if ierr != nil {
		return nil, ierr
	}
	return nm, nil
}

// initManifestWith is initManifest but for an explicit passphrase byte slice and a
// base manifest (preserving CreatedAt + Light), used by rotation.
func (s *Store) initManifestWith(passBytes []byte, base *manifest, n, p int) (*manifest, error) {
	tmpPass := secret.New(append([]byte(nil), passBytes...))
	defer tmpPass.Zero()
	nm, err := s.initManifest(tmpPass)
	if err != nil {
		return nil, err
	}
	// Preserve the original creation time + light flag; only the verifier and
	// fingerprint salt change on rotation.
	nm.CreatedAt = base.CreatedAt
	nm.Light = base.Light
	// initManifest used s.scryptParams(s.light); ensure the recorded defaults match
	// the rotation params (they do: effectiveScrypt picked the same source).
	nm.KDFDefaults.N = n
	nm.KDFDefaults.P = p
	return nm, nil
}

// stageManifest writes the new manifest to keystore.json.new (0600).
func (s *Store) stageManifest(nm *manifest) error {
	nm.Format = manifestFormatVersion
	b, err := json.MarshalIndent(nm, "", "  ")
	if err != nil {
		return errWrap(CodeStateCorrupt, "cannot encode the rotated keystore.json", err)
	}
	if werr := fsx.WriteAtomic(s.manifestPath()+stagedSuffix, b, 0o600); werr != nil {
		if fsx.IsReadOnly(werr) {
			return errKeys(CodeKeystoreReadOnly, "the keystore is read-only; cannot stage the rotation")
		}
		return errWrap(CodeStateCorrupt, "cannot stage the rotated keystore.json", werr)
	}
	return nil
}

// restageSecretFile decrypts a wallet blob OR a standalone key file with oldBytes
// and writes its re-encryption (fresh salts/IVs) to <file>.new (0600). It
// dispatches on the path prefix.
func (s *Store) restageSecretFile(rel string, oldBytes, newBytes []byte, n, p int) error {
	full := filepath.Join(s.dir, filepath.FromSlash(rel))
	stagedFull := full + stagedSuffix

	if strings.HasPrefix(rel, "wallets/") {
		// Wallet blob: DecryptDataV3 -> EncryptDataV3 (arbitrary-bytes envelope).
		id := strings.TrimSuffix(strings.TrimPrefix(rel, "wallets/"), ".json")
		plain, derr := s.readWalletPlaintext(id, oldBytes)
		if derr != nil {
			return derr
		}
		defer zeroBytes(plain)
		cj, eerr := gethkeystore.EncryptDataV3(plain, newBytes, n, p)
		if eerr != nil {
			return errWrap(CodeStateCorrupt, "cannot re-encrypt the wallet blob", eerr)
		}
		blob := walletBlob{DaxieWallet: walletBlobVersion, Type: "mnemonic", ID: id, Version: 3, Crypto: cj}
		b, _ := json.MarshalIndent(blob, "", "  ")
		return stageWrite(stagedFull, b)
	}

	// Standalone key file: DecryptKey -> EncryptKey (stock geth v3, byte-for-byte).
	// Preserve the file's existing UUID so the rotated file is the same identity.
	keyUUID, uerr := s.uuidOfStandaloneFile(rel)
	if uerr != nil {
		return uerr
	}
	priv, derr := s.readStandaloneKey(rel, oldBytes)
	if derr != nil {
		return derr
	}
	defer zeroECDSA(priv)
	gkey := &gethkeystore.Key{Id: keyUUID, Address: cryptoAddr(priv), PrivateKey: priv}
	b, eerr := gethkeystore.EncryptKey(gkey, string(newBytes), n, p)
	if eerr != nil {
		return errWrap(CodeStateCorrupt, "cannot re-encrypt the standalone key", eerr)
	}
	return stageWrite(stagedFull, b)
}

func stageWrite(stagedFull string, b []byte) error {
	if werr := fsx.WriteAtomic(stagedFull, b, 0o600); werr != nil {
		if fsx.IsReadOnly(werr) {
			return errKeys(CodeKeystoreReadOnly, "the keystore is read-only; cannot stage the rotation")
		}
		return errWrap(CodeStateCorrupt, "cannot stage a rotated secret file", werr)
	}
	return nil
}

// swapStaged renames each <file>.new -> <file> for the given relative paths. It is
// idempotent: a missing .new with an already-present target is a completed swap, a
// no-op (the forward-recovery case). Any other error is fatal.
func swapStaged(dir string, relFiles []string) error {
	for _, rel := range relFiles {
		target := filepath.Join(dir, filepath.FromSlash(rel))
		staged := target + stagedSuffix
		if _, err := os.Stat(staged); err != nil {
			if os.IsNotExist(err) {
				// Already swapped (forward recovery) — confirm the target exists.
				if _, terr := os.Stat(target); terr == nil {
					continue
				}
				return errKeysf(CodeStateCorrupt, "rotation swap incomplete: neither %s nor its staged copy exist", rel)
			}
			return errWrap(CodeStateCorrupt, "cannot stat a staged rotation file", err)
		}
		if rerr := renameStaged(staged, target); rerr != nil {
			return errWrap(CodeStateCorrupt, "cannot complete the rotation swap", rerr)
		}
	}
	return nil
}

// renameStaged renames a staged file over its target with replace-existing
// semantics. On POSIX os.Rename is atomic against open readers; on Windows Go's
// os.Rename maps to MoveFileEx(MOVEFILE_REPLACE_EXISTING) for files. The staged
// file was durably written via fsx.WriteAtomic, so this is the only rename keys
// does outside fsx — a single rename of an already-fsynced file, kept here so the
// rotation swap is auditable in one place.
func renameStaged(staged, target string) error { return os.Rename(staged, target) }

// ── crash recovery (run by keys.Open under the exclusive lock, §3.8) ────────────

// recoverRotation scans the keystore dir for rotation artifacts and brings it to a
// single-passphrase consistent state. With the marker present it rolls FORWARD
// (finish every rename, delete the marker); with only .new files it rolls BACK
// (delete them). It is idempotent and safe to call on every Open. The caller holds
// the exclusive lock.
func recoverRotation(dir string) error {
	markerPath := filepath.Join(dir, rotateMarkerName)
	mb, err := os.ReadFile(markerPath) // #nosec G304 -- markerPath is ROTATE-COMMIT under the store's own keystore dir
	if err == nil {
		// Marker present: roll FORWARD.
		var marker rotateMarker
		if jerr := json.Unmarshal(mb, &marker); jerr != nil {
			return errWrap(CodeStateCorrupt, "the rotation commit marker is corrupt", jerr)
		}
		if serr := swapStaged(dir, marker.Files); serr != nil {
			return serr
		}
		if rerr := os.Remove(markerPath); rerr != nil && !os.IsNotExist(rerr) {
			return errWrap(CodeStateCorrupt, "cannot remove the rotation marker after forward recovery", rerr)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return errWrap(CodeStateCorrupt, "cannot read the rotation marker", err)
	}

	// No marker: roll BACK any orphaned .new files (an interrupted STAGE).
	return rollbackStaged(dir)
}

// rollbackStaged removes every <file>.new under the keystore dir (manifest +
// wallets/ + accounts/). Used when no commit marker is present (§3.8 roll-back).
func rollbackStaged(dir string) error {
	dirs := []string{dir, filepath.Join(dir, "wallets"), filepath.Join(dir, "accounts")}
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return errWrap(CodeStateCorrupt, "cannot scan for rotation artifacts", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			// fsx.WriteAtomic's own temp is "<base>.tmp-<rand>" (random hex tail), so
			// it never ends in ".new"; only our staged files do. A clean suffix
			// match is therefore safe.
			if strings.HasSuffix(e.Name(), stagedSuffix) {
				_ = os.Remove(filepath.Join(d, e.Name()))
			}
		}
	}
	return nil
}
