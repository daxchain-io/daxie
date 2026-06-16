package keys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"

	"github.com/daxchain-io/daxie/internal/fsx"
	"github.com/daxchain-io/daxie/internal/secret"
)

const manifestFormatVersion = 1

// verifierPlaintextLen is the size of the random plaintext sealed in the verifier
// (§3.3): 32 random bytes encrypted under the keystore passphrase. A successful
// decrypt proves the passphrase without touching any wallet.
const verifierPlaintextLen = 32

// fingerprintSaltLen is the size of the non-secret salt for the passphrase
// fingerprint. The fingerprint is a salted hash echoed to orchestrators (§3.3);
// it is NOT the verifier salt or any KDF input.
const fingerprintSaltLen = 16

// manifest is the on-disk keystore.json (§3.3): format version, KDF template
// defaults, the passphrase verifier, the light flag, and the fingerprint salt.
type manifest struct {
	Format          int              `json:"daxie_keystore"`
	CreatedAt       string           `json:"created_at"`
	Light           bool             `json:"light,omitempty"`  // manifest created under DAXIE_KDF_LIGHT
	KDFDefaults     kdfDefaults      `json:"kdf_defaults"`     // template for NEW files only
	FingerprintSalt string           `json:"fingerprint_salt"` // hex; non-secret
	Verifier        verifierEnvelope `json:"verifier"`         // {crypto: v3 crypto object}
}

type kdfDefaults struct {
	KDF   string `json:"kdf"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DKLen int    `json:"dklen"`
}

// verifierEnvelope wraps a standard Web3 Secret Storage v3 crypto object (§3.3).
type verifierEnvelope struct {
	Crypto gethkeystore.CryptoJSON `json:"crypto"`
}

// loadManifest reads and parses keystore.json. A missing manifest is the
// uninitialized case (returns os.ErrNotExist wrapped as nil manifest). A perms
// failure is a keystore.perms_insecure tripwire.
func (s *Store) loadManifest() (*manifest, error) {
	path := s.manifestPath()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errKeys(CodeStateCorrupt, "cannot stat keystore.json: "+err.Error())
	}
	if err := checkPerms(path); err != nil {
		return nil, err
	}
	// Lock-free on POSIX; shared RLock + ERROR_ACCESS_DENIED retry on Windows
	// (§3.3/§7.9) — readKeystoreFile is the platform-split reader.
	b, err := s.readKeystoreFile(path)
	if err != nil {
		return nil, errKeys(CodeStateCorrupt, "cannot read keystore.json: "+err.Error())
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, errWrap(CodeStateCorrupt, "keystore.json is corrupt (not valid JSON)", err)
	}
	if m.Format > manifestFormatVersion {
		return nil, errKeysf(CodeStateCorrupt, "keystore.json format %d is newer than supported (%d)", m.Format, manifestFormatVersion)
	}
	return &m, nil
}

// saveManifest atomically writes keystore.json with 0600 perms. The caller MUST
// hold the index.lock.
func (s *Store) saveManifest(m *manifest) error {
	m.Format = manifestFormatVersion
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return errWrap(CodeStateCorrupt, "cannot encode keystore.json", err)
	}
	if err := fsx.WriteAtomic(s.manifestPath(), b, 0o600); err != nil {
		if fsx.IsReadOnly(err) {
			return errKeys(CodeKeystoreReadOnly, "the keystore is read-only; keystore.json cannot be written")
		}
		return errWrap(CodeStateCorrupt, "cannot write keystore.json", err)
	}
	return nil
}

// effectiveScrypt resolves the (N, p) this store uses, honoring the light flag
// ONLY when the manifest was created light (§3.4). If no manifest exists yet
// (first init) the store's own Light option decides — that init then records it.
func (s *Store) effectiveScrypt(m *manifest) (n, p int) {
	light := false
	if m != nil {
		// A production manifest can never be downgraded: light is honored only when
		// the manifest itself was created light.
		light = m.Light
	} else {
		light = s.light
	}
	return s.scryptParams(light)
}

// EnsureInitialized verifies pass against the verifier, OR — on first init —
// writes the verifier after confirm matches pass, then returns the non-secret
// salted fingerprint (§3.3). It is the one-passphrase-per-keystore gate every
// material-adding operation calls before encrypting. The caller MUST hold the
// index.lock (the wallet/account create paths take it and call this inside).
//
// First-init typo protection (§3.3): on the very first use there is nothing to
// check against, so a confirm MUST be supplied and MUST match pass before the
// verifier is written; a nil/mismatched confirm yields keystore.confirm_required
// (exit 4), never a silent commit to a typo'd passphrase. After the keystore
// exists the confirm argument is ignored.
func (s *Store) EnsureInitialized(ctx context.Context, pass, confirm *secret.Bytes) (string, error) {
	m, err := s.loadManifest()
	if err != nil {
		return "", err
	}
	if m != nil {
		// Already initialized: verify (confirm ignored).
		if err := verifyAgainst(m, pass); err != nil {
			return "", err
		}
		return fingerprint(m.FingerprintSalt, pass), nil
	}

	// First init: require a matching confirmation before writing the verifier.
	if confirm == nil || confirm.Len() == 0 {
		return "", errKeys(CodeKeystoreConfirmRequired,
			"first keystore use requires passphrase confirmation: supply --passphrase-confirm-stdin|file or DAXIE_PASSPHRASE_CONFIRM[_FILE] (interactive double-entry at a TTY)")
	}
	if subtle.ConstantTimeCompare(pass.Reveal(), confirm.Reveal()) != 1 {
		return "", errKeys(CodeKeystoreConfirmRequired, "the passphrase and its confirmation do not match")
	}

	if err := s.ensureDirs(); err != nil {
		return "", err
	}
	nm, err := s.initManifest(pass)
	if err != nil {
		return "", err
	}
	if err := s.saveManifest(nm); err != nil {
		return "", err
	}
	return fingerprint(nm.FingerprintSalt, pass), nil
}

// VerifyPassphrase decrypts the verifier with pass; a MAC failure is
// keystore.bad_passphrase (exit 4). An uninitialized keystore returns
// keystore.bad_passphrase too (there is nothing to verify against, so any
// material-adding op must go through EnsureInitialized first).
func (s *Store) VerifyPassphrase(ctx context.Context, pass *secret.Bytes) error {
	m, err := s.loadManifest()
	if err != nil {
		return err
	}
	if m == nil {
		return errKeys(CodeKeystoreBadPassphrase, "the keystore is not initialized")
	}
	return verifyAgainst(m, pass)
}

// initManifest builds a fresh manifest: a random fingerprint salt and a verifier
// (32 random bytes sealed under pass in a v3 envelope), at this store's effective
// scrypt params. It does NOT write — the caller persists it.
func (s *Store) initManifest(pass *secret.Bytes) (*manifest, error) {
	n, p := s.scryptParams(s.light)

	plain := make([]byte, verifierPlaintextLen)
	if _, err := rand.Read(plain); err != nil {
		return nil, errWrap(CodeStateCorrupt, "cannot read entropy for the keystore verifier", err)
	}
	defer zeroBytes(plain)

	cj, err := gethkeystore.EncryptDataV3(plain, pass.Reveal(), n, p)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "cannot seal the keystore verifier", err)
	}

	salt := make([]byte, fingerprintSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, errWrap(CodeStateCorrupt, "cannot read entropy for the passphrase fingerprint salt", err)
	}

	return &manifest{
		Format:    manifestFormatVersion,
		CreatedAt: formatTime(s.clock()),
		Light:     s.light,
		KDFDefaults: kdfDefaults{
			KDF:   kdfName,
			N:     n,
			R:     scryptR,
			P:     p,
			DKLen: scryptDKLen,
		},
		FingerprintSalt: hex.EncodeToString(salt),
		Verifier:        verifierEnvelope{Crypto: cj},
	}, nil
}

// verifyAgainst decrypts the verifier crypto object with pass; a MAC failure
// (geth ErrDecrypt) is keystore.bad_passphrase, any other decode failure is
// state.corrupt.
func verifyAgainst(m *manifest, pass *secret.Bytes) error {
	plain, err := gethkeystore.DecryptDataV3(m.Verifier.Crypto, string(pass.Reveal()))
	if err != nil {
		if errors.Is(err, gethkeystore.ErrDecrypt) {
			return errKeys(CodeKeystoreBadPassphrase, "wrong keystore passphrase")
		}
		return errWrap(CodeStateCorrupt, "the keystore verifier is unreadable", err)
	}
	zeroBytes(plain)
	return nil
}

// fingerprint is a non-secret, deterministic salted hash of the passphrase
// (§3.3): SHA-256(saltHex-decoded || pass), hex, truncated. It is echoed so an
// orchestrator can assert it matches a re-derivation from its secret source. It
// is NOT the verifier salt or any KDF input, and reveals nothing about the
// passphrase that a brute-forcer with the salt could not already attempt — but it
// is cheap and stable, which is its only purpose.
func fingerprint(saltHex string, pass *secret.Bytes) string {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		salt = []byte(saltHex)
	}
	h := sha256.New()
	h.Write(salt)
	h.Write(pass.Reveal())
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8]) // 64-bit fingerprint; collision-irrelevant (assertion aid)
}
