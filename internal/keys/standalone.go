package keys

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"github.com/daxchain-io/daxie/internal/fsx"
)

// standalone accounts are BYTE-FOR-BYTE stock geth v3 key files (§3.1 decision 2):
// EncryptKey produces the exact JSON geth/clef read, and the file name follows
// geth's UTC--<iso8601>--<lowercase-hex-addr> convention. Point geth at
// <keystore>/accounts/ and it works.

// keyFileName builds geth's standard UTC key-file name for an address at time t.
// It mirrors geth's keyFileName/toISO8601 exactly (lowercase hex address, no 0x).
func keyFileName(addr common.Address, t time.Time) string {
	return fmt.Sprintf("UTC--%s--%s", toISO8601(t.UTC()), hex.EncodeToString(addr[:]))
}

// toISO8601 mirrors geth's timestamp format used in key file names.
func toISO8601(t time.Time) string {
	name, offset := t.Zone()
	tz := "Z"
	if name != "UTC" {
		tz = fmt.Sprintf("%03d00", offset/3600)
	}
	return fmt.Sprintf("%04d-%02d-%02dT%02d-%02d-%02d.%09d%s",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), tz)
}

// writeStandaloneFile encrypts priv into a stock geth v3 JSON blob under pass and
// atomically writes it to accounts/<UTC--…--addr> with 0600 perms. It returns the
// account UUID and the relative file path stored in meta. The caller MUST hold the
// index.lock and zeroECDSA(priv) after this returns.
func (s *Store) writeStandaloneFile(priv *ecdsa.PrivateKey, passBytes []byte, n, p int) (id, relFile string, addr common.Address, err error) {
	id = uuid.New().String()
	keyUUID, perr := uuid.Parse(id)
	if perr != nil {
		return "", "", common.Address{}, errWrap(CodeStateCorrupt, "cannot parse a fresh UUID", perr)
	}
	gkey := &gethkeystore.Key{
		Id:         keyUUID,
		Address:    cryptoAddr(priv),
		PrivateKey: priv,
	}
	// EncryptKey requires a string passphrase (geth's boundary, §3.10 honest
	// residual). The transient string carries the same secret the caller already
	// holds; it falls out of scope immediately.
	blob, eerr := gethkeystore.EncryptKey(gkey, string(passBytes), n, p)
	if eerr != nil {
		return "", "", common.Address{}, errWrap(CodeStateCorrupt, "cannot encrypt the standalone key", eerr)
	}
	addr = gkey.Address
	name := keyFileName(addr, s.clock())
	relFile = filepath.Join("accounts", name)
	full := filepath.Join(s.dir, relFile)
	if werr := fsx.WriteAtomic(full, blob, 0o600); werr != nil {
		if fsx.IsReadOnly(werr) {
			return "", "", common.Address{}, errKeys(CodeKeystoreReadOnly, "the keystore is read-only; the standalone key cannot be written")
		}
		return "", "", common.Address{}, errWrap(CodeStateCorrupt, "cannot write the standalone key file", werr)
	}
	return id, relFile, addr, nil
}

// readStandaloneKey reads + decrypts a standalone key file with pass, returning a
// geth *ecdsa.PrivateKey the caller MUST zeroECDSA. A MAC failure is
// keystore.bad_passphrase. relFile is the meta-stored relative path.
func (s *Store) readStandaloneKey(relFile string, passBytes []byte) (*ecdsa.PrivateKey, error) {
	full := filepath.Join(s.dir, relFile)
	if err := checkPerms(full); err != nil {
		return nil, err
	}
	// Lock-free on POSIX; shared RLock + ERROR_ACCESS_DENIED retry on Windows
	// (§3.3/§7.9) via the platform-split readKeystoreFile.
	b, err := s.readKeystoreFile(full)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "cannot read the standalone key file", err)
	}
	key, derr := gethkeystore.DecryptKey(b, string(passBytes))
	if derr != nil {
		if errors.Is(derr, gethkeystore.ErrDecrypt) {
			return nil, errKeys(CodeKeystoreBadPassphrase, "wrong keystore passphrase")
		}
		return nil, errWrap(CodeStateCorrupt, "the standalone key file is unreadable", derr)
	}
	return key.PrivateKey, nil
}

// cryptoAddr returns the address for a geth private key.
func cryptoAddr(priv *ecdsa.PrivateKey) common.Address {
	return gethcrypto.PubkeyToAddress(priv.PublicKey)
}

// uuidOfStandaloneFile reads the v3 file's `id` field so a rotation preserves the
// account's UUID identity (no decrypt). relFile is meta-stored.
func (s *Store) uuidOfStandaloneFile(relFile string) (uuid.UUID, error) {
	full := filepath.Join(s.dir, relFile)
	// Lock-free on POSIX; shared RLock + ERROR_ACCESS_DENIED retry on Windows
	// (§3.3/§7.9) via the platform-split readKeystoreFile.
	b, err := s.readKeystoreFile(full)
	if err != nil {
		return uuid.UUID{}, errWrap(CodeStateCorrupt, "cannot read the standalone key file", err)
	}
	var hdr struct {
		Id string `json:"id"`
	}
	if jerr := json.Unmarshal(b, &hdr); jerr != nil {
		return uuid.UUID{}, errWrap(CodeStateCorrupt, "the standalone key file is corrupt", jerr)
	}
	id, perr := uuid.Parse(hdr.Id)
	if perr != nil {
		// A missing/invalid id is non-fatal: mint a fresh one for the rotated file.
		return uuid.New(), nil
	}
	return id, nil
}
