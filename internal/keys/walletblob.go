package keys

import (
	"encoding/json"
	"errors"

	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"

	"github.com/daxchain-io/daxie/internal/fsx"
)

// walletBlobVersion marks the daxie wallet-blob superset format.
const walletBlobVersion = 1

// walletBlob is the encrypted-mnemonic file at wallets/<uuid>.json (§3.3). It
// reuses the geth v3 `crypto` envelope VERBATIM via EncryptDataV3/DecryptDataV3
// (which roundtrip arbitrary bytes — NOT a 32-byte curve key, deliberately not
// EncryptKey/DecryptKey). The outer object is a marked superset that geth tools
// skip: it lives OUTSIDE accounts/ and has NO `address` field, plus an explicit
// daxie_wallet marker and a "type":"mnemonic" tag.
type walletBlob struct {
	DaxieWallet int                     `json:"daxie_wallet"` // superset marker
	Type        string                  `json:"type"`         // "mnemonic"
	ID          string                  `json:"id"`           // wallet UUID
	Version     int                     `json:"version"`      // v3 envelope version (3)
	Crypto      gethkeystore.CryptoJSON `json:"crypto"`
}

// writeWalletBlob seals plaintext (the {v,mnemonic,bip39_passphrase} document)
// under pass at this store's effective scrypt params and atomically writes
// wallets/<id>.json with 0600 perms. The caller MUST hold the index.lock and MUST
// zero plaintext after this returns. id is the wallet UUID.
func (s *Store) writeWalletBlob(id string, plaintext, passBytes []byte, n, p int) error {
	cj, err := gethkeystore.EncryptDataV3(plaintext, passBytes, n, p)
	if err != nil {
		return errWrap(CodeStateCorrupt, "cannot encrypt the wallet mnemonic", err)
	}
	blob := walletBlob{
		DaxieWallet: walletBlobVersion,
		Type:        "mnemonic",
		ID:          id,
		Version:     3,
		Crypto:      cj,
	}
	b, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		return errWrap(CodeStateCorrupt, "cannot encode the wallet blob", err)
	}
	if err := fsx.WriteAtomic(s.walletBlobPath(id), b, 0o600); err != nil {
		if fsx.IsReadOnly(err) {
			return errKeys(CodeKeystoreReadOnly, "the keystore is read-only; the wallet blob cannot be written")
		}
		return errWrap(CodeStateCorrupt, "cannot write the wallet blob", err)
	}
	return nil
}

// readWalletPlaintext reads wallets/<id>.json, perm-checks it, decrypts it with
// pass, and returns the decrypted plaintext bytes (the caller owns and MUST zero
// them). A MAC failure is keystore.bad_passphrase. The plaintext is the
// {v,mnemonic,bip39_passphrase} document; decode it with decodePlaintext.
func (s *Store) readWalletPlaintext(id string, passBytes []byte) ([]byte, error) {
	path := s.walletBlobPath(id)
	if err := checkPerms(path); err != nil {
		return nil, err
	}
	// Lock-free on POSIX; shared RLock + ERROR_ACCESS_DENIED retry on Windows
	// (§3.3/§7.9) via the platform-split readKeystoreFile.
	b, err := s.readKeystoreFile(path)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "cannot read the wallet blob", err)
	}
	var blob walletBlob
	if err := json.Unmarshal(b, &blob); err != nil {
		return nil, errWrap(CodeStateCorrupt, "the wallet blob is corrupt (not valid JSON)", err)
	}
	plain, err := gethkeystore.DecryptDataV3(blob.Crypto, string(passBytes))
	if err != nil {
		if errors.Is(err, gethkeystore.ErrDecrypt) {
			return nil, errKeys(CodeKeystoreBadPassphrase, "wrong keystore passphrase")
		}
		return nil, errWrap(CodeStateCorrupt, "the wallet blob is unreadable", err)
	}
	return plain, nil
}
