package keys

import (
	"context"
	"os"

	"github.com/google/uuid"

	"github.com/ethereum/go-ethereum/common"

	"github.com/daxchain-io/daxie/internal/secret"
)

// CreateResult is the output of CreateWallet. Mnemonic/BIP39Pass are *secret.Bytes
// the CALLER must zero (defer .Zero()); they are shown ONCE (§3.5 display-once) and
// never persisted in plaintext anywhere else.
type CreateResult struct {
	WalletID   string
	PathPrefix string
	Index0Addr common.Address
	Mnemonic   *secret.Bytes // freshly generated; caller zeroes
	BIP39Pass  *secret.Bytes // empty for a created wallet (no 25th word on create)
}

// CreateWallet generates a fresh BIP-39 wallet (§3.5): verify/initialize the
// passphrase against the verifier, generate the mnemonic, encrypt the blob, write
// meta.json with index 0 auto-derived, and return the mnemonic for one-time
// display. words is 12 or 24. pass is the keystore passphrase.
//
// First-init confirmation is handled by EnsureInitialized via the confirm
// argument threaded by the service; CreateWallet itself takes only pass and relies
// on the verifier being established (the service calls EnsureInitialized first on
// the first create — see the service contract). To keep keys self-contained, this
// method calls VerifyPassphrase, which fails closed if the keystore is not yet
// initialized; the service's first-create path calls EnsureInitialized beforehand.
//
// NOTE on the seam: because first-init needs a confirm and that is acquired by the
// frontend, the service is responsible for calling EnsureInitialized(pass, confirm)
// before the first CreateWallet. CreateWallet here re-verifies (cheap relative to
// the create) so a direct keys caller (tests) gets the same one-passphrase guard.
func (s *Store) CreateWallet(ctx context.Context, name string, words int, pass *secret.Bytes) (CreateResult, error) {
	if !validName(name) {
		return CreateResult{}, errKeysf(CodeUsageInvalidName, "%q is not a valid wallet name (use [a-z0-9][a-z0-9_-]{0,63}; '/', '#', '.' and address-shaped names are reserved)", name)
	}
	if _, ok := wordsToEntropyBits(words); !ok {
		return CreateResult{}, errKeysf(CodeUsageWords, "unsupported word count %d (use 12 or 24)", words)
	}

	unlock, err := s.lockForWrite(ctx)
	if err != nil {
		return CreateResult{}, err
	}
	defer unlock()

	if err := s.VerifyPassphrase(ctx, pass); err != nil {
		return CreateResult{}, err
	}

	m, err := s.loadMeta()
	if err != nil {
		return CreateResult{}, err
	}
	if m.nameExists(name, "") {
		return CreateResult{}, errKeysf(CodeUsageNameCollision, "the name %q is already in use by another wallet or account (names share one namespace)", name)
	}

	man, err := s.loadManifest()
	if err != nil {
		return CreateResult{}, err
	}
	n, p := s.effectiveScrypt(man)

	// Generate mnemonic (NFKD bytes we own).
	mnemonic, err := generateMnemonic(words)
	if err != nil {
		return CreateResult{}, err
	}
	// Derive index 0 address (string-free seed + BIP-44).
	emptyPass := []byte{}
	seed := seedFromMnemonic(mnemonic, emptyPass)
	addr0, derr := deriveAddress(seed, 0)
	zeroBytes(seed)
	if derr != nil {
		zeroBytes(mnemonic)
		return CreateResult{}, derr
	}

	// Seal the blob.
	plaintext := encodePlaintext(mnemonic, emptyPass)
	walletID := uuid.New().String()
	if werr := s.writeWalletBlob(walletID, plaintext, pass.Reveal(), n, p); werr != nil {
		zeroBytes(plaintext)
		zeroBytes(mnemonic)
		return CreateResult{}, werr
	}
	zeroBytes(plaintext)

	// Update meta: register wallet, materialize index 0, next_index = 1.
	now := formatTime(s.clock())
	m.Wallets[walletID] = &metaWallet{
		Name:       name,
		CreatedAt:  now,
		PathPrefix: defaultPathPrefix,
		NextIndex:  1,
		Accounts: map[string]*metaHDAccount{
			"0": {Address: addr0.Hex(), CreatedAt: now},
		},
	}
	if serr := s.saveMeta(m); serr != nil {
		// Roll back the orphaned blob (best-effort) so a failed meta write does not
		// leave a secret file with no metadata.
		_ = os.Remove(s.walletBlobPath(walletID))
		zeroBytes(mnemonic)
		return CreateResult{}, serr
	}

	return CreateResult{
		WalletID:   walletID,
		PathPrefix: defaultPathPrefix,
		Index0Addr: addr0,
		Mnemonic:   secret.New(mnemonic), // takes ownership; caller zeroes
		BIP39Pass:  secret.New([]byte{}),
	}, nil
}

// ImportWallet imports an existing BIP-39 mnemonic (§3.5): NFKD-normalize,
// checksum-validate hard, encrypt with an optional bip39 passphrase, and register
// with index 0 auto-derived. mnemonic / bip39pass are the secret inputs (caller
// zeroes them); pass is the keystore passphrase.
func (s *Store) ImportWallet(ctx context.Context, name string, mnemonic, bip39pass, pass *secret.Bytes) (string, common.Address, error) {
	if !validName(name) {
		return "", common.Address{}, errKeysf(CodeUsageInvalidName, "%q is not a valid wallet name", name)
	}

	unlock, err := s.lockForWrite(ctx)
	if err != nil {
		return "", common.Address{}, err
	}
	defer unlock()

	if err := s.VerifyPassphrase(ctx, pass); err != nil {
		return "", common.Address{}, err
	}

	m, err := s.loadMeta()
	if err != nil {
		return "", common.Address{}, err
	}
	if m.nameExists(name, "") {
		return "", common.Address{}, errKeysf(CodeUsageNameCollision, "the name %q is already in use by another wallet or account", name)
	}

	man, err := s.loadManifest()
	if err != nil {
		return "", common.Address{}, err
	}
	n, p := s.effectiveScrypt(man)

	normMn, err := validateMnemonic(mnemonic.Reveal())
	if err != nil {
		return "", common.Address{}, err
	}
	defer zeroBytes(normMn)

	var b39 []byte
	if bip39pass != nil {
		b39 = bip39pass.Reveal()
	}

	seed := seedFromMnemonic(normMn, b39)
	addr0, derr := deriveAddress(seed, 0)
	zeroBytes(seed)
	if derr != nil {
		return "", common.Address{}, derr
	}

	plaintext := encodePlaintext(normMn, b39)
	walletID := uuid.New().String()
	if werr := s.writeWalletBlob(walletID, plaintext, pass.Reveal(), n, p); werr != nil {
		zeroBytes(plaintext)
		return "", common.Address{}, werr
	}
	zeroBytes(plaintext)

	now := formatTime(s.clock())
	m.Wallets[walletID] = &metaWallet{
		Name:       name,
		CreatedAt:  now,
		PathPrefix: defaultPathPrefix,
		NextIndex:  1,
		Accounts: map[string]*metaHDAccount{
			"0": {Address: addr0.Hex(), CreatedAt: now},
		},
	}
	if serr := s.saveMeta(m); serr != nil {
		_ = os.Remove(s.walletBlobPath(walletID))
		return "", common.Address{}, serr
	}
	return walletID, addr0, nil
}

// ListWallets returns every wallet, sorted by name, with materialized account
// metadata. No unlock required.
func (s *Store) ListWallets(ctx context.Context) ([]Wallet, error) {
	m, err := s.loadMeta()
	if err != nil {
		return nil, err
	}
	out := make([]Wallet, 0, len(m.Wallets))
	for id, w := range m.Wallets {
		out = append(out, walletFromMeta(id, w))
	}
	sortWalletsByName(out)
	return out, nil
}

// ShowWallet returns one wallet by name (case-insensitive). Unknown name is
// ref.not_found.
func (s *Store) ShowWallet(ctx context.Context, name string) (Wallet, error) {
	m, err := s.loadMeta()
	if err != nil {
		return Wallet{}, err
	}
	id, w := m.findWalletByName(name)
	if w == nil {
		return Wallet{}, errKeysf(CodeRefNotFound, "no wallet named %q", name)
	}
	return walletFromMeta(id, w), nil
}

// RenameWallet renames a wallet (metadata only — the UUID and blob are
// untouched). The new name must be free in the one namespace. Unknown old name is
// ref.not_found; a taken new name is usage.name_collision.
func (s *Store) RenameWallet(ctx context.Context, oldName, newName string) (string, error) {
	if !validName(newName) {
		return "", errKeysf(CodeUsageInvalidName, "%q is not a valid wallet name", newName)
	}
	unlock, err := s.lockForWrite(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()

	m, err := s.loadMeta()
	if err != nil {
		return "", err
	}
	id, w := m.findWalletByName(oldName)
	if w == nil {
		return "", errKeysf(CodeRefNotFound, "no wallet named %q", oldName)
	}
	if m.nameExists(newName, id) {
		return "", errKeysf(CodeUsageNameCollision, "the name %q is already in use by another wallet or account", newName)
	}
	w.Name = newName
	if err := s.saveMeta(m); err != nil {
		return "", err
	}
	return id, nil
}

// DeleteWallet removes a wallet's blob and meta entry. If the deleted wallet held
// the default account, the default is cleared. Unknown name is ref.not_found.
func (s *Store) DeleteWallet(ctx context.Context, name string) (string, error) {
	unlock, err := s.lockForWrite(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()

	m, err := s.loadMeta()
	if err != nil {
		return "", err
	}
	id, w := m.findWalletByName(name)
	if w == nil {
		return "", errKeysf(CodeRefNotFound, "no wallet named %q", name)
	}
	// Clear the default if it pointed into this wallet.
	if defaultPointsToWallet(m.DefaultAccount, w.Name) {
		m.DefaultAccount = ""
	}
	delete(m.Wallets, id)
	if err := s.saveMeta(m); err != nil {
		return "", err
	}
	// Remove the secret blob after the meta commit (so a crash mid-delete leaves a
	// readable-but-orphaned blob the next Open could GC, never a referenced-missing
	// blob).
	_ = os.Remove(s.walletBlobPath(id))
	return id, nil
}

// ExportWallet returns the mnemonic + bip39 passphrase for a wallet, freshly
// authed (§3.9): pass is verified against the verifier and used to decrypt the
// blob. Returns *secret.Bytes the caller MUST zero. Output is stdout-only at the
// frontend; this method never writes to a file.
func (s *Store) ExportWallet(ctx context.Context, name string, pass *secret.Bytes) (*secret.Bytes, *secret.Bytes, error) {
	// Fresh auth: verify even though decrypt would also catch a wrong passphrase,
	// so the canonical bad_passphrase code is produced before any blob read.
	if err := s.VerifyPassphrase(ctx, pass); err != nil {
		return nil, nil, err
	}
	m, err := s.loadMeta()
	if err != nil {
		return nil, nil, err
	}
	id, w := m.findWalletByName(name)
	if w == nil {
		return nil, nil, errKeysf(CodeRefNotFound, "no wallet named %q", name)
	}
	plain, err := s.readWalletPlaintext(id, pass.Reveal())
	if err != nil {
		return nil, nil, err
	}
	defer zeroBytes(plain)
	mn, b39, derr := decodePlaintext(plain)
	if derr != nil {
		return nil, nil, errWrap(CodeStateCorrupt, "the wallet blob plaintext is malformed", derr)
	}
	return secret.New(mn), secret.New(b39), nil
}

// ── helpers ────────────────────────────────────────────────────────────────────

// lockForWrite ensures the keystore dir exists (so the .lock can be created) and
// takes the exclusive lock. Used by every mutating wallet/account operation.
func (s *Store) lockForWrite(ctx context.Context) (func(), error) {
	if err := s.ensureDirs(); err != nil {
		return nil, err
	}
	return s.lock(ctx)
}

func walletFromMeta(id string, w *metaWallet) Wallet {
	accts := make(map[uint32]HDAccount, len(w.Accounts))
	for k, a := range w.Accounts {
		idx, ok := parseDecimalIndex(k)
		if !ok {
			continue
		}
		accts[idx] = HDAccount{
			Index:     idx,
			Address:   common.HexToAddress(a.Address),
			Alias:     a.Alias,
			CreatedAt: parseTime(a.CreatedAt),
		}
	}
	pp := w.PathPrefix
	if pp == "" {
		pp = defaultPathPrefix
	}
	return Wallet{
		ID:         id,
		Name:       w.Name,
		CreatedAt:  parseTime(w.CreatedAt),
		PathPrefix: pp,
		NextIndex:  w.NextIndex,
		Accounts:   accts,
	}
}

func sortWalletsByName(ws []Wallet) {
	for i := 1; i < len(ws); i++ {
		for j := i; j > 0 && ws[j-1].Name > ws[j].Name; j-- {
			ws[j-1], ws[j] = ws[j], ws[j-1]
		}
	}
}

// defaultPointsToWallet reports whether a default_account ref ("treasury/0" or
// "treasury/payroll") names the given wallet.
func defaultPointsToWallet(def, walletName string) bool {
	if def == "" {
		return false
	}
	for i := 0; i < len(def); i++ {
		if def[i] == '/' {
			return def[:i] == walletName
		}
	}
	return false
}
