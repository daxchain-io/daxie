package keys

import (
	"context"
	"os"

	"github.com/ethereum/go-ethereum/common"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
)

// DeriveNext allocates the wallet's next_index, derives that address (one unlock),
// materializes it in meta.json, and returns the index + address (§3.5). next_index
// is monotonic and never reused after a forget (account delete). The allocator is
// the same one receive --new uses, inheriting the read-only-keystore rule.
func (s *Store) DeriveNext(ctx context.Context, wallet string, pass *secret.Bytes) (uint32, common.Address, error) {
	unlock, err := s.lockForWrite(ctx)
	if err != nil {
		return 0, common.Address{}, err
	}
	defer unlock()

	if err := s.VerifyPassphrase(ctx, pass); err != nil {
		return 0, common.Address{}, err
	}
	m, err := s.loadMeta()
	if err != nil {
		return 0, common.Address{}, err
	}
	id, w := m.findWalletByName(wallet)
	if w == nil {
		return 0, common.Address{}, errKeysf(CodeRefNotFound, "no wallet named %q", wallet)
	}
	index := w.NextIndex
	addr, derr := s.deriveAndCache(id, w, index, pass)
	if derr != nil {
		return 0, common.Address{}, derr
	}
	w.NextIndex = index + 1
	if serr := s.saveMeta(m); serr != nil {
		return 0, common.Address{}, serr
	}
	return index, addr, nil
}

// DeriveIndex derives + materializes a specific index. If already materialized it
// is idempotent (returns the cached address without re-deriving). next_index is
// advanced past index if needed so the watermark invariant holds. Out-of-range
// (hardened) index is usage.bad_index.
func (s *Store) DeriveIndex(ctx context.Context, wallet string, index uint32, pass *secret.Bytes) (common.Address, error) {
	if index >= hardened {
		return common.Address{}, errKeysf(CodeUsageBadIndex, "index %d is out of range (non-hardened indexes only: 0..%d)", index, hardened-1)
	}
	unlock, err := s.lockForWrite(ctx)
	if err != nil {
		return common.Address{}, err
	}
	defer unlock()

	if err := s.VerifyPassphrase(ctx, pass); err != nil {
		return common.Address{}, err
	}
	m, err := s.loadMeta()
	if err != nil {
		return common.Address{}, err
	}
	id, w := m.findWalletByName(wallet)
	if w == nil {
		return common.Address{}, errKeysf(CodeRefNotFound, "no wallet named %q", wallet)
	}
	if existing, ok := w.Accounts[indexKey(index)]; ok {
		return common.HexToAddress(existing.Address), nil
	}
	addr, derr := s.deriveAndCache(id, w, index, pass)
	if derr != nil {
		return common.Address{}, derr
	}
	if index >= w.NextIndex {
		w.NextIndex = index + 1
	}
	if serr := s.saveMeta(m); serr != nil {
		return common.Address{}, serr
	}
	return addr, nil
}

// deriveAndCache unlocks the wallet blob, derives the address at index, zeroes the
// seed, and writes the materialized entry into w (in-memory; caller saves meta).
func (s *Store) deriveAndCache(id string, w *metaWallet, index uint32, pass *secret.Bytes) (common.Address, error) {
	plain, err := s.readWalletPlaintext(id, pass.Reveal())
	if err != nil {
		return common.Address{}, err
	}
	defer zeroBytes(plain)
	mn, b39, derr := decodePlaintext(plain)
	if derr != nil {
		return common.Address{}, errWrap(CodeStateCorrupt, "the wallet blob plaintext is malformed", derr)
	}
	defer zeroBytes(mn)
	defer zeroBytes(b39)

	seed := seedFromMnemonic(mn, b39)
	addr, aerr := deriveAddress(seed, index)
	zeroBytes(seed)
	if aerr != nil {
		return common.Address{}, aerr
	}
	if w.Accounts == nil {
		w.Accounts = map[string]*metaHDAccount{}
	}
	w.Accounts[indexKey(index)] = &metaHDAccount{
		Address:   addr.Hex(),
		CreatedAt: formatTime(s.clock()),
	}
	return addr, nil
}

// Alias names a materialized HD index (§3.5). The alias must be valid (non-numeric,
// §3.1) and unique within the wallet. Aliasing an unmaterialized index is
// ref.not_found (derive it first).
func (s *Store) Alias(ctx context.Context, wallet string, index uint32, alias string) error {
	if !validAlias(alias) {
		return errKeysf(CodeUsageInvalidName, "%q is not a valid alias (use [a-z0-9][a-z0-9_-]{0,63}, not purely numeric)", alias)
	}
	unlock, err := s.lockForWrite(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	m, err := s.loadMeta()
	if err != nil {
		return err
	}
	_, w := m.findWalletByName(wallet)
	if w == nil {
		return errKeysf(CodeRefNotFound, "no wallet named %q", wallet)
	}
	acct, ok := w.Accounts[indexKey(index)]
	if !ok {
		return errKeysf(CodeRefNotFound, "%s/%d is not materialized; derive it before aliasing", wallet, index)
	}
	// Unique within the wallet (and not colliding with an existing index).
	if aliasInUse(w, alias, index) {
		return errKeysf(CodeUsageNameCollision, "the alias %q is already in use in wallet %q", alias, wallet)
	}
	acct.Alias = alias
	return s.saveMeta(m)
}

// Unalias removes the alias from an index, returning the removed alias. Absent
// alias is ref.not_found.
func (s *Store) Unalias(ctx context.Context, wallet string, index uint32) (string, error) {
	unlock, err := s.lockForWrite(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()

	m, err := s.loadMeta()
	if err != nil {
		return "", err
	}
	_, w := m.findWalletByName(wallet)
	if w == nil {
		return "", errKeysf(CodeRefNotFound, "no wallet named %q", wallet)
	}
	acct, ok := w.Accounts[indexKey(index)]
	if !ok || acct.Alias == "" {
		return "", errKeysf(CodeRefNotFound, "%s/%d has no alias", wallet, index)
	}
	removed := acct.Alias
	acct.Alias = ""
	if err := s.saveMeta(m); err != nil {
		return "", err
	}
	return removed, nil
}

// ImportStandalone imports a raw private key as a stock geth v3 file (§3.5):
// validate the key in [1, n-1], reject a duplicate address, encrypt, register in
// meta. name shares the one namespace. rawKey is the secret input (caller zeroes);
// pass is the keystore passphrase.
func (s *Store) ImportStandalone(ctx context.Context, name string, rawKey, pass *secret.Bytes) (string, common.Address, error) {
	if !validName(name) {
		return "", common.Address{}, errKeysf(CodeUsageInvalidName, "%q is not a valid account name", name)
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

	priv, perr := privateKeyFromRaw(rawKey.Reveal())
	if perr != nil {
		return "", common.Address{}, perr
	}
	addr := cryptoAddr(priv)
	// Reject an address already present (HD or standalone).
	if existing := m.findByAddress(addr); existing != "" {
		zeroECDSA(priv)
		return "", common.Address{}, errKeysf(CodeUsageNameCollision, "an account with address %s already exists (%s)", addr.Hex(), existing)
	}

	man, err := s.loadManifest()
	if err != nil {
		zeroECDSA(priv)
		return "", common.Address{}, err
	}
	n, p := s.effectiveScrypt(man)

	id, relFile, _, werr := s.writeStandaloneFile(priv, pass.Reveal(), n, p)
	zeroECDSA(priv)
	if werr != nil {
		return "", common.Address{}, werr
	}

	now := formatTime(s.clock())
	m.Accounts[id] = &metaStandalone{
		Name:      name,
		Address:   addr.Hex(),
		File:      relFile,
		CreatedAt: now,
	}
	if serr := s.saveMeta(m); serr != nil {
		_ = os.Remove(s.dir + "/" + relFile)
		return "", common.Address{}, serr
	}
	return id, addr, nil
}

// ListAccounts returns all accounts (HD materialized + standalone), optionally
// filtered to one wallet. No unlock. Sorted: HD by wallet then index, then
// standalone by name.
func (s *Store) ListAccounts(ctx context.Context, walletFilter string) ([]AccountInfo, error) {
	m, err := s.loadMeta()
	if err != nil {
		return nil, err
	}
	def := m.DefaultAccount
	var out []AccountInfo

	// HD accounts.
	wallets := make([]*metaWallet, 0, len(m.Wallets))
	for _, w := range m.Wallets {
		if walletFilter != "" && !equalFold(w.Name, walletFilter) {
			continue
		}
		wallets = append(wallets, w)
	}
	sortMetaWalletsByName(wallets)
	for _, w := range wallets {
		for _, idx := range sortedIndexes(w) {
			a := w.Accounts[indexKey(idx)]
			ref := w.Name + "/" + indexKey(idx)
			out = append(out, AccountInfo{
				Ref:       ref,
				Address:   common.HexToAddress(a.Address),
				Kind:      "hd",
				Wallet:    w.Name,
				Index:     idx,
				HasIndex:  true,
				Alias:     a.Alias,
				Path:      pathString(idx),
				Default:   def == ref || (a.Alias != "" && def == w.Name+"/"+a.Alias),
				CreatedAt: parseTime(a.CreatedAt),
			})
		}
	}

	// Standalone accounts (skipped when a wallet filter is set).
	if walletFilter == "" {
		stands := make([]*metaStandalone, 0, len(m.Accounts))
		for _, a := range m.Accounts {
			stands = append(stands, a)
		}
		sortStandalonesByName(stands)
		for _, a := range stands {
			out = append(out, AccountInfo{
				Ref:       a.Name,
				Address:   common.HexToAddress(a.Address),
				Kind:      "standalone",
				Default:   def == a.Name,
				CreatedAt: parseTime(a.CreatedAt),
			})
		}
	}
	return out, nil
}

// ShowAccount resolves a ref to its full AccountInfo (§3.2). Read-only;
// destination context (no unlock). RefAddress/RefENS are not local objects here.
func (s *Store) ShowAccount(ctx context.Context, ref domain.AccountRef) (AccountInfo, error) {
	m, err := s.loadMeta()
	if err != nil {
		return AccountInfo{}, err
	}
	info, _, rerr := m.resolveInfo(ref)
	if rerr != nil {
		return AccountInfo{}, rerr
	}
	info.Default = m.refIsDefault(info)
	return info, nil
}

// DeleteAccount forgets an HD index (mode "forget" — the mnemonic still holds it,
// no key file) or removes a standalone key file (mode "remove"). next_index is
// NEVER decremented (the index is not reused, §3.5). Unknown ref is ref.not_found.
func (s *Store) DeleteAccount(ctx context.Context, ref domain.AccountRef) (string, error) {
	unlock, err := s.lockForWrite(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()

	m, err := s.loadMeta()
	if err != nil {
		return "", err
	}
	switch ref.Kind {
	case domain.RefHDIndex, domain.RefHDAlias:
		id, w := m.findWalletByName(ref.Wallet)
		if w == nil {
			return "", errKeysf(CodeRefNotFound, "no wallet named %q", ref.Wallet)
		}
		_ = id
		idx, ok := w.indexForRef(ref)
		if !ok {
			return "", errKeysf(CodeRefNotFound, "no such account %q", ref.Raw)
		}
		acct := w.Accounts[indexKey(idx)]
		// Clear default if it pointed here.
		if m.refIsDefault(AccountInfo{Ref: w.Name + "/" + indexKey(idx), Wallet: w.Name, Index: idx, HasIndex: true, Alias: acct.Alias, Kind: "hd"}) {
			m.DefaultAccount = ""
		}
		delete(w.Accounts, indexKey(idx)) // forget: next_index untouched
		if serr := s.saveMeta(m); serr != nil {
			return "", serr
		}
		return "forget", nil
	case domain.RefNamed:
		id, a := m.findStandaloneByName(ref.Name)
		if a == nil {
			return "", errKeysf(CodeRefNotFound, "no account named %q", ref.Name)
		}
		if m.DefaultAccount == a.Name {
			m.DefaultAccount = ""
		}
		relFile := a.File
		delete(m.Accounts, id)
		if serr := s.saveMeta(m); serr != nil {
			return "", serr
		}
		_ = os.Remove(s.dir + "/" + relFile)
		return "remove", nil
	default:
		return "", errKeysf(CodeUsageReadOnlyContext, "%q is not a deletable keystore account", ref.Raw)
	}
}

// ExportStandalone returns the raw private key (hex) for a standalone account,
// freshly authed (§3.9). HD accounts are not exportable this way (export the
// wallet mnemonic, or this returns ref.not_found for a non-standalone ref). The
// returned *secret.Bytes (0x-hex) is the caller's to zero; output is stdout-only.
func (s *Store) ExportStandalone(ctx context.Context, ref domain.AccountRef, pass *secret.Bytes) (*secret.Bytes, error) {
	if ref.Kind != domain.RefNamed {
		return nil, errKeysf(CodeRefNotFound, "%q is not a standalone account; only standalone accounts export a private key (export the wallet mnemonic for an HD account)", ref.Raw)
	}
	if err := s.VerifyPassphrase(ctx, pass); err != nil {
		return nil, err
	}
	m, err := s.loadMeta()
	if err != nil {
		return nil, err
	}
	_, a := m.findStandaloneByName(ref.Name)
	if a == nil {
		return nil, errKeysf(CodeRefNotFound, "no account named %q", ref.Name)
	}
	priv, perr := s.readStandaloneKey(a.File, pass.Reveal())
	if perr != nil {
		return nil, perr
	}
	// Serialize to 0x-hex into a secret buffer, then zero the key.
	hexKey := privateKeyHex(priv)
	zeroECDSA(priv)
	return secret.New(hexKey), nil
}

// SetDefault sets the default account (account use, §3.3). The ref must resolve to
// a signable keystore account (HD index/alias or standalone) — a bare wallet or an
// address ref is rejected. Writes meta.json.
func (s *Store) SetDefault(ctx context.Context, ref domain.AccountRef) error {
	unlock, err := s.lockForWrite(ctx)
	if err != nil {
		return err
	}
	defer unlock()

	m, err := s.loadMeta()
	if err != nil {
		return err
	}
	canonical, rerr := m.canonicalSigningRef(ref)
	if rerr != nil {
		return rerr
	}
	m.DefaultAccount = canonical
	return s.saveMeta(m)
}

// DefaultAccount returns the configured default account ref and whether one is set.
func (s *Store) DefaultAccount(ctx context.Context) (string, bool) {
	m, err := s.loadMeta()
	if err != nil || m.DefaultAccount == "" {
		return "", false
	}
	return m.DefaultAccount, true
}

// ── meta resolution helpers ────────────────────────────────────────────────────

// findByAddress returns a human ref for an account holding addr, or "" if none.
func (m *metaFile) findByAddress(addr common.Address) string {
	target := addr.Hex()
	for _, w := range m.Wallets {
		for k, a := range w.Accounts {
			if equalFold(a.Address, target) {
				return w.Name + "/" + k
			}
		}
	}
	for _, a := range m.Accounts {
		if equalFold(a.Address, target) {
			return a.Name
		}
	}
	return ""
}

// indexForRef resolves an HD ref (index or alias) to a materialized index in this
// wallet.
func (w *metaWallet) indexForRef(ref domain.AccountRef) (uint32, bool) {
	switch ref.Kind {
	case domain.RefHDIndex:
		if _, ok := w.Accounts[indexKey(ref.Index)]; ok {
			return ref.Index, true
		}
		return 0, false
	case domain.RefHDAlias:
		for k, a := range w.Accounts {
			if a.Alias != "" && a.Alias == ref.Name {
				if idx, ok := parseDecimalIndex(k); ok {
					return idx, true
				}
			}
		}
		return 0, false
	default:
		return 0, false
	}
}

// resolveInfo turns a parsed ref into an AccountInfo (read-only). Returns the
// canonical ref string too.
func (m *metaFile) resolveInfo(ref domain.AccountRef) (AccountInfo, string, error) {
	switch ref.Kind {
	case domain.RefHDIndex, domain.RefHDAlias:
		_, w := m.findWalletByName(ref.Wallet)
		if w == nil {
			return AccountInfo{}, "", errKeysf(CodeRefNotFound, "no wallet named %q", ref.Wallet)
		}
		idx, ok := w.indexForRef(ref)
		if !ok {
			return AccountInfo{}, "", errKeysf(CodeRefNotFound, "no such account %q (derive the index or check the alias)", ref.Raw)
		}
		a := w.Accounts[indexKey(idx)]
		canonical := w.Name + "/" + indexKey(idx)
		return AccountInfo{
			Ref:       canonical,
			Address:   common.HexToAddress(a.Address),
			Kind:      "hd",
			Wallet:    w.Name,
			Index:     idx,
			HasIndex:  true,
			Alias:     a.Alias,
			Path:      pathString(idx),
			CreatedAt: parseTime(a.CreatedAt),
		}, canonical, nil
	case domain.RefNamed:
		_, a := m.findStandaloneByName(ref.Name)
		if a == nil {
			return AccountInfo{}, "", errKeysf(CodeRefNotFound, "no account named %q", ref.Name)
		}
		return AccountInfo{
			Ref:       a.Name,
			Address:   common.HexToAddress(a.Address),
			Kind:      "standalone",
			CreatedAt: parseTime(a.CreatedAt),
		}, a.Name, nil
	case domain.RefAddress, domain.RefENS:
		return AccountInfo{}, "", errKeysf(CodeUsageReadOnlyContext, "%q is an address/ENS reference, not a local keystore account", ref.Raw)
	default:
		return AccountInfo{}, "", errKeysf(CodeRefNotFound, "%q does not resolve to a keystore account", ref.Raw)
	}
}

// canonicalSigningRef validates a ref names a SIGNABLE account and returns its
// canonical "wallet/index" or "name" form (for storing as the default). A bare
// wallet, address, or ENS ref is rejected (a wallet is not a signing identity).
func (m *metaFile) canonicalSigningRef(ref domain.AccountRef) (string, error) {
	switch ref.Kind {
	case domain.RefHDIndex, domain.RefHDAlias, domain.RefNamed:
		_, canonical, err := m.resolveInfo(ref)
		return canonical, err
	case domain.RefAddress:
		return "", errKeysf(CodeUsageReadOnlyContext, "a raw address cannot be the default account; use a keystore ref like treasury/0")
	case domain.RefENS:
		return "", errKeysf(CodeUsageReadOnlyContext, "an ENS name cannot be the default account; use a keystore ref like treasury/0")
	default:
		return "", errKeysf(CodeRefNotFound, "%q does not resolve to a keystore account", ref.Raw)
	}
}

// refIsDefault reports whether an AccountInfo is the current default, matching on
// the canonical index ref OR the alias ref form.
func (m *metaFile) refIsDefault(info AccountInfo) bool {
	if m.DefaultAccount == "" {
		return false
	}
	if m.DefaultAccount == info.Ref {
		return true
	}
	if info.Kind == "hd" && info.Alias != "" && m.DefaultAccount == info.Wallet+"/"+info.Alias {
		return true
	}
	return false
}

// aliasInUse reports whether alias is already used by a DIFFERENT index in the
// wallet, or collides with an index literal.
func aliasInUse(w *metaWallet, alias string, selfIndex uint32) bool {
	for k, a := range w.Accounts {
		idx, _ := parseDecimalIndex(k)
		if idx == selfIndex {
			continue
		}
		if a.Alias == alias {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func sortMetaWalletsByName(ws []*metaWallet) {
	for i := 1; i < len(ws); i++ {
		for j := i; j > 0 && ws[j-1].Name > ws[j].Name; j-- {
			ws[j-1], ws[j] = ws[j], ws[j-1]
		}
	}
}

func sortStandalonesByName(as []*metaStandalone) {
	for i := 1; i < len(as); i++ {
		for j := i; j > 0 && as[j-1].Name > as[j].Name; j-- {
			as[j-1], as[j] = as[j], as[j-1]
		}
	}
}
