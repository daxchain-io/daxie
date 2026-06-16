package keys

import (
	"github.com/ethereum/go-ethereum/common"

	"github.com/daxchain-io/daxie/internal/domain"
)

// Context distinguishes signing/source positions from destination/read-only ones
// (§3.2). It is exported so a caller that wants the rule named explicitly can pass
// it; the package itself enforces the split through LookupSigning vs AddressOf,
// which is the load-bearing form (the design uses two methods, not a flag).
type Context int

const (
	// ContextSigning is a --from/--account/export position: must resolve to a
	// signable keystore account; RefAddress/RefENS and bare wallets are rejected.
	ContextSigning Context = iota
	// ContextDestination is a --to/balance/read-only position: an address/ENS is
	// fine; resolution is the chain/ens layer's job, not keys.
	ContextDestination
)

// LookupSigning turns a parsed ref into a domain.Signable bound to its keystore
// object (§3.2). It accepts wallet/index, wallet/alias, and standalone names; it
// REJECTS RefAddress and RefENS (read-only/destination only) and a bare wallet
// name (a wallet has many addresses — not a signing identity), with a helpful
// hint. Unknown wallet/index/alias/name each give a distinct ref.not_found.
//
// The returned Signable does NOT hold any secret: it captures the store + the
// object's locator (wallet id + index, or standalone file) and re-reads/decrypts
// at sign time using the passphrase the domain.Unlocker provides, then zeroes.
func (s *Store) LookupSigning(ref domain.AccountRef) (domain.Signable, error) {
	switch ref.Kind {
	case domain.RefAddress:
		return nil, errKeysf(CodeUsageReadOnlyContext,
			"%s is a raw address; raw addresses are read-only and cannot sign — use a keystore ref like treasury/0", ref.Raw)
	case domain.RefENS:
		return nil, errKeysf(CodeUsageReadOnlyContext,
			"%s is an ENS name; ENS names are destinations, not signing identities", ref.Raw)
	}

	m, err := s.loadMeta()
	if err != nil {
		return nil, err
	}

	switch ref.Kind {
	case domain.RefHDIndex, domain.RefHDAlias:
		id, w := m.findWalletByName(ref.Wallet)
		if w == nil {
			return nil, errKeysf(CodeRefNotFound, "no wallet named %q", ref.Wallet)
		}
		idx, ok := w.indexForRef(ref)
		if !ok {
			if ref.Kind == domain.RefHDAlias {
				return nil, errKeysf(CodeRefNotFound, "wallet %q has no account aliased %q", ref.Wallet, ref.Name)
			}
			return nil, errKeysf(CodeRefNotFound, "wallet %q has no materialized account at index %d (derive it first)", ref.Wallet, ref.Index)
		}
		acct := w.Accounts[indexKey(idx)]
		return &hdSignable{
			store:    s,
			walletID: id,
			index:    idx,
			addr:     common.HexToAddress(acct.Address),
		}, nil

	case domain.RefNamed:
		// A bare name: in a SIGNING context it is exactly the keystore namespace. If
		// it is a wallet name, reject with a hint (a wallet is not a signing
		// identity). If it is a standalone account, resolve it.
		if _, w := m.findWalletByName(ref.Name); w != nil {
			hint := ref.Name + "/0"
			return nil, errKeysf(CodeRefNotFound,
				"%q is a wallet, not a signing account; a wallet has many addresses — did you mean %s?", ref.Name, hint)
		}
		_, a := m.findStandaloneByName(ref.Name)
		if a == nil {
			return nil, errKeysf(CodeRefNotFound, "no account named %q", ref.Name)
		}
		return &standaloneSignable{
			store: s,
			file:  a.File,
			addr:  common.HexToAddress(a.Address),
		}, nil

	default:
		return nil, errKeysf(CodeRefNotFound, "%q does not resolve to a signing account", ref.Raw)
	}
}

// AddressOf resolves a ref to an address WITHOUT unlocking (§3.2) — the read-only /
// destination path. RefAddress returns its literal; HD/standalone return the
// cached plaintext address from meta; RefENS is not keys' job (the caller routes
// ENS to the ens layer). A bare wallet name resolves to nothing here (a wallet has
// no single address) — it is ref.not_found.
func (s *Store) AddressOf(ref domain.AccountRef) (common.Address, error) {
	switch ref.Kind {
	case domain.RefAddress:
		return ref.Addr, nil
	case domain.RefENS:
		return common.Address{}, errKeysf(CodeUsageReadOnlyContext,
			"%s is an ENS name; resolve it through the ens layer, not the keystore", ref.Raw)
	}
	m, err := s.loadMeta()
	if err != nil {
		return common.Address{}, err
	}
	switch ref.Kind {
	case domain.RefHDIndex, domain.RefHDAlias:
		_, w := m.findWalletByName(ref.Wallet)
		if w == nil {
			return common.Address{}, errKeysf(CodeRefNotFound, "no wallet named %q", ref.Wallet)
		}
		idx, ok := w.indexForRef(ref)
		if !ok {
			return common.Address{}, errKeysf(CodeRefNotFound, "no such account %q", ref.Raw)
		}
		return common.HexToAddress(w.Accounts[indexKey(idx)].Address), nil
	case domain.RefNamed:
		if _, a := m.findStandaloneByName(ref.Name); a != nil {
			return common.HexToAddress(a.Address), nil
		}
		// A bare wallet name has no single address.
		if _, w := m.findWalletByName(ref.Name); w != nil {
			return common.Address{}, errKeysf(CodeRefNotFound,
				"%q is a wallet, not a single address; reference an account like %s/0", ref.Name, ref.Name)
		}
		return common.Address{}, errKeysf(CodeRefNotFound, "no account named %q", ref.Name)
	default:
		return common.Address{}, errKeysf(CodeRefNotFound, "%q does not resolve to an address", ref.Raw)
	}
}
