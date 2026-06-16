package keys

import (
	"context"
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/daxchain-io/daxie/internal/domain"
)

// Compile-time proof the keys impls satisfy the domain seams (§2.6/§3.12). If
// Group A's domain.Signer/Signable interface shapes drift from what keys
// implements, the build fails here rather than at a call site.
var (
	_ domain.Signable = (*hdSignable)(nil)
	_ domain.Signable = (*standaloneSignable)(nil)
	_ domain.Signer   = (*signerAdapter)(nil)
)

// hdSignable is a resolved HD signing identity (§3.2). It holds NO secret — only
// the locator. At sign time it pulls the passphrase from the Unlocker, decrypts
// the wallet blob, derives the index, signs, and zeroes the seed + key.
type hdSignable struct {
	store    *Store
	walletID string
	index    uint32
	addr     common.Address
}

func (h *hdSignable) Address() common.Address { return h.addr }

func (h *hdSignable) SignTx(ctx context.Context, tx *types.Transaction, chainID *big.Int, u domain.Unlocker) ([]byte, common.Hash, error) {
	priv, err := h.unlock(ctx, u)
	if err != nil {
		return nil, common.Hash{}, err
	}
	defer zeroECDSA(priv)
	return signTx(tx, chainID, priv)
}

func (h *hdSignable) SignHash(ctx context.Context, hash common.Hash, u domain.Unlocker) ([]byte, error) {
	priv, err := h.unlock(ctx, u)
	if err != nil {
		return nil, err
	}
	defer zeroECDSA(priv)
	return signHash(hash, priv)
}

// unlock derives the HD key for h.index, zeroing all intermediate secret material
// (passphrase copy, plaintext, mnemonic, seed) before returning. The returned key
// is the caller's to zeroECDSA.
func (h *hdSignable) unlock(ctx context.Context, u domain.Unlocker) (*ecdsa.PrivateKey, error) {
	passBytes, err := acquirePass(ctx, u)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(passBytes)

	plain, perr := h.store.readWalletPlaintext(h.walletID, passBytes)
	if perr != nil {
		return nil, perr
	}
	defer zeroBytes(plain)
	mn, b39, derr := decodePlaintext(plain)
	if derr != nil {
		return nil, errWrap(CodeStateCorrupt, "the wallet blob plaintext is malformed", derr)
	}
	defer zeroBytes(mn)
	defer zeroBytes(b39)

	seed := seedFromMnemonic(mn, b39)
	defer zeroBytes(seed)
	return derivePrivateKey(seed, h.index)
}

// standaloneSignable is a resolved standalone signing identity (§3.2). It holds NO
// secret — only the file locator.
type standaloneSignable struct {
	store *Store
	file  string
	addr  common.Address
}

func (a *standaloneSignable) Address() common.Address { return a.addr }

func (a *standaloneSignable) SignTx(ctx context.Context, tx *types.Transaction, chainID *big.Int, u domain.Unlocker) ([]byte, common.Hash, error) {
	priv, err := a.unlock(ctx, u)
	if err != nil {
		return nil, common.Hash{}, err
	}
	defer zeroECDSA(priv)
	return signTx(tx, chainID, priv)
}

func (a *standaloneSignable) SignHash(ctx context.Context, hash common.Hash, u domain.Unlocker) ([]byte, error) {
	priv, err := a.unlock(ctx, u)
	if err != nil {
		return nil, err
	}
	defer zeroECDSA(priv)
	return signHash(hash, priv)
}

func (a *standaloneSignable) unlock(ctx context.Context, u domain.Unlocker) (*ecdsa.PrivateKey, error) {
	passBytes, err := acquirePass(ctx, u)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(passBytes)
	return a.store.readStandaloneKey(a.file, passBytes)
}

// acquirePass pulls the passphrase bytes from the Unlocker into a slice keys owns
// and zeroes. The Unlocker may return nil (a KMS/daemon backend that needs no
// passphrase); keys then has no passphrase and the decrypt fails closed with
// keystore.bad_passphrase — which is correct for the LOCAL keystore (a daemon
// backend is a different domain.Signer impl, §2.10). A nil Unlocker is a
// passphrase-required error.
func acquirePass(ctx context.Context, u domain.Unlocker) ([]byte, error) {
	if u == nil {
		return nil, errKeys(CodeKeystoreBadPassphrase, "no unlocker provided for a signing operation")
	}
	raw, err := u.Passphrase(ctx)
	if err != nil {
		return nil, err
	}
	// Copy into a slice keys owns so the unlocker's backing secret.Bytes can be
	// zeroed independently by its owner (the service).
	cp := make([]byte, len(raw))
	copy(cp, raw)
	return cp, nil
}

// signTx signs tx for chainID and returns the RLP-encoded signed bytes + the
// signed-tx hash. Uses the latest signer for the chain (EIP-1559/legacy aware).
func signTx(tx *types.Transaction, chainID *big.Int, priv *ecdsa.PrivateKey) ([]byte, common.Hash, error) {
	signer := types.LatestSignerForChainID(chainID)
	signed, err := types.SignTx(tx, signer, priv)
	if err != nil {
		return nil, common.Hash{}, errWrap(CodeStateCorrupt, "cannot sign the transaction", err)
	}
	raw, merr := signed.MarshalBinary()
	if merr != nil {
		return nil, common.Hash{}, errWrap(CodeStateCorrupt, "cannot encode the signed transaction", merr)
	}
	return raw, signed.Hash(), nil
}

// signHash signs a 32-byte digest (EIP-191/712 prehashed) and returns the 65-byte
// [R||S||V] signature.
func signHash(hash common.Hash, priv *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := gethcrypto.Sign(hash.Bytes(), priv)
	if err != nil {
		return nil, errWrap(CodeStateCorrupt, "cannot sign the hash", err)
	}
	return sig, nil
}

// ── the domain.Signer adapter (§3.12) ──────────────────────────────────────────

// signerAdapter wraps *Store to satisfy domain.Signer. It is stateless re:
// identity — the parsed AccountRef is the parameter — and threads unlock material
// through domain.Unlocker, so a future KMS/daemon backend is a swap, not a
// refactor (§2.10).
type signerAdapter struct{ s *Store }

// Signer returns the domain.Signer view of this store. Constructed by service.Open
// (§3.12); never holds a passphrase.
func (s *Store) Signer() domain.Signer { return &signerAdapter{s: s} }

func (a *signerAdapter) Address(ctx context.Context, ref domain.AccountRef) (common.Address, error) {
	return a.s.AddressOf(ref)
}

func (a *signerAdapter) SignTx(ctx context.Context, ref domain.AccountRef, tx *types.Transaction, chainID *big.Int, u domain.Unlocker) ([]byte, common.Hash, error) {
	sg, err := a.s.LookupSigning(ref)
	if err != nil {
		return nil, common.Hash{}, err
	}
	return sg.SignTx(ctx, tx, chainID, u)
}

func (a *signerAdapter) SignHash(ctx context.Context, ref domain.AccountRef, hash common.Hash, u domain.Unlocker) ([]byte, error) {
	sg, err := a.s.LookupSigning(ref)
	if err != nil {
		return nil, err
	}
	return sg.SignHash(ctx, hash, u)
}
