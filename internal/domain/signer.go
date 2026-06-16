package domain

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Signer is the future-proofed key boundary (§2.6, requirements §5). It resolves
// a parsed AccountRef to an address (read-only, no unlock) and signs transactions
// and hashes. Unlock material flows via a separate Unlocker so a KMS / hardware /
// remote-daemon backend implements the SAME interface without a passphrase
// concept — this is what makes the v1.1 daemon relocation a swap, not a refactor.
//
// Policy is NOT behind this interface and there is no GuardedSigner decorator:
// policy runs in service ahead of Signer (§2.7). The local keys.Store satisfies
// this via a thin adapter (keys.Store.Signer, §3.12).
type Signer interface {
	// Address resolves a parsed ref to an address WITHOUT unlocking (the
	// explicitly unlock-free read-only path: --from for `contract call`,
	// balances, allowlist echoes). RefAddress resolves to itself; signing-only
	// shapes (bare wallet name) are rejected with ref.not_found.
	Address(ctx context.Context, ref AccountRef) (common.Address, error)

	// SignTx returns the RLP-encoded signed transaction and its hash. The
	// passphrase is acquired through u; a KMS/daemon backend ignores u. chainID
	// selects the EIP-155 signer.
	SignTx(ctx context.Context, ref AccountRef, tx *types.Transaction, chainID *big.Int, u Unlocker) (raw []byte, hash common.Hash, err error)

	// SignHash signs a 32-byte digest (EIP-191 / EIP-712 prehashed), returning the
	// 65-byte [R||S||V] signature.
	SignHash(ctx context.Context, ref AccountRef, hash common.Hash, u Unlocker) ([]byte, error)
}

// Unlocker is how a passphrase reaches the signer (§2.6). The local keystore reads
// it; a KMS/daemon signer ignores it — which is why the daemon is a swap, not a
// refactor.
//
// Deviation-with-rationale from the §2.6 verbatim print (owned here, §11 D1
// spirit): the design prints Passphrase(ctx) (secret.Bytes, error), but domain
// imports NOTHING internal (the arch matrix's contract rule: a domain import of
// the secret provider is a CONTRACT VIOLATION). The interface therefore returns
// the raw passphrase bytes; the CALLER (service) owns the backing secret.Bytes
// container and zeroes it on defer. The boundary is unchanged — only the
// secret-holding container moves to a layer permitted to hold it (service/secret),
// exactly the §11 D1 "keep the boundary, move the container" reconciliation. A
// KMS/daemon backend returns (nil, nil) and the signer never reads it.
type Unlocker interface {
	// Passphrase returns the raw passphrase bytes. The returned slice is borrowed
	// from a secret.Bytes the caller owns and zeroes; the signer must NOT retain
	// or copy it beyond the signing call. A no-passphrase backend returns
	// (nil, nil).
	Passphrase(ctx context.Context) ([]byte, error)
}

// Signable is a resolved signing identity bound to its keystore object, returned
// by keys.Store.LookupSigning (§3.2). It signs through the same Unlocker seam as
// Signer, so the per-account path and the ref-routed path share one unlock model.
// Concrete implementations live in the keys provider (hdSignable /
// standaloneSignable); they zero the *ecdsa.PrivateKey immediately after signing
// (§3.10).
type Signable interface {
	// Address is the resolved account address (already known, no unlock).
	Address() common.Address

	// SignTx signs tx under chainID, acquiring the passphrase via u, and returns
	// the RLP-encoded signed transaction and its hash.
	SignTx(ctx context.Context, tx *types.Transaction, chainID *big.Int, u Unlocker) (raw []byte, hash common.Hash, err error)

	// SignHash signs a 32-byte digest, returning the 65-byte [R||S||V] signature.
	SignHash(ctx context.Context, hash common.Hash, u Unlocker) ([]byte, error)
}
