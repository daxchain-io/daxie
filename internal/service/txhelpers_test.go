package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// txhelpers_test.go holds the shared M3 service-test scaffolding: a deterministic
// in-package signer (no keystore needed), address/error helpers, and a
// send-ready Service builder that wires a fake chain client + a fake signer +
// the real journal/policy/nonce/contacts (all on isolated temp dirs).

// someAddr returns a deterministic non-zero address keyed by n.
func someAddr(n byte) common.Address {
	var a common.Address
	a[19] = n
	a[0] = 0xda
	return a
}

// errString is a plain error for taxonomy tests.
type errString string

func (e errString) Error() string { return string(e) }

// fakeSigner is a deterministic domain.Signer that signs ANY tx without a
// keystore. SignTx RLP-encodes the unsigned tx (so raw_tx round-trips) and
// derives a stable hash from the tx's own hash — good enough for the journal +
// the rebroadcast-same-bytes assertions. It records the calls for ordering tests.
type fakeSigner struct {
	addr    common.Address
	signed  int
	lastRaw []byte
}

func (f *fakeSigner) Address(_ context.Context, _ domain.AccountRef) (common.Address, error) {
	return f.addr, nil
}

func (f *fakeSigner) SignTx(_ context.Context, _ domain.AccountRef, tx *types.Transaction, _ *big.Int, _ domain.Unlocker) ([]byte, common.Hash, error) {
	f.signed++
	// Encode the unsigned tx as the "raw" bytes (deterministic + decodable).
	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, common.Hash{}, err
	}
	f.lastRaw = raw
	// A stable, unique-per-(nonce,value) hash: the geth tx hash of the unsigned tx.
	return raw, tx.Hash(), nil
}

func (f *fakeSigner) SignHash(_ context.Context, _ domain.AccountRef, _ common.Hash, _ domain.Unlocker) ([]byte, error) {
	return make([]byte, 65), nil
}

var _ domain.Signer = (*fakeSigner)(nil)

// sendService opens an isolated Service wired for the send pipeline: a fake chain
// client (returned by a stub provider), a fake signer for `from`, and a
// passphrase env so withUnlocker succeeds. It returns the service + the fake
// client + the fake signer so a test can program receipts/fees and assert on the
// journal.
func sendService(t *testing.T, from common.Address) (*Service, *fake.Client, *fakeSigner) {
	t.Helper()
	f := fake.New()
	svc := openWithProvider(t, &stubProvider{cc: f})
	sgn := &fakeSigner{addr: from}
	svc.signer = sgn
	// A passphrase source so withUnlocker resolves cleanly (the fake signer ignores
	// it, but the acquisition path still runs).
	svc.secretIO = SecretIO{LookupEnv: func(k string) (string, bool) {
		if k == "DAXIE_PASSPHRASE" {
			return "test-pass", true
		}
		return "", false
	}}
	return svc, f, sgn
}

// fakeReceipt builds a minimal mined receipt for hash h at block blk with the
// given status (1 ok / 0 reverted).
func fakeReceipt(h common.Hash, blk uint64, status uint64) *types.Receipt {
	return &types.Receipt{
		TxHash:            h,
		Status:            status,
		BlockNumber:       new(big.Int).SetUint64(blk),
		BlockHash:         common.HexToHash("0xb10c"),
		GasUsed:           21000,
		EffectiveGasPrice: big.NewInt(1_000_000_000),
	}
}

// txReq builds a baseline ETH send request from a raw-address --from to a raw 0x
// recipient. A raw-address --from lets AddressOf resolve without a keystore while
// the injected fakeSigner does the signing.
func txReq(from, to common.Address, amountWei string) domain.TxRequest {
	return domain.TxRequest{
		From:   from.Hex(),
		To:     to.Hex(),
		Amount: amountWei + "wei",
	}
}
