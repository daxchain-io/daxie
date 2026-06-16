package keys

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
)

func TestSignTxThroughSignerAdapter(t *testing.T) {
	s, pass := initStore(t)
	importAbandon(t, s, pass, "tre")

	signer := s.Signer()
	ref, _ := domain.ParseAccountRef("tre/0")
	u := testUnlocker{pass: testPass}

	chainID := big.NewInt(1)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     0,
		To:        &common.Address{0x01},
		Value:     big.NewInt(1),
		Gas:       21000,
		GasFeeCap: big.NewInt(1_000_000_000),
		GasTipCap: big.NewInt(1_000_000_000),
	})

	raw, hash, err := signer.SignTx(context.Background(), ref, tx, chainID, u)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || (hash == common.Hash{}) {
		t.Fatal("empty signed tx / hash")
	}

	// Recover the sender from the signed tx and assert it is tre/0's address.
	var decoded types.Transaction
	if err := decoded.UnmarshalBinary(raw); err != nil {
		t.Fatalf("decode signed tx: %v", err)
	}
	from, err := types.Sender(types.LatestSignerForChainID(chainID), &decoded)
	if err != nil {
		t.Fatalf("recover sender: %v", err)
	}
	want, _ := signer.Address(context.Background(), ref)
	if from != want {
		t.Fatalf("recovered sender %s != %s", from.Hex(), want.Hex())
	}
}

func TestSignHashStandalone(t *testing.T) {
	s, pass := initStore(t)
	rawHex := "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	key := secret.NewString(rawHex)
	defer key.Zero()
	if _, _, err := s.ImportStandalone(context.Background(), "ops", key, pass); err != nil {
		t.Fatal(err)
	}

	ref, _ := domain.ParseAccountRef("ops")
	sg, err := s.LookupSigning(ref)
	if err != nil {
		t.Fatal(err)
	}
	digest := gethcrypto.Keccak256Hash([]byte("hello"))
	sig, err := sg.SignHash(context.Background(), digest, testUnlocker{pass: testPass})
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length = %d, want 65", len(sig))
	}
	// Recover the signer pubkey from the signature and verify the address.
	pub, err := gethcrypto.SigToPub(digest.Bytes(), sig)
	if err != nil {
		t.Fatal(err)
	}
	if gethcrypto.PubkeyToAddress(*pub) != sg.Address() {
		t.Fatal("recovered address mismatch")
	}
}

func TestZeroECDSAWipesKey(t *testing.T) {
	priv, err := gethcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Snapshot the secret scalar bytes (avoids touching the deprecated D field
	// directly): a fresh key has non-zero scalar bytes.
	before := gethcrypto.FromECDSA(priv)
	if allZero(before) {
		t.Fatal("generated key scalar is zero")
	}
	zeroBytes(before)

	zeroECDSA(priv)
	// After zeroing, the scalar bytes are all zero.
	after := gethcrypto.FromECDSA(priv)
	if !allZero(after) {
		t.Fatalf("zeroECDSA left non-zero scalar bytes: %x", after)
	}
	zeroBytes(after)
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return len(b) > 0
}

func TestSignWrongPassphraseFailsClosed(t *testing.T) {
	s, pass := initStore(t)
	importAbandon(t, s, pass, "tre")
	ref, _ := domain.ParseAccountRef("tre/0")
	sg, err := s.LookupSigning(ref)
	if err != nil {
		t.Fatal(err)
	}
	digest := gethcrypto.Keccak256Hash([]byte("x"))
	if _, e := sg.SignHash(context.Background(), digest, testUnlocker{pass: "wrong"}); !codeIs(e, CodeKeystoreBadPassphrase) {
		t.Fatalf("sign with wrong pass: got %v, want %s", e, CodeKeystoreBadPassphrase)
	}
}
