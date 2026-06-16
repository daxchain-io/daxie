package keys

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
)

// TestGethV3RoundTripDaxieToGeth: a key keys imports must be readable by geth's
// own keystore.DecryptKey (byte-for-byte stock v3, §3.1 decision 2).
func TestGethV3RoundTripDaxieToGeth(t *testing.T) {
	s, pass := initStore(t)
	rawHex := "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	key := secret.NewString(rawHex)
	defer key.Zero()
	_, addr, err := s.ImportStandalone(context.Background(), "ops", key, pass)
	if err != nil {
		t.Fatal(err)
	}

	// Locate the produced accounts/UTC--… file and decrypt it with GETH directly.
	m, _ := s.loadMeta()
	var rel string
	for _, a := range m.Accounts {
		rel = a.File
	}
	if rel == "" {
		t.Fatal("no standalone file recorded")
	}
	blob, err := os.ReadFile(filepath.Join(s.dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	gkey, derr := gethkeystore.DecryptKey(blob, testPass)
	if derr != nil {
		t.Fatalf("geth could not decrypt the daxie-written v3 file: %v", derr)
	}
	if gkey.Address != addr {
		t.Fatalf("geth-decrypted address %s != %s", gkey.Address.Hex(), addr.Hex())
	}
	// Stock file name convention: UTC--<ts>--<lowercase hex addr, no 0x>.
	base := filepath.Base(rel)
	if !strings.HasPrefix(base, "UTC--") || !strings.HasSuffix(base, strings.ToLower(addr.Hex()[2:])) {
		t.Fatalf("non-stock geth file name: %s", base)
	}
}

// TestGethV3RoundTripGethToDaxie: a v3 file produced by GETH (EncryptKey at light
// scrypt) must be readable by keys (AddressOf + ExportStandalone).
func TestGethV3RoundTripGethToDaxie(t *testing.T) {
	s, pass := initStore(t)

	// Produce a geth v3 file directly.
	priv, _ := gethcrypto.GenerateKey()
	addr := gethcrypto.PubkeyToAddress(priv.PublicKey)
	id, _ := uuid.NewRandom()
	gkey := &gethkeystore.Key{Id: id, Address: addr, PrivateKey: priv}
	blob, err := gethkeystore.EncryptKey(gkey, testPass, gethkeystore.LightScryptN, gethkeystore.LightScryptP)
	if err != nil {
		t.Fatal(err)
	}

	// Drop it into accounts/ and register it in meta as a standalone account.
	if err := s.ensureDirs(); err != nil {
		t.Fatal(err)
	}
	rel := filepath.ToSlash(filepath.Join("accounts", keyFileName(addr, s.clock())))
	if err := os.WriteFile(filepath.Join(s.dir, rel), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ := s.loadMeta()
	m.Accounts[id.String()] = &metaStandalone{
		Name:      "geth-import",
		Address:   addr.Hex(),
		File:      rel,
		CreatedAt: formatTime(s.clock()),
	}
	if err := s.saveMeta(m); err != nil {
		t.Fatal(err)
	}

	// keys reads the geth-produced file.
	ref, _ := domain.ParseAccountRef("geth-import")
	got, err := s.AddressOf(ref)
	if err != nil {
		t.Fatal(err)
	}
	if got != addr {
		t.Fatalf("AddressOf = %s, want %s", got.Hex(), addr.Hex())
	}
	out, eerr := s.ExportStandalone(context.Background(), ref, pass)
	if eerr != nil {
		t.Fatalf("ExportStandalone of a geth file: %v", eerr)
	}
	defer out.Zero()
	wantHex := privateKeyHex(priv)
	defer zeroBytes(wantHex)
	if string(out.Reveal()) != string(wantHex) {
		t.Fatal("exported key does not match the geth-imported key")
	}
}

// TestWalletBlobDataV3RoundTrip: the wallet blob uses EncryptDataV3/DecryptDataV3
// (arbitrary bytes), NOT EncryptKey — the §3.3 distinction. EncryptKey would
// reject the non-curve mnemonic plaintext.
func TestWalletBlobDataV3RoundTrip(t *testing.T) {
	plaintext := encodePlaintext([]byte(abandonMnemonic), []byte("TREZOR"))
	cj, err := gethkeystore.EncryptDataV3(plaintext, []byte(testPass), gethkeystore.LightScryptN, gethkeystore.LightScryptP)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gethkeystore.DecryptDataV3(cj, testPass)
	if err != nil {
		t.Fatal(err)
	}
	mn, b39, derr := decodePlaintext(got)
	if derr != nil {
		t.Fatal(derr)
	}
	if string(mn) != abandonMnemonic || string(b39) != "TREZOR" {
		t.Fatalf("blob round-trip mismatch: mn=%q b39=%q", mn, b39)
	}
	// EncryptKey would reject this >32-byte non-curve plaintext — prove the
	// distinction is real by checking the blob is larger than a 32-byte key.
	if len(plaintext) <= 32 {
		t.Fatal("plaintext unexpectedly small; the EncryptKey-vs-EncryptDataV3 distinction is the point")
	}
}

// TestWalletBlobIsMarkedSuperset: the wallet blob carries the daxie marker and no
// `address` field, so geth tooling skips it.
func TestWalletBlobIsMarkedSuperset(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "w", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()
	b, err := os.ReadFile(s.walletBlobPath(cr.WalletID))
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, `"daxie_wallet"`) {
		t.Error("wallet blob missing the daxie_wallet superset marker")
	}
	if strings.Contains(js, `"address"`) {
		t.Error("wallet blob must NOT carry an address field (geth tools key off it)")
	}
}
