package keys

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
)

// TestReadCheckedInGethV3Fixture reads a v3 key file produced by go-ethereum's own
// EncryptKey (checked in under testdata/, addr 0x2c75…) — the geth→daxie direction
// against a real, externally-produced file (§2.9 / plan §5 item 3).
func TestReadCheckedInGethV3Fixture(t *testing.T) {
	const fixturePass = "fixture-passphrase"
	const fixtureAddr = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"

	dir := t.TempDir()
	s, err := Open(context.Background(), Options{Dir: dir, Clock: fixedClock(), Light: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	// Initialize the keystore under the fixture passphrase (one-passphrase rule),
	// then drop the checked-in geth file into accounts/ and register it.
	pass := secret.NewString(fixturePass)
	defer pass.Zero()
	confirm := secret.NewString(fixturePass)
	defer confirm.Zero()
	if _, err := s.EnsureInitialized(context.Background(), pass, confirm); err != nil {
		t.Fatal(err)
	}

	blob, err := os.ReadFile("testdata/geth-v3-light.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ensureDirs(); err != nil {
		t.Fatal(err)
	}
	rel := "accounts/UTC--fixture--2c7536e3605d9c16a7a3d7b1898e529396a65c23"
	if err := os.WriteFile(filepath.Join(dir, rel), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ := s.loadMeta()
	m.Accounts["3a0b1c2d-4e5f-4a6b-8c9d-0e1f2a3b4c5d"] = &metaStandalone{
		Name: "fixture", Address: fixtureAddr, File: rel, CreatedAt: formatTime(s.clock()),
	}
	if err := s.saveMeta(m); err != nil {
		t.Fatal(err)
	}

	ref, _ := domain.ParseAccountRef("fixture")
	got, err := s.AddressOf(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(got.Hex(), fixtureAddr) {
		t.Fatalf("AddressOf(fixture) = %s, want %s", got.Hex(), fixtureAddr)
	}
	// And it signs (decrypt path on a foreign-produced file).
	sg, err := s.LookupSigning(ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, e := sg.SignHash(context.Background(), [32]byte{9}, testUnlocker{pass: fixturePass}); e != nil {
		t.Fatalf("sign with the geth fixture key: %v", e)
	}
}

// TestErrorsCarryNoSecrets asserts no plaintext mnemonic / key appears in an error
// rendering (§3.10: errors never carry secrets).
func TestErrorsCarryNoSecrets(t *testing.T) {
	s, pass := initStore(t)

	// A bad mnemonic error must not echo the mnemonic words.
	secretWords := "abandon abandon abandon" // an invalid (too-short) phrase
	bad := secret.NewString(secretWords)
	defer bad.Zero()
	empty := secret.NewString("")
	defer empty.Zero()
	_, _, err := s.ImportWallet(context.Background(), "bad", bad, empty, pass)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "abandon") {
		t.Fatalf("error leaked mnemonic words: %v", err)
	}

	// A bad raw key error must not echo the key hex.
	keyHex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	zeroKey := secret.NewString("0x0000000000000000000000000000000000000000000000000000000000000000")
	defer zeroKey.Zero()
	_, _, kerr := s.ImportStandalone(context.Background(), "k", zeroKey, pass)
	if kerr == nil || strings.Contains(kerr.Error(), keyHex) || strings.Contains(kerr.Error(), "0000000000000000") {
		t.Fatalf("key error leaked material: %v", kerr)
	}
}

// TestInfoCounts asserts keystore Info reports the right counts + KDF template.
func TestInfoCounts(t *testing.T) {
	s, pass := initStore(t)
	cr, err := s.CreateWallet(context.Background(), "w", 12, pass)
	if err != nil {
		t.Fatal(err)
	}
	cr.Mnemonic.Zero()
	cr.BIP39Pass.Zero()
	if _, _, e := s.DeriveNext(context.Background(), "w", pass); e != nil {
		t.Fatal(e)
	}
	k := secret.NewString("0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	defer k.Zero()
	if _, _, e := s.ImportStandalone(context.Background(), "ops", k, pass); e != nil {
		t.Fatal(e)
	}

	info, err := s.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !info.Initialized || info.Wallets != 1 || info.Accounts != 1 || info.HDAccounts != 2 {
		t.Fatalf("info = %+v", info)
	}
	if info.KDF != "scrypt" || info.ScryptN != lightScryptN {
		t.Fatalf("info KDF = %s N=%d, want scrypt/%d", info.KDF, info.ScryptN, lightScryptN)
	}
}

// TestLightGateNotHonoredOnStandardManifest: a store opened Light=true against a
// manifest created at STANDARD scrypt must NOT downgrade (a production keystore can
// never be silently weakened, §3.4). We assert via the manifest's recorded N.
func TestLightGateRespectsManifest(t *testing.T) {
	// Create a STANDARD keystore (Light=false) — but that costs ~1s of scrypt, so
	// we keep it minimal: just init + one verify, no wallet.
	if testing.Short() {
		t.Skip("standard scrypt is slow; skipped in -short")
	}
	dir := t.TempDir()
	std, err := Open(context.Background(), Options{Dir: dir, Clock: fixedClock(), Light: false})
	if err != nil {
		t.Fatal(err)
	}
	pass := secret.NewString(testPass)
	defer pass.Zero()
	confirm := secret.NewString(testPass)
	defer confirm.Zero()
	if _, err := std.EnsureInitialized(context.Background(), pass, confirm); err != nil {
		t.Fatal(err)
	}
	man, _ := std.loadManifest()
	if man.Light || man.KDFDefaults.N != stdScryptN {
		t.Fatalf("standard manifest recorded light=%v N=%d", man.Light, man.KDFDefaults.N)
	}
	// Reopen with Light=true; effectiveScrypt must still pick STANDARD (manifest
	// was not created light).
	reLight, _ := Open(context.Background(), Options{Dir: dir, Clock: fixedClock(), Light: true})
	man2, _ := reLight.loadManifest()
	n, _ := reLight.effectiveScrypt(man2)
	if n != stdScryptN {
		t.Fatalf("Light=true downgraded a standard keystore to N=%d", n)
	}
}
