package chain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
)

// writeTestCertKey generates a self-signed cert+key PEM pair into dir with the
// given key-file mode, returning (certPath, keyPath, caPath). The same cert is
// used as both the leaf and a CA bundle for the assembly tests.
func writeTestCertKey(t *testing.T, dir string, keyMode os.FileMode) (cert, key, ca string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "daxie-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	cert = filepath.Join(dir, "client.crt")
	key = filepath.Join(dir, "client.key")
	ca = filepath.Join(dir, "ca.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(cert, certPEM, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(ca, certPEM, 0o644); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	if err := os.WriteFile(key, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Chmod(key, keyMode); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	return cert, key, ca
}

// TestBuildTLSConfig_NoMaterial returns nil config when no TLS paths are set.
func TestBuildTLSConfig_NoMaterial(t *testing.T) {
	cfg, err := buildTLSConfig(Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Fatalf("config = %v, want nil when no TLS material configured", cfg)
	}
}

// TestBuildTLSConfig_ClientCertAndCA assembles a real tls.Config from cert+key+CA
// PATHS: the client certificate and the custom RootCAs pool must both be present.
func TestBuildTLSConfig_ClientCertAndCA(t *testing.T) {
	dir := t.TempDir()
	cert, key, ca := writeTestCertKey(t, dir, 0o600)

	cfg, err := buildTLSConfig(Options{TLSCert: cert, TLSKey: key, TLSCA: ca})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg == nil {
		t.Fatal("config = nil, want a populated *tls.Config")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates = %d, want 1 (mTLS client identity)", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Errorf("RootCAs = nil, want the custom CA pool")
	}
}

// TestBuildTLSConfig_CAOnly uses a CA bundle with no client cert (server-auth
// pinning only).
func TestBuildTLSConfig_CAOnly(t *testing.T) {
	dir := t.TempDir()
	_, _, ca := writeTestCertKey(t, dir, 0o600)

	cfg, err := buildTLSConfig(Options{TLSCA: ca})
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("want a config with RootCAs set")
	}
	if len(cfg.Certificates) != 0 {
		t.Errorf("Certificates = %d, want 0 (no client cert configured)", len(cfg.Certificates))
	}
}

// TestBuildTLSConfig_CertWithoutKey fails closed: one half of a client identity
// is an operator mistake, surfaced as config.invalid (exit 2).
func TestBuildTLSConfig_CertWithoutKey(t *testing.T) {
	dir := t.TempDir()
	cert, _, _ := writeTestCertKey(t, dir, 0o600)

	_, err := buildTLSConfig(Options{TLSCert: cert})
	if err == nil {
		t.Fatal("expected config.invalid for cert without key, got nil")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeConfigInvalid {
		t.Fatalf("err = %v, want config.invalid", err)
	}
}

// TestBuildTLSConfig_InsecureKeyPerms is the §7.9 tripwire: a world/group-
// readable key file is refused with keystore.perms_insecure (exit 12) BEFORE the
// key is loaded — a leaked mTLS key is a leaked credential.
func TestBuildTLSConfig_InsecureKeyPerms(t *testing.T) {
	if os.Getenv("DAXIE_SKIP_PERM_CHECK") == "1" {
		t.Skip("perm check disabled via env")
	}
	if runtime.GOOS == "windows" {
		// This tripwire is driven by POSIX mode bits: writeTestCertKey chmod 0o644
		// to make the key world-readable. On Windows os.Chmod only toggles the
		// read-only bit and does NOT create a world-readable DACL, so the file
		// keeps its owner-only inherited ACL and CheckPerms correctly returns nil —
		// the premise can't be set up via chmod. The Windows DACL insecure-perms
		// path is exercised by internal/fsx's own CheckPerms test instead.
		t.Skip("POSIX mode bits don't model a Windows world-readable DACL; covered by internal/fsx perms test")
	}
	dir := t.TempDir()
	cert, key, _ := writeTestCertKey(t, dir, 0o644) // world-readable key

	_, err := buildTLSConfig(Options{TLSCert: cert, TLSKey: key})
	if err == nil {
		t.Fatal("expected keystore.perms_insecure for a world-readable key, got nil")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeKeystorePermsInsecure {
		t.Fatalf("err = %v, want keystore.perms_insecure", err)
	}
	if de.Exit != domain.ExitIntegrity {
		t.Errorf("exit = %d, want %d (integrity)", de.Exit, domain.ExitIntegrity)
	}
}

// TestBuildTLSConfig_BadCABundle rejects a CA path with no valid PEM.
func TestBuildTLSConfig_BadCABundle(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(ca, []byte("not a pem"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := buildTLSConfig(Options{TLSCA: ca})
	if err == nil {
		t.Fatal("expected config.invalid for a CA bundle with no certs, got nil")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeConfigInvalid {
		t.Fatalf("err = %v, want config.invalid", err)
	}
}
