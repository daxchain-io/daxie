package chain

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// dial_wss_test.go is the load-bearing proof that mTLS material reaches the
// WEBSOCKET transport. Before the fix, dialOptions wired the *tls.Config only on
// the HTTP path, so a wss:// endpoint configured with --tls-cert/--tls-key/--tls-ca
// silently dropped the client cert (handshake fails / server accepts an
// unauthenticated session) and the custom CA pool (server cert verified against
// system roots — fail-open). These tests stand up a wss server that REQUIRES a
// client cert signed by a private CA and assert:
//
//   - Dial SUCCEEDS only when TLSCert/TLSKey (client identity) + TLSCA (the private
//     CA that signs the server cert) are supplied — i.e. the dialer carried them;
//   - Dial FAILS CLOSED without the client cert (the server rejects the handshake);
//   - the chain-id guard still runs over the wss transport.

// wssTestPKI is a minimal private CA plus a server cert (SAN 127.0.0.1) and a
// client cert, all in-memory + on disk (Options takes file paths).
type wssTestPKI struct {
	caCertPEM   []byte
	caPool      *x509.CertPool
	serverCert  tls.Certificate
	clientCertF string
	clientKeyF  string
	caF         string
}

func newWSSTestPKI(t *testing.T) *wssTestPKI {
	t.Helper()
	dir := t.TempDir()

	// ── CA ──
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "daxie-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// ── server leaf (SAN 127.0.0.1) signed by the CA ──
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	srvCert := tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}

	// ── client leaf signed by the CA ──
	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "daxie-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	cliCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliDER})
	cliKeyDER, err := x509.MarshalPKCS8PrivateKey(cliKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	cliKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: cliKeyDER})

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertPEM)

	clientCertF := filepath.Join(dir, "client.crt")
	clientKeyF := filepath.Join(dir, "client.key")
	caF := filepath.Join(dir, "ca.pem")
	mustWrite(t, clientCertF, cliCertPEM, 0o644)
	mustWrite(t, clientKeyF, cliKeyPEM, 0o600)
	mustWrite(t, caF, caCertPEM, 0o644)

	return &wssTestPKI{
		caCertPEM:   caCertPEM,
		caPool:      caPool,
		serverCert:  srvCert,
		clientCertF: clientCertF,
		clientKeyF:  clientKeyF,
		caF:         caF,
	}
}

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// newWSSChainIDServer starts a TLS websocket server that REQUIRES a client cert
// signed by pki.caPool and answers eth_chainId with chainID. It returns the wss://
// URL. The handshake fails closed for a client that presents no/invalid cert.
func newWSSChainIDServer(t *testing.T, pki *wssTestPKI, chainID *big.Int) string {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			var req rpcReq
			if err := conn.ReadJSON(&req); err != nil {
				return
			}
			resp := rpcResp{JSONRPC: "2.0", ID: req.ID}
			switch req.Method {
			case "eth_chainId":
				resp.Result = "0x" + chainID.Text(16)
			default:
				resp.Error = &rpcErr{Code: -32601, Message: "method not found: " + req.Method}
			}
			if err := conn.WriteJSON(resp); err != nil {
				return
			}
		}
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert, // mTLS: a client cert is mandatory
		ClientCAs:    pki.caPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// httptest gives an https://127.0.0.1:PORT URL; rewrite the scheme to wss://.
	return "wss://" + strings.TrimPrefix(srv.URL, "https://")
}

// TestDial_WSS_MTLS_Succeeds proves the client cert + custom CA actually reach the
// websocket handshake: a wss:// dial with TLSCert/TLSKey/TLSCA completes the mTLS
// handshake and the chain-id guard passes. Before the fix this hung/failed because
// the dialer carried no TLS config.
func TestDial_WSS_MTLS_Succeeds(t *testing.T) {
	pki := newWSSTestPKI(t)
	url := newWSSChainIDServer(t, pki, big.NewInt(1))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cc, err := Dial(ctx, Options{
		URL:           url,
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1),
		TLSCert:       pki.clientCertF,
		TLSKey:        pki.clientKeyF,
		TLSCA:         pki.caF,
		Timeout:       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial(wss + mTLS): unexpected error (the client cert/CA was not carried to the ws dialer?): %v", err)
	}
	defer cc.Close()

	id, err := cc.ChainID(ctx)
	if err != nil {
		t.Fatalf("ChainID over wss: %v", err)
	}
	if id.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("ChainID = %v, want 1", id)
	}
}

// TestDial_WSS_NoClientCert_FailsClosed proves the mTLS server REJECTS a wss client
// that presents no client cert (so the success above is meaningful — the cert is
// genuinely required and genuinely presented). TLSCA is supplied so the failure is
// the client-auth requirement, not server-cert verification.
func TestDial_WSS_NoClientCert_FailsClosed(t *testing.T) {
	pki := newWSSTestPKI(t)
	url := newWSSChainIDServer(t, pki, big.NewInt(1))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cc, err := Dial(ctx, Options{
		URL:           url,
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1),
		TLSCA:         pki.caF, // trust the server CA, but present NO client cert
		Timeout:       5 * time.Second,
	})
	if cc != nil {
		cc.Close()
	}
	if err == nil {
		t.Fatal("Dial(wss) without a client cert: expected the mTLS handshake to fail closed, got success")
	}
}

// TestDial_WSS_CustomCA_Carried proves the custom CA pool reaches the ws dialer:
// the server cert chains to a PRIVATE CA, so a dial that does NOT supply TLSCA
// (system roots only) must fail server-cert verification — confirming the CA is
// load-bearing and is honoured only when supplied. (The success path with TLSCA is
// covered above.) A client cert IS supplied so the failure is isolated to server-
// cert/CA verification.
func TestDial_WSS_CustomCA_Carried(t *testing.T) {
	pki := newWSSTestPKI(t)
	url := newWSSChainIDServer(t, pki, big.NewInt(1))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cc, err := Dial(ctx, Options{
		URL:           url,
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1),
		TLSCert:       pki.clientCertF,
		TLSKey:        pki.clientKeyF,
		// No TLSCA: the private-CA server cert must NOT verify against system roots.
		Timeout: 5 * time.Second,
	})
	if cc != nil {
		cc.Close()
	}
	if err == nil {
		t.Fatal("Dial(wss) without the private CA: expected server-cert verification to fail, got success")
	}
}

// TestDialOptions_WS_CarriesTLSDialer is a white-box guard: when ws && a TLS config
// is present, dialOptions must emit a websocket dialer option (so the discard the
// fix repaired regresses loudly even if the integration servers above ever change).
func TestDialOptions_WS_CarriesTLSDialer(t *testing.T) {
	pki := newWSSTestPKI(t)
	opts, err := dialOptions(Options{
		URL:     "wss://node.example",
		TLSCert: pki.clientCertF,
		TLSKey:  pki.clientKeyF,
		TLSCA:   pki.caF,
	}, true)
	if err != nil {
		t.Fatalf("dialOptions(ws + TLS): %v", err)
	}
	// Apply the options to a clientConfig-like probe via a real rpc client option:
	// we cannot read geth's private clientConfig, so assert at least one option is a
	// websocket dialer by checking the option set is non-empty and that a no-TLS ws
	// dial yields FEWER options (no dialer added).
	noTLS, err := dialOptions(Options{URL: "wss://node.example"}, true)
	if err != nil {
		t.Fatalf("dialOptions(ws, no TLS): %v", err)
	}
	if len(opts) <= len(noTLS) {
		t.Fatalf("ws+TLS produced %d options, ws-no-TLS produced %d; expected the TLS path to add a websocket dialer",
			len(opts), len(noTLS))
	}
}
