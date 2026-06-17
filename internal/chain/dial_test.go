package chain

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/core/types"
)

// rpcReq / rpcResp are the minimal JSON-RPC shapes the mock node speaks. The
// mock answers eth_chainId and a few read methods so Dial's verification guard
// (and the wired read methods) can be exercised with no network and no anvil.
type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  []any           `json:"params"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// mockNode is an httptest JSON-RPC server with a programmable chain-id. It also
// records the headers of every request so header-attachment can be asserted
// end-to-end through Dial.
type mockNode struct {
	*httptest.Server
	chainID *big.Int

	mu       sync.Mutex
	gotHeads []http.Header
}

func newMockNode(t *testing.T, chainID *big.Int) *mockNode {
	t.Helper()
	m := &mockNode{chainID: chainID}
	m.Server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.Close)
	return m
}

func (m *mockNode) headers() []http.Header {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]http.Header, len(m.gotHeads))
	copy(out, m.gotHeads)
	return out
}

func (m *mockNode) handle(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.gotHeads = append(m.gotHeads, r.Header.Clone())
	m.mu.Unlock()

	body, _ := io.ReadAll(r.Body)
	var req rpcReq
	_ = json.Unmarshal(body, &req)

	resp := rpcResp{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "eth_chainId":
		resp.Result = "0x" + m.chainID.Text(16)
	case "eth_blockNumber":
		resp.Result = "0x10"
	case "eth_getBalance":
		resp.Result = "0x0"
	case "eth_getTransactionCount":
		resp.Result = "0x0"
	default:
		resp.Error = &rpcErr{Code: -32601, Message: "method not found: " + req.Method}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// TestDial_ChainIDMatch_Succeeds proves a correct endpoint dials and the guard
// passes.
func TestDial_ChainIDMatch_Succeeds(t *testing.T) {
	node := newMockNode(t, big.NewInt(1))
	ctx := context.Background()

	cc, err := Dial(ctx, Options{
		URL:           node.URL,
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1),
	})
	if err != nil {
		t.Fatalf("Dial: unexpected error: %v", err)
	}
	defer cc.Close()

	id, err := cc.ChainID(ctx)
	if err != nil {
		t.Fatalf("ChainID: %v", err)
	}
	if id.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("ChainID = %v, want 1", id)
	}
}

// TestDial_ChainIDMismatch_Refuses is the load-bearing security guard: an
// endpoint reporting a different chain-id than the network declares MUST be
// refused, fail CLOSED with rpc.chain_id_mismatch (exit 12), and carry the
// {endpoint, network, expected, got} data envelope. A wrong/malicious endpoint
// must never be usable.
func TestDial_ChainIDMismatch_Refuses(t *testing.T) {
	node := newMockNode(t, big.NewInt(999)) // endpoint claims chain-id 999
	ctx := context.Background()

	cc, err := Dial(ctx, Options{
		URL:           node.URL,
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1), // we expect mainnet (1)
	})
	if cc != nil {
		cc.Close()
		t.Fatalf("Dial returned a usable client on chain-id mismatch; must refuse")
	}
	if err == nil {
		t.Fatal("Dial: expected a chain-id-mismatch error, got nil")
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("Dial error is not a *domain.Error: %v", err)
	}
	if de.Code != domain.CodeRPCChainIDMismatch {
		t.Fatalf("error code = %q, want %q", de.Code, domain.CodeRPCChainIDMismatch)
	}
	if de.Exit != domain.ExitIntegrity {
		t.Fatalf("exit = %d, want %d (integrity)", de.Exit, domain.ExitIntegrity)
	}
	if de.Data["expected"] != "1" || de.Data["got"] != "999" {
		t.Fatalf("data = %#v, want expected=1 got=999", de.Data)
	}
	if de.Data["network"] != "mainnet" || de.Data["endpoint"] != node.URL {
		t.Fatalf("data = %#v, want network=mainnet endpoint=%s", de.Data, node.URL)
	}
}

// TestDial_CustomHeaders_AttachThroughDial proves headers configured on Options
// reach the node on the chain-id probe (and therefore every subsequent request).
func TestDial_CustomHeaders_AttachThroughDial(t *testing.T) {
	node := newMockNode(t, big.NewInt(1))
	ctx := context.Background()

	cc, err := Dial(ctx, Options{
		URL:           node.URL,
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1),
		Headers:       map[string]string{"Authorization": "Bearer t0ken"},
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cc.Close()

	// Make one more call so we have at least two recorded requests.
	if _, err := cc.BlockNumber(ctx); err != nil {
		t.Fatalf("BlockNumber: %v", err)
	}

	heads := node.headers()
	if len(heads) == 0 {
		t.Fatal("node saw no requests")
	}
	for i, h := range heads {
		if got := h.Get("Authorization"); got != "Bearer t0ken" {
			t.Errorf("request %d Authorization = %q, want %q", i, got, "Bearer t0ken")
		}
	}
}

// TestDial_Unreachable_MapsToRPCUnreachable proves a dead endpoint maps to
// rpc.unreachable (exit 6, retryable), not an opaque internal error.
func TestDial_Unreachable_MapsToRPCUnreachable(t *testing.T) {
	// A server that immediately closes yields a connection failure on the probe.
	node := newMockNode(t, big.NewInt(1))
	url := node.URL
	node.Close() // now nothing is listening

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cc, err := Dial(ctx, Options{
		URL:           url,
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1),
		Timeout:       1 * time.Second,
	})
	if cc != nil {
		cc.Close()
	}
	if err == nil {
		t.Fatal("Dial to a dead endpoint: expected an error, got nil")
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error is not a *domain.Error: %v", err)
	}
	if de.Code != domain.CodeRPCUnreachable {
		t.Fatalf("code = %q, want %q", de.Code, domain.CodeRPCUnreachable)
	}
	if de.Exit != domain.ExitNetwork {
		t.Fatalf("exit = %d, want %d (network)", de.Exit, domain.ExitNetwork)
	}
	if !de.Retryable {
		t.Errorf("rpc.unreachable should be Retryable")
	}
}

// TestDial_NilExpectChainID_SkipsGuard proves the non-command probe path: a nil
// ExpectChainID dials without running the verification guard (used only where no
// network is declared).
func TestDial_NilExpectChainID_SkipsGuard(t *testing.T) {
	node := newMockNode(t, big.NewInt(42))
	ctx := context.Background()

	cc, err := Dial(ctx, Options{URL: node.URL, Network: "probe"})
	if err != nil {
		t.Fatalf("Dial with nil ExpectChainID: %v", err)
	}
	defer cc.Close()

	id, err := cc.ChainID(ctx)
	if err != nil {
		t.Fatalf("ChainID: %v", err)
	}
	if id.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("ChainID = %v, want 42", id)
	}
}

// TestSubscribe_HTTP_ReturnsErrNotSupported proves the Subscribe-on-HTTP fallback
// signal: an HTTP(S) client returns chain.ErrNotSupported (no second interface).
func TestSubscribe_HTTP_ReturnsErrNotSupported(t *testing.T) {
	node := newMockNode(t, big.NewInt(1))
	ctx := context.Background()

	cc, err := Dial(ctx, Options{URL: node.URL, Network: "mainnet", ExpectChainID: big.NewInt(1)})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cc.Close()

	if _, err := cc.SubscribeNewHead(ctx, make(chan uint64, 1)); !errors.Is(err, ErrNotSupported) {
		t.Errorf("SubscribeNewHead on HTTP: err = %v, want ErrNotSupported", err)
	}
	if _, err := cc.SubscribeLogs(ctx, ethereum.FilterQuery{}, make(chan types.Log, 1)); !errors.Is(err, ErrNotSupported) {
		t.Errorf("SubscribeLogs on HTTP: err = %v, want ErrNotSupported", err)
	}
}

// TestDial_ChainIDMismatch_DoesNotLeakSecret proves the §7.5 contract: a resolved
// API key embedded in the endpoint URL must NOT appear in the chain-id-mismatch
// error message or its data envelope (those are printed to the terminal/logs). The
// service composition root supplies a masked DisplayURL; chain renders that, never
// the resolved URL.
func TestDial_ChainIDMismatch_DoesNotLeakSecret(t *testing.T) {
	node := newMockNode(t, big.NewInt(999)) // wrong chain-id forces the mismatch path
	ctx := context.Background()

	const secret = "abcdef0123456789abcdef0123456789deadbeef" // a 40-char opaque key
	resolvedURL := node.URL + "/v2/" + secret

	cc, err := Dial(ctx, Options{
		URL:           resolvedURL,
		DisplayURL:    node.URL + "/v2/***", // what service would supply (masked)
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1),
	})
	if cc != nil {
		cc.Close()
	}
	if err == nil {
		t.Fatal("Dial: expected a chain-id-mismatch error, got nil")
	}
	assertNoSecret(t, err, secret)

	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error is not a *domain.Error: %v", err)
	}
	if got, _ := de.Data["endpoint"].(string); strings.Contains(got, secret) {
		t.Fatalf("data.endpoint leaked the secret: %q", got)
	}
}

// TestDial_Unreachable_DoesNotLeakSecret proves the same for the unreachable path,
// AND that even without a service-supplied DisplayURL, chain's own fallback masking
// keeps a resolved API key out of the error (so a probe path can never leak).
func TestDial_Unreachable_DoesNotLeakSecret(t *testing.T) {
	node := newMockNode(t, big.NewInt(1))
	base := node.URL
	node.Close() // nothing is listening now → dial fails (unreachable)

	const secret = "abcdef0123456789abcdef0123456789deadbeef"
	resolvedURL := base + "/v2/" + secret

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// No DisplayURL supplied: chain must fall back to masking the resolved URL.
	cc, err := Dial(ctx, Options{
		URL:           resolvedURL,
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1),
		Timeout:       1 * time.Second,
	})
	if cc != nil {
		cc.Close()
	}
	if err == nil {
		t.Fatal("Dial to a dead endpoint: expected an error, got nil")
	}
	assertNoSecret(t, err, secret)
}

// assertNoSecret fails if secret appears in the error's human message, its JSON
// (data envelope), or the rendered domain error string.
func assertNoSecret(t *testing.T, err error, secret string) {
	t.Helper()
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error message leaked the secret %q: %v", secret, err)
	}
	var de *domain.Error
	if errors.As(err, &de) {
		if strings.Contains(de.Msg, secret) {
			t.Fatalf("domain error Msg leaked the secret: %q", de.Msg)
		}
		blob, _ := json.Marshal(de.Data)
		if strings.Contains(string(blob), secret) {
			t.Fatalf("domain error Data leaked the secret: %s", blob)
		}
	}
}

// TestIsWebsocket classifies scheme detection for the Subscribe* gate.
func TestIsWebsocket(t *testing.T) {
	cases := map[string]bool{
		"ws://localhost:8545":   true,
		"wss://node.example":    true,
		"WSS://NODE":            true,
		"  ws://x ":             true,
		"http://localhost:8545": false,
		"https://node.example":  false,
		"":                      false,
	}
	for url, want := range cases {
		if got := isWebsocket(url); got != want {
			t.Errorf("isWebsocket(%q) = %v, want %v", url, got, want)
		}
	}
}
