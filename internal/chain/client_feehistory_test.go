package chain

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// client_feehistory_test.go pins the §5.4 SuggestFees contract against the REAL
// JSON-RPC adapter (no anvil needed — a canned eth_feeHistory response over an
// httptest JSON-RPC server). It asserts the three load-bearing properties the
// adversarial review found violated:
//
//  1. the percentile triple requested is exactly [25,50,90] (slow/normal/fast);
//  2. the lookback window is the CALLER-supplied block count (not a hardcoded 5);
//  3. each tier is the MEDIAN of its percentile column across the sampled blocks,
//     NOT the latest block's value — a single MEV-bribe final block must NOT
//     poison `fast`.

// feeHistoryNode is a JSON-RPC httptest server that answers eth_chainId +
// eth_feeHistory with a programmed FeeHistory, recording the feeHistory params so
// the test can assert the block count + percentile triple actually sent.
type feeHistoryNode struct {
	*httptest.Server
	chainID *big.Int

	// reward is the per-block, per-percentile tip matrix (hex strings); baseFee is
	// the blockCount+1 base-fee array (hex strings); oldestBlock is a hex string.
	reward      [][]string
	baseFee     []string
	oldestBlock string

	mu          sync.Mutex
	gotBlocks   any   // params[0] (block count) of the last eth_feeHistory call
	gotPercents []any // params[2] (reward percentiles) of the last call
	feeCalls    int
}

func newFeeHistoryNode(t *testing.T) *feeHistoryNode {
	t.Helper()
	n := &feeHistoryNode{chainID: big.NewInt(1)}
	n.Server = httptest.NewServer(http.HandlerFunc(n.handle))
	t.Cleanup(n.Close)
	return n
}

func (n *feeHistoryNode) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params []any           `json:"params"`
	}
	_ = json.Unmarshal(body, &req)

	resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	switch req.Method {
	case "eth_chainId":
		resp["result"] = "0x" + n.chainID.Text(16)
	case "eth_feeHistory":
		n.mu.Lock()
		n.feeCalls++
		if len(req.Params) > 0 {
			n.gotBlocks = req.Params[0]
		}
		if len(req.Params) > 2 {
			if pcts, ok := req.Params[2].([]any); ok {
				n.gotPercents = pcts
			}
		}
		n.mu.Unlock()
		resp["result"] = map[string]any{
			"oldestBlock":   n.oldestBlock,
			"baseFeePerGas": n.baseFee,
			"reward":        n.reward,
			"gasUsedRatio":  make([]float64, len(n.reward)),
		}
	default:
		resp["error"] = map[string]any{"code": -32601, "message": "method not found: " + req.Method}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// TestSuggestFees_PercentileTriple_Window_MedianNotLatest is the chain-level proof
// the §5.4 review demands. Fixture: 5 sampled blocks whose 90th-percentile column
// is [1,1,1,1,1000gwei] — the final block is a 1000gwei MEV-bribe outlier. The
// MEDIAN of that column is 1 (the third of five sorted values), so `fast` must be
// 1 — NOT 1000 (which is what taking the latest block would give).
func TestSuggestFees_PercentileTriple_Window_MedianNotLatest(t *testing.T) {
	node := newFeeHistoryNode(t)

	// 5 blocks, each row = [25th, 50th, 90th]. The 90th column has an outlier final
	// block (1000gwei); every other column is a clean constant so the medians are
	// exact and obvious. 1gwei = 0x3b9aca00.
	const g1 = "0x3b9aca00"     // 1 gwei
	const g2 = "0x77359400"     // 2 gwei
	const g3 = "0xb2d05e00"     // 3 gwei
	const gBig = "0xe8d4a51000" // 1000 gwei (the MEV-bribe outlier)
	node.reward = [][]string{
		{g1, g2, g3},
		{g1, g2, g3},
		{g1, g2, g3},
		{g1, g2, g3},
		{g1, g2, gBig}, // outlier 90th in the LATEST block
	}
	// baseFeePerGas has blockCount+1 = 6 entries; the LAST is the next block's base.
	node.baseFee = []string{g1, g1, g1, g1, g1, g2} // next base fee = 2gwei
	node.oldestBlock = "0x10"

	cc, err := Dial(context.Background(), Options{
		URL:           node.URL,
		Network:       "mainnet",
		ExpectChainID: big.NewInt(1),
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cc.Close()

	const wantBlocks = 20
	fees, err := cc.SuggestFees(context.Background(), wantBlocks)
	if err != nil {
		t.Fatalf("SuggestFees: %v", err)
	}

	// ── (1) the percentile triple is exactly [25,50,90] ──
	if got := node.gotPercents; len(got) != 3 ||
		toF(got[0]) != 25 || toF(got[1]) != 50 || toF(got[2]) != 90 {
		t.Errorf("feeHistory percentiles = %v, want [25 50 90]", got)
	}

	// ── (2) the block window is the caller-supplied 20 (not a hardcoded 5) ──
	if got := node.gotBlocks; toF(got) != float64(wantBlocks) {
		t.Errorf("feeHistory block count = %v, want %d (from config, not a const)", got, wantBlocks)
	}

	// ── (3) MEDIAN, not latest: fast = median([3,3,3,3,1000])gwei = 3gwei ──
	wantFast := big.NewInt(3_000_000_000)
	if fees.PriorityFast.Cmp(wantFast) != 0 {
		t.Errorf("fast tip = %s, want %s (median of the 90th column, NOT the 1000gwei latest block)",
			fees.PriorityFast, wantFast)
	}
	// slow = median of the 25th column ([1,1,1,1,1]) = 1gwei; normal = 2gwei.
	if fees.PrioritySlow.Cmp(big.NewInt(1_000_000_000)) != 0 {
		t.Errorf("slow tip = %s, want 1gwei (median of the 25th column)", fees.PrioritySlow)
	}
	if fees.PriorityNormal.Cmp(big.NewInt(2_000_000_000)) != 0 {
		t.Errorf("normal tip = %s, want 2gwei (median of the 50th column)", fees.PriorityNormal)
	}
	// next-block base fee is the LAST baseFeePerGas entry (2gwei).
	if fees.BaseFee.Cmp(big.NewInt(2_000_000_000)) != 0 {
		t.Errorf("base fee = %s, want 2gwei (the next-block base, last entry)", fees.BaseFee)
	}

	// ── one feeHistory call total (the §5.4 single-call contract) ──
	if node.feeCalls != 1 {
		t.Errorf("eth_feeHistory called %d times, want 1", node.feeCalls)
	}
}

// toF coerces a JSON number/string param to a float64 for assertions (geth encodes
// the block count + percentiles as hex strings for the count and JSON numbers for
// the percentiles; this normalizes both).
func toF(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		// hex (block count) — geth sends the count as "0x14".
		if len(t) > 2 && (t[1] == 'x' || t[1] == 'X') {
			n := new(big.Int)
			if _, ok := n.SetString(t[2:], 16); ok {
				f, _ := new(big.Float).SetInt(n).Float64()
				return f
			}
		}
		// plain decimal string fallback.
		f := new(big.Float)
		if _, ok := f.SetString(t); ok {
			out, _ := f.Float64()
			return out
		}
	}
	return -1
}
