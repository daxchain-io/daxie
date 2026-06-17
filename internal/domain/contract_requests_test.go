package domain

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// contract_requests_test.go pins the M10 `daxie contract` wire shapes (the JSON tags
// the --json frontend and the future MCP schema bind against) and asserts the §2.5
// no-float invariant: NO request/result/value field is a float type. Args cross as
// []string; decoded values come back as labeled string DecodedValue.

func TestContractCallResultWireShape(t *testing.T) {
	blk := uint64(123)
	r := ContractCallResult{
		Contract: Dest{Name: "stk", Via: "literal"},
		Method:   "earned",
		Returns:  []DecodedValue{{Name: "amount", Type: "uint256", Value: "42"}},
		Block:    &blk,
		Network:  "mainnet",
	}
	m := mustMarshalMap(t, r)
	for _, k := range []string{"contract", "method", "returns", "block", "network"} {
		if _, ok := m[k]; !ok {
			t.Errorf("ContractCallResult JSON missing key %q (got keys %v)", k, keysOf(m))
		}
	}
	// returns[].value is a STRING (a uint256 exceeds int64 → never a JSON number).
	rets, _ := m["returns"].([]any)
	if len(rets) != 1 {
		t.Fatalf("returns len = %d, want 1", len(rets))
	}
	dv, _ := rets[0].(map[string]any)
	if _, ok := dv["value"].(string); !ok {
		t.Errorf("DecodedValue.value must marshal as a JSON string (got %T)", dv["value"])
	}
}

func TestDecodeResultWireShape(t *testing.T) {
	r := DecodeResult{
		Method:   "approve",
		Selector: "0x095ea7b3",
		Args: []DecodedValue{
			{Name: "spender", Type: "address", Value: "0xabc"},
			{Name: "value", Type: "uint256", Value: "115792089237316195423570985008687907853269984665640564039457584007913129639935"},
		},
	}
	m := mustMarshalMap(t, r)
	for _, k := range []string{"method", "selector", "args"} {
		if _, ok := m[k]; !ok {
			t.Errorf("DecodeResult JSON missing key %q", k)
		}
	}
	// The 2^256-1 value MUST stay a string (a float would lose precision — the bug
	// the no-float rule exists to prevent).
	args, _ := m["args"].([]any)
	last, _ := args[1].(map[string]any)
	if s, ok := last["value"].(string); !ok || !strings.HasPrefix(s, "115792089") {
		t.Errorf("DecodeResult arg value must be the exact decimal STRING, got %v (%T)", last["value"], last["value"])
	}
}

func TestEncodeResultWireShape(t *testing.T) {
	b, err := json.Marshal(EncodeResult{Calldata: "0xdeadbeef"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != `{"calldata":"0xdeadbeef"}` {
		t.Errorf("EncodeResult JSON = %s, want {\"calldata\":\"0xdeadbeef\"}", b)
	}
}

func TestContractLogsResultWireShape(t *testing.T) {
	r := ContractLogsResult{
		Contract: Dest{Name: "stk"},
		Event:    "Staked",
		Logs: []DecodedLog{{
			TxHash: "0xtx", LogIndex: 0, Block: 7, BlockHash: "0xbh", Event: "Staked",
			Args: []DecodedValue{{Name: "user", Type: "address", Value: "0xu"}},
		}},
		Network: "mainnet",
	}
	m := mustMarshalMap(t, r)
	for _, k := range []string{"contract", "event", "logs", "network"} {
		if _, ok := m[k]; !ok {
			t.Errorf("ContractLogsResult JSON missing key %q", k)
		}
	}
}

// TestContractRequestsNoFloatField walks every M10 request/result struct and fails if
// any field is a float kind (§2.5 compile-time decimal-exactness rule). It reuses the
// package-shared recursive assertNoFloat (keys_requests_test.go).
func TestContractRequestsNoFloatField(t *testing.T) {
	types := []any{
		ABISource{}, DecodedValue{},
		ContractCallRequest{}, ContractCallResult{},
		ContractSendRequest{},
		LogFilter{}, DecodedLog{}, ContractLogsRequest{}, ContractLogsResult{},
		EncodeRequest{}, EncodeResult{}, DecodeRequest{}, DecodeResult{},
		ContractRow{}, ContractListResult{}, ContractRemoveResult{},
		ContractAddRequest{}, ContractShowRequest{}, ContractListRequest{}, ContractRemoveRequest{},
	}
	for _, v := range types {
		rt := reflect.TypeOf(v)
		assertNoFloat(t, rt, rt.Name())
	}
}

func mustMarshalMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %T: %v", v, err)
	}
	return m
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
