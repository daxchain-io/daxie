package journal

import (
	"encoding/json"
	"strings"
	"testing"
)

// the §5.6 example record, VERBATIM, as the canonical round-trip fixture. If a field
// name or shape drifts from the design, this fails — the schema is LAW.
const designExample = `{
  "v": 1, "id": "01J9ZD3A6K2Q4XH8YQ0VBM5T2N", "seq": 3, "ts": "2026-06-15T17:04:05.123Z",
  "chain_id": 1, "network": "mainnet", "kind": "erc20-transfer", "status": "pending",
  "source": "cli", "from": "0x52ae...", "to": "0xdef1...", "nonce": 187,
  "tx_hash": "0x9c1f...", "raw_tx": "0x02f8b1...", "value_wei": "0",
  "asset": { "kind": "erc20", "contract": "0xa0b8...", "alias": "USDC",
    "decimals": 6, "amount": "25000000", "token_id": null },
  "fees": { "type": "eip1559", "gas_limit": 65000,
    "max_fee_per_gas": "30000000000", "max_priority_fee_per_gas": "1000000000",
    "gas_price": null, "speed": "normal" },
  "reservation_id": "01J9ZD...", "worst_case_gas_wei": "1950000000000000",
  "replaces": null, "replaced_by": null,
  "receipt": { "block_number": 19000123, "block_hash": "0x77aa...",
    "gas_used": 48211, "effective_gas_price": "12100000000", "status": 1 },
  "error": null, "rpc": "mainnet-alchemy"
}`

func TestRecordUnmarshalDesignExample(t *testing.T) {
	t.Parallel()
	var r Record
	if err := json.Unmarshal([]byte(designExample), &r); err != nil {
		t.Fatalf("unmarshal §5.6 example: %v", err)
	}

	if r.V != 1 {
		t.Errorf("v = %d, want 1", r.V)
	}
	if r.ID != "01J9ZD3A6K2Q4XH8YQ0VBM5T2N" {
		t.Errorf("id = %q", r.ID)
	}
	if r.Seq != 3 {
		t.Errorf("seq = %d, want 3", r.Seq)
	}
	if r.ChainID != 1 || r.Network != "mainnet" {
		t.Errorf("chain = %d / %q", r.ChainID, r.Network)
	}
	if r.Kind != KindERC20Transfer {
		t.Errorf("kind = %q, want %q", r.Kind, KindERC20Transfer)
	}
	if r.Status != StatusPending {
		t.Errorf("status = %q", r.Status)
	}
	if r.Nonce != 187 {
		t.Errorf("nonce = %d", r.Nonce)
	}
	if r.ValueWei != "0" {
		t.Errorf("value_wei = %q", r.ValueWei)
	}
	if r.Asset.Kind != "erc20" || r.Asset.Amount == nil || *r.Asset.Amount != "25000000" {
		t.Errorf("asset = %+v", r.Asset)
	}
	if r.Asset.Decimals == nil || *r.Asset.Decimals != 6 {
		t.Errorf("asset.decimals = %v", r.Asset.Decimals)
	}
	if r.Asset.TokenID != nil {
		t.Errorf("asset.token_id should be nil, got %v", *r.Asset.TokenID)
	}
	if r.Fees.Type != "eip1559" || r.Fees.GasLimit != 65000 {
		t.Errorf("fees = %+v", r.Fees)
	}
	if r.Fees.GasPrice != nil {
		t.Errorf("fees.gas_price should be nil for eip1559")
	}
	if r.Fees.MaxFeePerGas == nil || *r.Fees.MaxFeePerGas != "30000000000" {
		t.Errorf("fees.max_fee_per_gas = %v", r.Fees.MaxFeePerGas)
	}
	if r.WorstCaseGasWei != "1950000000000000" {
		t.Errorf("worst_case_gas_wei = %q", r.WorstCaseGasWei)
	}
	if r.Replaces != nil || r.ReplacedBy != nil {
		t.Errorf("replaces/replaced_by should be nil")
	}
	if r.Receipt == nil || r.Receipt.BlockNumber != 19000123 || r.Receipt.Status != 1 {
		t.Errorf("receipt = %+v", r.Receipt)
	}
	if r.Error != nil {
		t.Errorf("error should be nil")
	}
	if r.RPC != "mainnet-alchemy" {
		t.Errorf("rpc = %q", r.RPC)
	}
}

func TestRecordRoundTripPreservesFieldNames(t *testing.T) {
	t.Parallel()
	var r Record
	if err := json.Unmarshal([]byte(designExample), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	b, err := json.Marshal(&r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(b)

	// The exact §5.6 wire field names must all be present (verbatim).
	for _, name := range []string{
		`"v":`, `"id":`, `"seq":`, `"ts":`, `"chain_id":`, `"network":`, `"kind":`,
		`"status":`, `"source":`, `"from":`, `"to":`, `"nonce":`, `"tx_hash":`,
		`"raw_tx":`, `"value_wei":`, `"asset":`, `"fees":`, `"reservation_id":`,
		`"worst_case_gas_wei":`, `"replaces":`, `"replaced_by":`, `"receipt":`,
		`"error":`, `"rpc":`,
		// nested
		`"max_fee_per_gas":`, `"max_priority_fee_per_gas":`, `"gas_price":`,
		`"effective_gas_price":`, `"block_number":`, `"block_hash":`, `"gas_used":`,
	} {
		if !strings.Contains(out, name) {
			t.Errorf("round-trip JSON missing field %s\ngot: %s", name, out)
		}
	}

	// null-valued required pointers must serialize as JSON null (not be omitted) so a
	// reader can distinguish "unset" — replaces/replaced_by/receipt/error/amount have
	// no omitempty in the schema.
	for _, nullField := range []string{`"replaces":null`, `"replaced_by":null`, `"error":null`} {
		if !strings.Contains(out, nullField) {
			t.Errorf("expected %s in round-trip output\ngot: %s", nullField, out)
		}
	}
}

func TestStatusTerminalAndNonceConsumption(t *testing.T) {
	t.Parallel()
	terminal := []Status{StatusConfirmed, StatusReverted, StatusReplaced, StatusFailed}
	nonTerminal := []Status{StatusSigned, StatusBroadcast, StatusPending, StatusMined, StatusDropped}

	for _, s := range terminal {
		if !s.IsTerminal() {
			t.Errorf("%q should be terminal", s)
		}
	}
	for _, s := range nonTerminal {
		if s.IsTerminal() {
			t.Errorf("%q should NOT be terminal", s)
		}
	}

	// Only `failed` did not consume an on-chain nonce (a refused broadcast).
	if StatusFailed.consumesNonce() {
		t.Errorf("failed must NOT consume a nonce")
	}
	for _, s := range append(append([]Status{}, terminal...), nonTerminal...) {
		if s == StatusFailed {
			continue
		}
		if !s.consumesNonce() {
			t.Errorf("%q should consume a nonce (only failed does not)", s)
		}
	}
}
