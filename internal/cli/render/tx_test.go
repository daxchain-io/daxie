package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// The hash is the essential output of a send and prints even under --quiet (like
// the balance value); the context lines are suppressed by --quiet.
func TestTxResultHashIsEssential(t *testing.T) {
	r := domain.TxResult{
		Hash:      "0xdeadbeef",
		From:      common.HexToAddress("0x1111111111111111111111111111111111111111"),
		To:        domain.Dest{Address: common.HexToAddress("0x2222222222222222222222222222222222222222"), Name: "exchange"},
		AmountWei: "500000000000000000",
		Nonce:     7,
		Status:    domain.TxStatusConfirmed,
		Gas:       domain.GasResult{GasLimit: 21000, MaxFeePerGas: "30000000000", PriorityFee: "1000000000"},
		JournalID: "01HX",
	}

	var quiet bytes.Buffer
	TxResult(&quiet, Mode{Quiet: true}, r)
	if !strings.HasPrefix(quiet.String(), "0xdeadbeef\n") {
		t.Errorf("quiet TxResult must still print the hash; got %q", quiet.String())
	}
	if strings.Contains(quiet.String(), "nonce") {
		t.Errorf("quiet TxResult leaked a context line: %q", quiet.String())
	}

	var full bytes.Buffer
	TxResult(&full, Mode{}, r)
	out := full.String()
	for _, want := range []string{"0xdeadbeef", "exchange", "nonce:   7", "status:  confirmed", "gas-limit: 21000"} {
		if !strings.Contains(out, want) {
			t.Errorf("TxResult human missing %q in:\n%s", want, out)
		}
	}
}

// A legacy tx shows gas-price, not the 1559 max-fee/priority columns.
func TestTxResultLegacyGasLines(t *testing.T) {
	r := domain.TxResult{
		Hash:   "0xabc",
		Status: domain.TxStatusPending,
		Gas:    domain.GasResult{Legacy: true, GasLimit: 21000, GasPrice: "20000000000"},
	}
	var buf bytes.Buffer
	TxResult(&buf, Mode{}, r)
	out := buf.String()
	if !strings.Contains(out, "gas-price: 20000000000 wei") {
		t.Errorf("legacy TxResult missing gas-price line:\n%s", out)
	}
	if strings.Contains(out, "max-fee:") {
		t.Errorf("legacy TxResult must not print a 1559 max-fee line:\n%s", out)
	}
}

// GasQuotes prints the base fee headline and one row per speed; --legacy switches
// the columns to gas-price.
func TestGasQuotes(t *testing.T) {
	r := domain.GasQuotesResult{
		Network: "mainnet",
		BaseFee: "12000000000",
		Slow:    domain.GasResult{MaxFeePerGas: "20000000000", PriorityFee: "500000000"},
		Normal:  domain.GasResult{MaxFeePerGas: "30000000000", PriorityFee: "1000000000"},
		Fast:    domain.GasResult{MaxFeePerGas: "45000000000", PriorityFee: "2000000000"},
	}
	var buf bytes.Buffer
	GasQuotes(&buf, Mode{}, r)
	out := buf.String()
	for _, want := range []string{"base fee: 12000000000 wei", "slow", "normal", "fast", "30000000000"} {
		if !strings.Contains(out, want) {
			t.Errorf("GasQuotes missing %q in:\n%s", want, out)
		}
	}

	// Legacy view: gas-price column populated, no 1559 columns.
	rl := domain.GasQuotesResult{
		Network: "polygon", Legacy: true, BaseFee: "",
		Slow:   domain.GasResult{Legacy: true, GasPrice: "30000000000"},
		Normal: domain.GasResult{Legacy: true, GasPrice: "35000000000"},
		Fast:   domain.GasResult{Legacy: true, GasPrice: "50000000000"},
	}
	buf.Reset()
	GasQuotes(&buf, Mode{}, rl)
	if !strings.Contains(buf.String(), "35000000000") {
		t.Errorf("legacy GasQuotes missing a gas-price value:\n%s", buf.String())
	}
}

// ContactsTable and Contact render the §7.8 fields.
func TestContactsRender(t *testing.T) {
	rows := []domain.ContactRow{
		{Name: "exchange", Address: "0xabc"},
		{Name: "vitalik", Address: "0xd8da", ENS: "vitalik.eth", PinnedAt: "2026-06-15T10:00:00Z"},
	}
	var tbl bytes.Buffer
	ContactsTable(&tbl, Mode{}, rows)
	for _, want := range []string{"NAME", "exchange", "vitalik", "vitalik.eth"} {
		if !strings.Contains(tbl.String(), want) {
			t.Errorf("ContactsTable missing %q in:\n%s", want, tbl.String())
		}
	}

	var one bytes.Buffer
	Contact(&one, Mode{}, rows[1])
	if !strings.HasPrefix(one.String(), "0xd8da\n") {
		t.Errorf("Contact must print the address as the essential first line; got %q", one.String())
	}
	if !strings.Contains(one.String(), "ens:  vitalik.eth") {
		t.Errorf("Contact missing ens line:\n%s", one.String())
	}
}

// TestResultSingleObject confirms Result emits exactly one JSON object for a
// TxResult (no trailing progress) — the §5.9 single-object stdout contract.
func TestResultSingleObject(t *testing.T) {
	r := domain.TxResult{Hash: "0xfeed", Status: domain.TxStatusConfirmed, Nonce: 3}
	var buf bytes.Buffer
	if err := Result(&buf, Mode{JSON: true}, r, nil); err != nil {
		t.Fatalf("Result: %v", err)
	}
	dec := json.NewDecoder(strings.NewReader(buf.String()))
	var first map[string]any
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("first object not valid JSON: %v (%q)", err, buf.String())
	}
	if dec.More() {
		t.Errorf("expected exactly one JSON object on stdout, found more: %q", buf.String())
	}
	if first["hash"] != "0xfeed" {
		t.Errorf("hash = %v, want 0xfeed", first["hash"])
	}
}
