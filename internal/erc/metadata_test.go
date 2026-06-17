package erc

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

var (
	tokenAddr = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48") // USDC
	ownerAddr = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
)

// word32 left-pads v to a 32-byte ABI return word.
func word32(v *big.Int) []byte { return common.LeftPadBytes(v.Bytes(), 32) }

// abiString encodes s as a canonical ABI dynamic-string return (offset 0x20,
// length, padded data) — the modern symbol()/name() return shape.
func abiString(s string) []byte {
	out := make([]byte, 0, 96+len(s))
	out = append(out, word32(big.NewInt(0x20))...)             // offset
	out = append(out, word32(big.NewInt(int64(len(s))))...)    // length
	data := common.RightPadBytes([]byte(s), (len(s)+31)/32*32) // padded to 32
	out = append(out, data...)
	return out
}

// bytes32 packs s into a single 32-byte word (legacy symbol() return), trailing
// NUL-padded.
func bytes32(s string) []byte { return common.RightPadBytes([]byte(s), 32) }

// callReturning builds a fake whose CallContract returns a fixed payload and
// records the call so the test can assert the To/Data sent.
func callReturning(payload []byte) *fake.Client {
	c := fake.New()
	c.CallContractFn = func(_ context.Context, _ ethereum.CallMsg, _ *big.Int) ([]byte, error) {
		return payload, nil
	}
	return c
}

func TestDecimals(t *testing.T) {
	c := callReturning(word32(big.NewInt(6)))
	got, err := Ops{}.Decimals(context.Background(), c, tokenAddr)
	if err != nil {
		t.Fatalf("Decimals error: %v", err)
	}
	if got != 6 {
		t.Fatalf("Decimals = %d, want 6", got)
	}

	// The eth_call must target the token contract with the decimals() selector.
	calls := c.CallsFor("CallContract")
	if len(calls) != 1 {
		t.Fatalf("CallContract calls = %d, want 1", len(calls))
	}
	msg := calls[0].Args[0].(ethereum.CallMsg)
	if msg.To == nil || *msg.To != tokenAddr {
		t.Errorf("CallMsg.To = %v, want %s", msg.To, tokenAddr)
	}
	if len(msg.Data) != 4 || string(msg.Data) != string(selector(sigDecimals)) {
		t.Errorf("CallMsg.Data = 0x%x, want decimals() selector 0x313ce567", msg.Data)
	}
}

func TestDecimalsOutOfRange(t *testing.T) {
	// A decimals() return that doesn't fit a uint8 is not a conforming ERC-20.
	c := callReturning(word32(big.NewInt(1000)))
	_, err := Ops{}.Decimals(context.Background(), c, tokenAddr)
	if !errors.Is(err, ErrNotERC20) {
		t.Fatalf("Decimals(1000) err = %v, want ErrNotERC20", err)
	}
}

func TestDecimalsEmptyReturnIsNotERC20(t *testing.T) {
	// An EOA / non-token contract returns empty — mapped to ErrNotERC20 (exit 2).
	c := callReturning(nil)
	_, err := Ops{}.Decimals(context.Background(), c, tokenAddr)
	if !errors.Is(err, ErrNotERC20) {
		t.Fatalf("Decimals(empty) err = %v, want ErrNotERC20", err)
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "usage.not_erc20" {
		t.Fatalf("err code = %v, want usage.not_erc20", err)
	}
	if de.Exit != domain.ExitUsage {
		t.Fatalf("ErrNotERC20 exit = %d, want %d (usage)", de.Exit, domain.ExitUsage)
	}
}

func TestSymbolString(t *testing.T) {
	c := callReturning(abiString("USDC"))
	got, err := Ops{}.Symbol(context.Background(), c, tokenAddr)
	if err != nil {
		t.Fatalf("Symbol error: %v", err)
	}
	if got != "USDC" {
		t.Fatalf("Symbol = %q, want USDC", got)
	}
}

func TestSymbolLegacyBytes32(t *testing.T) {
	// Legacy tokens (MKR/SAI-era) return a bytes32 symbol.
	c := callReturning(bytes32("MKR"))
	got, err := Ops{}.Symbol(context.Background(), c, tokenAddr)
	if err != nil {
		t.Fatalf("Symbol(bytes32) error: %v", err)
	}
	if got != "MKR" {
		t.Fatalf("Symbol(bytes32) = %q, want MKR", got)
	}
}

func TestSymbolEmptyIsNotERC20(t *testing.T) {
	c := callReturning(nil)
	_, err := Ops{}.Symbol(context.Background(), c, tokenAddr)
	if !errors.Is(err, ErrNotERC20) {
		t.Fatalf("Symbol(empty) err = %v, want ErrNotERC20", err)
	}
}

func TestNameString(t *testing.T) {
	c := callReturning(abiString("CryptoPunks"))
	got, err := Ops{}.Name(context.Background(), c, tokenAddr)
	if err != nil {
		t.Fatalf("Name error: %v", err)
	}
	if got != "CryptoPunks" {
		t.Fatalf("Name = %q, want CryptoPunks", got)
	}

	// The eth_call must target the contract with the name() selector 0x06fdde03 —
	// NOT symbol() (the NFT registry's default-alias source differs from tokens').
	calls := c.CallsFor("CallContract")
	if len(calls) != 1 {
		t.Fatalf("CallContract calls = %d, want 1", len(calls))
	}
	msg := calls[0].Args[0].(ethereum.CallMsg)
	if msg.To == nil || *msg.To != tokenAddr {
		t.Errorf("CallMsg.To = %v, want %s", msg.To, tokenAddr)
	}
	if len(msg.Data) != 4 || string(msg.Data) != string(selector(sigName)) {
		t.Errorf("CallMsg.Data = 0x%x, want name() selector 0x06fdde03", msg.Data)
	}
}

func TestNameLegacyBytes32(t *testing.T) {
	// A name() return packed as bytes32 (legacy shape) decodes like symbol().
	c := callReturning(bytes32("Maker"))
	got, err := Ops{}.Name(context.Background(), c, tokenAddr)
	if err != nil {
		t.Fatalf("Name(bytes32) error: %v", err)
	}
	if got != "Maker" {
		t.Fatalf("Name(bytes32) = %q, want Maker", got)
	}
}

func TestNameEmptyIsNotERC20(t *testing.T) {
	c := callReturning(nil)
	_, err := Ops{}.Name(context.Background(), c, tokenAddr)
	if !errors.Is(err, ErrNotERC20) {
		t.Fatalf("Name(empty) err = %v, want ErrNotERC20", err)
	}
}

func TestBalanceOf(t *testing.T) {
	c := callReturning(word32(big.NewInt(1_234_567)))
	got, err := Ops{}.BalanceOf(context.Background(), c, tokenAddr, ownerAddr)
	if err != nil {
		t.Fatalf("BalanceOf error: %v", err)
	}
	if got.Cmp(big.NewInt(1_234_567)) != 0 {
		t.Fatalf("BalanceOf = %s, want 1234567", got)
	}

	// The call must encode balanceOf(owner) — selector || owner left-padded.
	calls := c.CallsFor("CallContract")
	msg := calls[0].Args[0].(ethereum.CallMsg)
	wantData := append(selector(sigBalanceOf), common.LeftPadBytes(ownerAddr.Bytes(), 32)...)
	if string(msg.Data) != string(wantData) {
		t.Errorf("balanceOf calldata = 0x%x, want 0x%x", msg.Data, wantData)
	}
}

func TestOwnerOf(t *testing.T) {
	want := common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	c := callReturning(common.LeftPadBytes(want.Bytes(), 32))
	got, err := Ops{}.OwnerOf(context.Background(), c, tokenAddr, big.NewInt(42))
	if err != nil {
		t.Fatalf("OwnerOf error: %v", err)
	}
	if got != want {
		t.Fatalf("OwnerOf = %s, want %s", got, want)
	}

	// Calldata must be ownerOf(42).
	calls := c.CallsFor("CallContract")
	msg := calls[0].Args[0].(ethereum.CallMsg)
	wantData := append(selector(sigOwnerOf), common.LeftPadBytes(big.NewInt(42).Bytes(), 32)...)
	if string(msg.Data) != string(wantData) {
		t.Errorf("ownerOf calldata = 0x%x, want 0x%x", msg.Data, wantData)
	}
}

// TestMetadataTransportErrorPassThrough confirms a genuine transport/RPC error is
// propagated UNCHANGED (not relabeled ErrNotERC20), so the §5.7 rpc.* taxonomy +
// retryable hint survive. The fake's Err makes EVERY method fail.
func TestMetadataTransportErrorPassThrough(t *testing.T) {
	rpcErr := domain.New(domain.CodeRPCUnreachable, "endpoint down")
	c := fake.New()
	c.Err = rpcErr

	if _, err := (Ops{}).Decimals(context.Background(), c, tokenAddr); !errors.Is(err, rpcErr) {
		t.Errorf("Decimals transport err = %v, want the rpc error", err)
	}
	if _, err := (Ops{}).Symbol(context.Background(), c, tokenAddr); !errors.Is(err, rpcErr) {
		t.Errorf("Symbol transport err = %v, want the rpc error", err)
	}
	if _, err := (Ops{}).BalanceOf(context.Background(), c, tokenAddr, ownerAddr); !errors.Is(err, rpcErr) {
		t.Errorf("BalanceOf transport err = %v, want the rpc error", err)
	}
	if _, err := (Ops{}).OwnerOf(context.Background(), c, tokenAddr, big.NewInt(1)); !errors.Is(err, rpcErr) {
		t.Errorf("OwnerOf transport err = %v, want the rpc error", err)
	}

	// The transport error must NOT be ErrNotERC20 (that's reserved for a clean
	// empty/revert return, not a dialing failure).
	if _, err := (Ops{}).Decimals(context.Background(), c, tokenAddr); errors.Is(err, ErrNotERC20) {
		t.Error("transport error must not be relabeled ErrNotERC20")
	}
}

// compile-time anchor: the fake we drive really is a chain.Client (the seam).
var _ chain.Client = (*fake.Client)(nil)
