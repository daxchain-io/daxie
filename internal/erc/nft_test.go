package erc

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

var nftAddr = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")

// boolWord encodes a Go bool as a 32-byte ABI bool return word.
func boolWord(b bool) []byte {
	w := make([]byte, 32)
	if b {
		w[31] = 1
	}
	return w
}

// erc165Fake builds a fake whose supportsInterface(bytes4) returns true for
// exactly the interface ids in supported (keyed by their hex), and false for any
// other id — so DetectKind exercises the real 721-then-1155 probe order. A nil/
// empty `supported` makes EVERY supportsInterface return false (a non-NFT).
//
// It dispatches on the calldata: the selector is supportsInterface(bytes4)
// (0x01ffc9a7) and the queried id is the first 4 bytes of the single ABI word
// after the selector (bytes4 is left-aligned).
func erc165Fake(supported map[[4]byte]bool) *fake.Client {
	c := fake.New()
	wantSel := selector(sigSupportsInterface)
	c.CallContractFn = func(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
		if len(msg.Data) != 4+32 || string(msg.Data[:4]) != string(wantSel) {
			return nil, nil // not a supportsInterface call → empty (decodes to "no")
		}
		var id [4]byte
		copy(id[:], msg.Data[4:8]) // bytes4 left-aligned in its word
		return boolWord(supported[id]), nil
	}
	return c
}

func TestSupportsInterfaceTrue(t *testing.T) {
	c := erc165Fake(map[[4]byte]bool{iface721: true})
	ok, err := Ops{}.SupportsInterface(context.Background(), c, nftAddr, iface721)
	if err != nil {
		t.Fatalf("SupportsInterface error: %v", err)
	}
	if !ok {
		t.Fatal("SupportsInterface(721) = false, want true")
	}

	// The eth_call must target the contract with supportsInterface(bytes4) and the
	// id left-aligned in the ABI word.
	calls := c.CallsFor("CallContract")
	if len(calls) != 1 {
		t.Fatalf("CallContract calls = %d, want 1", len(calls))
	}
	msg := calls[0].Args[0].(ethereum.CallMsg)
	if msg.To == nil || *msg.To != nftAddr {
		t.Errorf("CallMsg.To = %v, want %s", msg.To, nftAddr)
	}
	if len(msg.Data) != 4+32 {
		t.Fatalf("supportsInterface calldata len = %d, want %d", len(msg.Data), 4+32)
	}
	if string(msg.Data[:4]) != string(selector(sigSupportsInterface)) {
		t.Errorf("supportsInterface selector = 0x%x, want 0x01ffc9a7", msg.Data[:4])
	}
	// id left-aligned: high 4 bytes carry the id, low 28 are zero.
	if string(msg.Data[4:8]) != string(iface721[:]) {
		t.Errorf("interface id word high bytes = 0x%x, want 0x%x", msg.Data[4:8], iface721)
	}
	for _, b := range msg.Data[8:] {
		if b != 0 {
			t.Fatalf("interface id word not left-aligned (low bytes nonzero): 0x%x", msg.Data[4:])
		}
	}
}

func TestSupportsInterfaceFalse(t *testing.T) {
	// A 165 contract that supports 721 but not 1155 → false for 1155.
	c := erc165Fake(map[[4]byte]bool{iface721: true})
	ok, err := Ops{}.SupportsInterface(context.Background(), c, nftAddr, iface1155)
	if err != nil {
		t.Fatalf("SupportsInterface error: %v", err)
	}
	if ok {
		t.Fatal("SupportsInterface(1155) = true, want false")
	}
}

func TestSupportsInterfaceEmptyReturnIsFalseNotError(t *testing.T) {
	// A non-165 contract (no supportsInterface) returns empty — reported as false,
	// NOT an error (so DetectKind can fall through to ErrNotNFT).
	c := callReturning(nil)
	ok, err := Ops{}.SupportsInterface(context.Background(), c, nftAddr, iface721)
	if err != nil {
		t.Fatalf("SupportsInterface(empty) err = %v, want nil", err)
	}
	if ok {
		t.Fatal("SupportsInterface(empty) = true, want false")
	}
}

func TestSupportsInterfaceTransportErrorPropagates(t *testing.T) {
	// A genuine transport error must propagate UNCHANGED (not be swallowed to
	// false), so a flaky RPC at `nft add` is retryable, not "not an NFT".
	rpcErr := domain.New(domain.CodeRPCUnreachable, "endpoint down")
	c := fake.New()
	c.Err = rpcErr
	_, err := Ops{}.SupportsInterface(context.Background(), c, nftAddr, iface721)
	if !errors.Is(err, rpcErr) {
		t.Fatalf("SupportsInterface transport err = %v, want the rpc error", err)
	}
}

func TestDetectKind721(t *testing.T) {
	c := erc165Fake(map[[4]byte]bool{iface721: true})
	kind, err := Ops{}.DetectKind(context.Background(), c, nftAddr)
	if err != nil {
		t.Fatalf("DetectKind error: %v", err)
	}
	if kind != Kind721 {
		t.Fatalf("DetectKind = %q, want %q", kind, Kind721)
	}
	// 721 is tried first; once it is true the 1155 probe must NOT run.
	if n := len(c.CallsFor("CallContract")); n != 1 {
		t.Fatalf("DetectKind(721) made %d calls, want 1 (short-circuit after 721)", n)
	}
}

func TestDetectKind1155(t *testing.T) {
	c := erc165Fake(map[[4]byte]bool{iface1155: true})
	kind, err := Ops{}.DetectKind(context.Background(), c, nftAddr)
	if err != nil {
		t.Fatalf("DetectKind error: %v", err)
	}
	if kind != Kind1155 {
		t.Fatalf("DetectKind = %q, want %q", kind, Kind1155)
	}
	// 721 (false) then 1155 (true) → two probes.
	if n := len(c.CallsFor("CallContract")); n != 2 {
		t.Fatalf("DetectKind(1155) made %d calls, want 2", n)
	}
}

func TestDetectKindNeitherIsErrNotNFT(t *testing.T) {
	// A contract that supports neither interface (an EOA, a plain ERC-20, a non-165
	// contract) → ErrNotNFT (exit 2 usage), never a silent kind.
	c := erc165Fake(nil)
	kind, err := Ops{}.DetectKind(context.Background(), c, nftAddr)
	if !errors.Is(err, ErrNotNFT) {
		t.Fatalf("DetectKind(neither) err = %v, want ErrNotNFT", err)
	}
	if kind != KindUnknown {
		t.Fatalf("DetectKind(neither) kind = %q, want KindUnknown", kind)
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != "usage.not_nft" {
		t.Fatalf("err code = %v, want usage.not_nft", err)
	}
	if de.Exit != domain.ExitUsage {
		t.Fatalf("ErrNotNFT exit = %d, want %d (usage)", de.Exit, domain.ExitUsage)
	}
}

func TestDetectKindTransportErrorPropagates(t *testing.T) {
	// A transport error during detection propagates (so `nft add` fails retryable,
	// not "not an NFT").
	rpcErr := domain.New(domain.CodeRPCUnreachable, "endpoint down")
	c := fake.New()
	c.Err = rpcErr
	_, err := Ops{}.DetectKind(context.Background(), c, nftAddr)
	if !errors.Is(err, rpcErr) {
		t.Fatalf("DetectKind transport err = %v, want the rpc error", err)
	}
	if errors.Is(err, ErrNotNFT) {
		t.Fatal("transport error must not be relabeled ErrNotNFT")
	}
}

func TestBalanceOf1155(t *testing.T) {
	c := callReturning(word32(big.NewInt(7)))
	got, err := Ops{}.BalanceOf1155(context.Background(), c, nftAddr, ownerAddr, big.NewInt(42))
	if err != nil {
		t.Fatalf("BalanceOf1155 error: %v", err)
	}
	if got.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("BalanceOf1155 = %s, want 7", got)
	}

	// Calldata must be balanceOf(owner, 42): selector || owner word || id word.
	calls := c.CallsFor("CallContract")
	msg := calls[0].Args[0].(ethereum.CallMsg)
	wantData := append(selector(sigBalanceOf1155), common.LeftPadBytes(ownerAddr.Bytes(), 32)...)
	wantData = append(wantData, common.LeftPadBytes(big.NewInt(42).Bytes(), 32)...)
	if string(msg.Data) != string(wantData) {
		t.Errorf("balanceOf(address,uint256) calldata = 0x%x, want 0x%x", msg.Data, wantData)
	}
	// The selector must be the 1155 two-arg balanceOf, NOT the ERC-20 one-arg.
	if string(msg.Data[:4]) == string(selector(sigBalanceOf)) {
		t.Fatal("BalanceOf1155 used the ERC-20 balanceOf(address) selector, want balanceOf(address,uint256)")
	}
}

func TestBalanceOf1155BigID(t *testing.T) {
	// IDs exceed 2^53; the read must round-trip a huge id intact (math/big).
	bigID, _ := new(big.Int).SetString("1606938044258990275541962092341162602522202993782792835301376", 10) // 2^200
	c := callReturning(word32(big.NewInt(3)))
	if _, err := (Ops{}).BalanceOf1155(context.Background(), c, nftAddr, ownerAddr, bigID); err != nil {
		t.Fatalf("BalanceOf1155(2^200) error: %v", err)
	}
	msg := c.CallsFor("CallContract")[0].Args[0].(ethereum.CallMsg)
	gotID := new(big.Int).SetBytes(msg.Data[4+32 : 4+64])
	if gotID.Cmp(bigID) != 0 {
		t.Fatalf("id word = %s, want %s (2^200 must survive)", gotID, bigID)
	}
}

func TestBalanceOf1155EmptyReturnIsErrNotNFT(t *testing.T) {
	c := callReturning(nil)
	_, err := Ops{}.BalanceOf1155(context.Background(), c, nftAddr, ownerAddr, big.NewInt(1))
	if !errors.Is(err, ErrNotNFT) {
		t.Fatalf("BalanceOf1155(empty) err = %v, want ErrNotNFT", err)
	}
}

func TestBalanceOf1155TransportErrorPropagates(t *testing.T) {
	rpcErr := domain.New(domain.CodeRPCUnreachable, "endpoint down")
	c := fake.New()
	c.Err = rpcErr
	_, err := Ops{}.BalanceOf1155(context.Background(), c, nftAddr, ownerAddr, big.NewInt(1))
	if !errors.Is(err, rpcErr) {
		t.Fatalf("BalanceOf1155 transport err = %v, want the rpc error", err)
	}
}
