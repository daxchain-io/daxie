package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// token_test.go covers the M5 token-registry use cases + the asset-resolution
// chokepoint + the allowance read against the chain fake + temp dirs. The
// non-negotiable it pins hardest: alias resolution is REGISTRY-ONLY — an
// unregistered name is ref.not_found, NEVER an on-chain symbol() lookup.

// ERC-20 read selectors (the first 4 keccak bytes), for the fake's CallContract
// dispatch. They mirror erc's internal selectors; pinned here so the fake answers
// the right read without importing erc internals.
var (
	selDecimals  = []byte{0x31, 0x3c, 0xe5, 0x67} // decimals()
	selSymbol    = []byte{0x95, 0xd8, 0x9b, 0x41} // symbol()
	selBalanceOf = []byte{0x70, 0xa0, 0x82, 0x31} // balanceOf(address)
	selAllowance = []byte{0xdd, 0x62, 0xed, 0x3e} // allowance(address,address)
)

// abiWord left-pads a big.Int to a 32-byte ABI word.
func abiWord(v *big.Int) []byte { return common.LeftPadBytes(v.Bytes(), 32) }

// abiString encodes s as a canonical ABI dynamic string return (offset 0x20,
// length, then padded bytes).
func abiString(s string) []byte {
	out := make([]byte, 0, 96)
	out = append(out, abiWord(big.NewInt(0x20))...)
	out = append(out, abiWord(big.NewInt(int64(len(s))))...)
	b := []byte(s)
	for len(b)%32 != 0 {
		b = append(b, 0)
	}
	return append(out, b...)
}

// hasSelector reports whether data begins with sel.
func hasSelector(data, sel []byte) bool {
	if len(data) < 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		if data[i] != sel[i] {
			return false
		}
	}
	return true
}

// erc20Fake returns a fake chain client whose CallContract answers the ERC-20
// metadata reads: decimals=dec, symbol=sym, balanceOf=bal, allowance=allow.
func erc20Fake(dec uint8, sym string, bal, allow *big.Int) *fake.Client {
	f := fake.New()
	f.CallContractFn = func(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
		switch {
		case hasSelector(msg.Data, selDecimals):
			return abiWord(big.NewInt(int64(dec))), nil
		case hasSelector(msg.Data, selSymbol):
			return abiString(sym), nil
		case hasSelector(msg.Data, selBalanceOf):
			if bal == nil {
				return abiWord(big.NewInt(0)), nil
			}
			return abiWord(bal), nil
		case hasSelector(msg.Data, selAllowance):
			if allow == nil {
				return abiWord(big.NewInt(0)), nil
			}
			return abiWord(allow), nil
		default:
			return nil, nil
		}
	}
	return f
}

func TestResolveAsset_AliasRegistryOnly_MissIsNotFound(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: fake.New()})
	cc := fake.New()

	// An unregistered alias MUST be ref.not_found — NEVER an on-chain symbol() lookup
	// (the anti-spoofing wall, §7.8). The fake records every chain call; assert none
	// was a symbol() read.
	_, err := svc.resolveAsset(context.Background(), cc, "mainnet", "totally-not-registered")
	if err == nil {
		t.Fatal("resolveAsset of an unregistered alias must error (ref.not_found)")
	}
	if de := domain.AsError(err); de.Code != domain.CodeRefNotFound {
		t.Fatalf("code = %q, want ref.not_found", de.Code)
	}
	for _, call := range cc.Calls {
		if call.Method == "CallContract" {
			t.Fatalf("resolveAsset did an on-chain CallContract for an unregistered alias — symbol-spoofing wall breached")
		}
	}
}

func TestResolveAsset_BundledMajor(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: fake.New()})
	// usdc is a compiled-in mainnet major; it resolves registry-only with NO chain read.
	ra, err := svc.resolveAsset(context.Background(), nil, "mainnet", "USDC")
	if err != nil {
		t.Fatalf("resolveAsset USDC: %v", err)
	}
	if ra.alias != "usdc" || ra.decimals != 6 || !ra.bundled {
		t.Fatalf("bundled usdc = %+v, want alias usdc decimals 6 bundled", ra)
	}
}

func TestResolveAsset_RawAddressReadsDecimals(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: fake.New()})
	cc := erc20Fake(18, "TST", nil, nil)
	contract := someAddr(0x70)
	ra, err := svc.resolveAsset(context.Background(), cc, "mainnet", contract.Hex())
	if err != nil {
		t.Fatalf("resolveAsset raw 0x: %v", err)
	}
	if ra.contract != contract || ra.decimals != 18 {
		t.Fatalf("raw asset = %+v, want contract %s decimals 18", ra, contract.Hex())
	}
	if ra.alias != "" {
		t.Errorf("an unregistered raw address must have no alias, got %q", ra.alias)
	}
}

func TestTokenAddListResolve_RoundTrip(t *testing.T) {
	cc := erc20Fake(6, "MYC", nil, nil)
	svc := openWithProvider(t, &stubProvider{cc: cc})
	contract := someAddr(0x42)

	// Add with an explicit --name.
	res, err := svc.TokenAdd(context.Background(), domain.LocalCLI(), domain.TokenAddRequest{
		Contract: contract.Hex(), Name: "mytoken", Network: "mainnet",
	})
	if err != nil {
		t.Fatalf("TokenAdd: %v", err)
	}
	if res.Token.Alias != "mytoken" || res.Token.Decimals != 6 {
		t.Fatalf("added row = %+v, want alias mytoken decimals 6", res.Token)
	}

	// It now resolves registry-only (no chain read needed for the alias).
	ra, err := svc.resolveAsset(context.Background(), nil, "mainnet", "MyToken") // case-insensitive
	if err != nil {
		t.Fatalf("resolveAsset added alias: %v", err)
	}
	if ra.contract != contract || ra.alias != "mytoken" {
		t.Fatalf("resolved = %+v, want contract %s alias mytoken", ra, contract.Hex())
	}

	// List shows it alongside the bundled majors.
	list, err := svc.TokenList(context.Background(), domain.LocalCLI(), domain.TokenListRequest{Network: "mainnet"})
	if err != nil {
		t.Fatalf("TokenList: %v", err)
	}
	found := false
	for _, row := range list.Tokens {
		if row.Alias == "mytoken" && !row.Bundled {
			found = true
		}
	}
	if !found {
		t.Fatalf("token list missing the added 'mytoken' file entry: %+v", list.Tokens)
	}
}

func TestTokenAdd_CollisionWithBundledRequiresName(t *testing.T) {
	cc := erc20Fake(6, "usdc", nil, nil) // symbol folds to "usdc", colliding with the bundled major
	svc := openWithProvider(t, &stubProvider{cc: cc})
	_, err := svc.TokenAdd(context.Background(), domain.LocalCLI(), domain.TokenAddRequest{
		Contract: someAddr(0x99).Hex(), Network: "mainnet", // no --name ⇒ defaults to "usdc"
	})
	if err == nil {
		t.Fatal("adding a token whose default alias collides with a bundled major must require --name")
	}
	if de := domain.AsError(err); de.Code != domain.CodeUsage+".duplicate" {
		t.Fatalf("code = %q, want usage.duplicate", de.Code)
	}
}

func TestTokenAllowance_Read(t *testing.T) {
	allow := big.NewInt(1_000_000) // 1 USDC at 6 decimals
	cc := erc20Fake(6, "TST", nil, allow)
	svc := openWithProvider(t, &stubProvider{cc: cc})
	owner := someAddr(0x01)
	spender := someAddr(0x02)
	contract := someAddr(0x42)

	res, err := svc.TokenAllowance(context.Background(), domain.LocalCLI(), domain.AllowanceRequest{
		Token:   contract.Hex(),
		Owner:   owner.Hex(),
		Spender: spender.Hex(),
		Network: "mainnet",
	}, nil)
	if err != nil {
		t.Fatalf("TokenAllowance: %v", err)
	}
	if res.Allowance != "1000000" {
		t.Errorf("allowance base = %q, want 1000000", res.Allowance)
	}
	if res.AllowanceFormatted != "1" {
		t.Errorf("allowance formatted = %q, want 1", res.AllowanceFormatted)
	}
	if res.Unlimited {
		t.Errorf("a bounded allowance must not be flagged unlimited")
	}
}
