package service

import (
	"context"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain/fake"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ens"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// ens_test.go is the M7 service-layer ENS resolution test: EnsResolve happy/unresolved
// paths, the EnsReverse forward-verify rule, and resolveDest provenance — all driven
// through the chain.Client fake (the single ENS test seam, §2.8/§2.9; there is NO
// ens.Resolver mock, by design). fake.New() reports chain-id 1, so RegistryFor picks
// the canonical mainnet registry; the fake's CallContract answers the ENS reads.

// ENS read selectors (mirrored here so the fake answers without importing ens
// internals). resolver(bytes32)=0x0178b8bf, addr(bytes32)=0x3b3b57de,
// name(bytes32)=0x691f3431 — the EIP-137 set abi_test.go pins as golden.
var (
	selEnsResolver = []byte{0x01, 0x78, 0xb8, 0xbf}
	selEnsAddr     = []byte{0x3b, 0x3b, 0x57, 0xde}
	selEnsName     = []byte{0x69, 0x1f, 0x34, 0x31}
)

// ensFake returns a fake chain client that answers the ENS call sequence: every
// resolver(node) returns the registry itself (combined registry+resolver), addr(node)
// returns addrs[node], and name(node) returns names[node]. node is the 32-byte word
// in the calldata after the selector. Reprogram addrs to stage a re-point (the
// pin-drift scenario).
func ensFake(addrs map[[32]byte]common.Address, names map[[32]byte]string) *fake.Client {
	f := fake.New()
	registrySelf := common.HexToAddress(ens.RegistryAddr)
	f.CallContractFn = func(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
		if len(msg.Data) < 36 {
			return nil, nil
		}
		var node [32]byte
		copy(node[:], msg.Data[4:36])
		switch {
		case hasSelector(msg.Data, selEnsResolver):
			// resolver(node) → the registry itself (it doubles as the public resolver).
			return common.LeftPadBytes(registrySelf.Bytes(), 32), nil
		case hasSelector(msg.Data, selEnsAddr):
			a, ok := addrs[node]
			if !ok {
				return common.LeftPadBytes(common.Address{}.Bytes(), 32), nil // zero ⇒ unresolved
			}
			return common.LeftPadBytes(a.Bytes(), 32), nil
		case hasSelector(msg.Data, selEnsName):
			n := names[node]
			return abiString(n), nil
		default:
			return nil, nil
		}
	}
	return f
}

func TestEnsResolve_HappyPath(t *testing.T) {
	want := common.HexToAddress("0x00000000000000000000000000000000000000a1")
	node := ens.Namehash("vitalik.eth")
	cc := ensFake(map[[32]byte]common.Address{node: want}, nil)
	svc := openWithProvider(t, &stubProvider{cc: cc})

	res, err := svc.EnsResolve(context.Background(), domain.LocalCLI(),
		domain.EnsResolveRequest{Name: "vitalik.eth"}, nil)
	if err != nil {
		t.Fatalf("EnsResolve: %v", err)
	}
	if common.HexToAddress(res.Address) != want {
		t.Fatalf("EnsResolve = %s, want %s", res.Address, want.Hex())
	}
}

func TestEnsResolve_UnresolvedIsRefNotFound(t *testing.T) {
	// No addr for the node ⇒ zero ⇒ ErrUnresolved ⇒ ref.not_found (exit 10), never a
	// zero address echoed as success.
	cc := ensFake(nil, nil)
	svc := openWithProvider(t, &stubProvider{cc: cc})

	_, err := svc.EnsResolve(context.Background(), domain.LocalCLI(),
		domain.EnsResolveRequest{Name: "nope.eth"}, nil)
	assertCode(t, err, domain.CodeRefNotFound)
}

func TestEnsReverse_ForwardVerified(t *testing.T) {
	subject := common.HexToAddress("0x00000000000000000000000000000000000000b2")
	const primary = "vitalik.eth"
	fwdNode := ens.Namehash(primary)
	revName := lowerHexNoPrefix(subject) + ".addr.reverse"
	revNode := ens.Namehash(revName)

	// Forward record points back to the subject ⇒ the reverse name is TRUSTED.
	cc := ensFake(
		map[[32]byte]common.Address{fwdNode: subject},
		map[[32]byte]string{revNode: primary},
	)
	svc := openWithProvider(t, &stubProvider{cc: cc})
	res, err := svc.EnsReverse(context.Background(), domain.LocalCLI(),
		domain.EnsReverseRequest{Address: subject.Hex()}, nil)
	if err != nil {
		t.Fatalf("EnsReverse: %v", err)
	}
	if !res.Verified || res.Name != primary {
		t.Fatalf("EnsReverse = %+v, want verified %q", res, primary)
	}
}

func TestEnsReverse_UntrustedWhenForwardMismatch(t *testing.T) {
	subject := common.HexToAddress("0x00000000000000000000000000000000000000b3")
	other := common.HexToAddress("0x00000000000000000000000000000000000000b4")
	const primary = "evil.eth"
	fwdNode := ens.Namehash(primary)
	revNode := ens.Namehash(lowerHexNoPrefix(subject) + ".addr.reverse")

	// The reverse name forward-resolves to OTHER, not the subject ⇒ NOT trusted ⇒ "".
	cc := ensFake(
		map[[32]byte]common.Address{fwdNode: other},
		map[[32]byte]string{revNode: primary},
	)
	svc := openWithProvider(t, &stubProvider{cc: cc})
	res, err := svc.EnsReverse(context.Background(), domain.LocalCLI(),
		domain.EnsReverseRequest{Address: subject.Hex()}, nil)
	if err != nil {
		t.Fatalf("EnsReverse: %v", err)
	}
	if res.Verified || res.Name != "" {
		t.Fatalf("EnsReverse = %+v, want unverified empty name (forward mismatch)", res)
	}
}

func TestEnsReverse_BadAddressIsUsage(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: fake.New()})
	_, err := svc.EnsReverse(context.Background(), domain.LocalCLI(),
		domain.EnsReverseRequest{Address: "not-hex"}, nil)
	de := domain.AsError(err)
	if de.Exit != domain.ExitUsage {
		t.Fatalf("bad reverse address exit = %d, want 2 (usage)", de.Exit)
	}
}

func TestResolveDest_ENSProvenance(t *testing.T) {
	want := common.HexToAddress("0x00000000000000000000000000000000000000c5")
	node := ens.Namehash("payee.eth")
	cc := ensFake(map[[32]byte]common.Address{node: want}, nil)
	svc := openWithProvider(t, &stubProvider{cc: cc})

	dest, err := svc.resolveDest(context.Background(), ChainRequest{}, "payee.eth")
	if err != nil {
		t.Fatalf("resolveDest ENS: %v", err)
	}
	if dest.Address != want || dest.Via != "ens" || dest.ENSName != "payee.eth" {
		t.Fatalf("resolveDest = %+v, want addr=%s via=ens ens_name=payee.eth", dest, want.Hex())
	}
}

func TestResolveDest_LiteralProvenance(t *testing.T) {
	svc := openWithProvider(t, &stubProvider{cc: fake.New()})
	dest, err := svc.resolveDest(context.Background(), ChainRequest{}, "0x00000000000000000000000000000000000000c6")
	if err != nil {
		t.Fatalf("resolveDest literal: %v", err)
	}
	if dest.Via != "literal" || dest.ENSName != "" {
		t.Fatalf("resolveDest literal = %+v, want via=literal no ens_name", dest)
	}
}

// TestResolvePinned_DriftViaChainFake is the §2.9 ENS pin-refusal UNIT test driven
// by the chain.Client fake returning X at allow-time, Y at send-time: ResolvePinned
// returns (X,nil) while the name still points at X, then (Y, ens.ErrPinChanged) after
// the fake is reprogrammed to Y. This is the seam the policy stage-4 gate consumes —
// proven WITHOUT a network and WITHOUT an ens.Resolver interface.
func TestResolvePinned_DriftViaChainFake(t *testing.T) {
	x := common.HexToAddress("0x00000000000000000000000000000000000000d7")
	y := common.HexToAddress("0x00000000000000000000000000000000000000d8")
	node := ens.Namehash("drift.eth")
	addrs := map[[32]byte]common.Address{node: x}
	cc := ensFake(addrs, nil)
	var r ens.Resolver

	// Allow-time: the name points at X; ResolvePinned(name, X) is satisfied.
	got, err := r.ResolvePinned(context.Background(), cc, "drift.eth", x)
	if err != nil || got != x {
		t.Fatalf("ResolvePinned matching = (%s,%v), want (%s,nil)", got.Hex(), err, x.Hex())
	}

	// Re-point the name to Y (same fake, reprogrammed map). ResolvePinned(name, X) now
	// returns (Y, ErrPinChanged) — the drift the stage-4 gate refuses.
	addrs[node] = y
	got, err = r.ResolvePinned(context.Background(), cc, "drift.eth", x)
	if err == nil {
		t.Fatalf("ResolvePinned after re-point returned nil error, want ErrPinChanged (got %s)", got.Hex())
	}
}

// lowerHexNoPrefix returns the lowercase 40-hex of an address with no 0x prefix
// (the label used to build the reverse node "<hex>.addr.reverse").
func lowerHexNoPrefix(a common.Address) string {
	const hexd = "0123456789abcdef"
	b := a.Bytes()
	out := make([]byte, 40)
	for i, by := range b {
		out[i*2] = hexd[by>>4]
		out[i*2+1] = hexd[by&0x0f]
	}
	return string(out)
}
