package ens

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/daxchain-io/daxie/internal/chain/fake"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// ─────────────────────────────────────────────────────────────────────────────
// A small ENS-aware programming layer over the universal chain.Client fake. It is
// the ONLY test seam (§2.8 / §2.1.1: no ens.Resolver interface). We program the
// fake's CallContractFn to answer the four ENS reads — registry.resolver(node),
// resolver.addr(node), resolver.name(node) — by (to, selector, node), exactly as a
// real registry/resolver pair would, so the production Resolve/Reverse code runs
// unchanged against the fake.
// ─────────────────────────────────────────────────────────────────────────────

// mockENS is the programmable state of a mock registry + resolver behind one
// chain.Client fake. It is keyed by node so re-pointing a record (the pin-drift
// test) is a single map write.
type mockENS struct {
	registry common.Address // the registry address the fake answers resolver(node) at
	resolver common.Address // the (single) resolver address records point to

	// addrs[node] = forward address record (resolver.addr(node)).
	addrs map[[32]byte]common.Address
	// names[node] = reverse name record (resolver.name(node)).
	names map[[32]byte]string
	// resolverless, when a node is present, makes registry.resolver(node) return
	// the ZERO address (no resolver set) — distinct from "resolver set but no
	// addr record".
	resolverless map[[32]byte]bool
}

func newMockENS() *mockENS {
	return &mockENS{
		registry:     common.HexToAddress("0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"),
		resolver:     common.HexToAddress("0x4976fb03C32e5B8cfe2b6cCB31c09Ba78EBaBa41"),
		addrs:        map[[32]byte]common.Address{},
		names:        map[[32]byte]string{},
		resolverless: map[[32]byte]bool{},
	}
}

// setAddr programs a forward record name → addr.
func (m *mockENS) setAddr(name string, addr common.Address) {
	m.addrs[Namehash(mustNorm(name))] = addr
}

// setReverseName programs a reverse record addr → name (the resolver.name(rnode)
// return). The caller still controls whether the forward record exists, which is
// what forward-verification checks.
func (m *mockENS) setReverseName(addr common.Address, name string) {
	m.names[reverseNode(addr)] = name
}

// mustNorm normalizes for keying so the test's record keys match what Resolve
// hashes after normalization.
func mustNorm(name string) string {
	n, _, _ := normalize(name)
	return n
}

// callFn returns a CallContractFn that answers the ENS reads from m.
func (m *mockENS) callFn() func(ctx context.Context, msg ethereum.CallMsg, block *big.Int) ([]byte, error) {
	return func(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
		if msg.To == nil || len(msg.Data) < 4+32 {
			return nil, nil // undecodable → empty return (treated as not-resolved)
		}
		sel := msg.Data[:4]
		var node [32]byte
		copy(node[:], msg.Data[4:36])

		switch {
		// registry.resolver(node) → resolver address.
		case *msg.To == m.registry && eqSel(sel, sigResolver):
			if m.resolverless[node] {
				return word(common.Address{}), nil
			}
			// A node we know about (has an addr or a name record) has a resolver.
			if _, ok := m.addrs[node]; ok {
				return word(m.resolver), nil
			}
			if _, ok := m.names[node]; ok {
				return word(m.resolver), nil
			}
			return word(common.Address{}), nil // unknown node: no resolver
		// resolver.addr(node) → forward address.
		case *msg.To == m.resolver && eqSel(sel, sigAddr):
			return word(m.addrs[node]), nil // zero address if no record
		// resolver.name(node) → reverse name (ABI string).
		case *msg.To == m.resolver && eqSel(sel, sigName):
			return abiString(m.names[node]), nil
		default:
			return nil, nil
		}
	}
}

func eqSel(got []byte, sig string) bool {
	want := selector(sig)
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// word left-pads an address to a 32-byte ABI return word.
func word(a common.Address) []byte {
	return common.LeftPadBytes(a.Bytes(), 32)
}

// newENSFake returns a chain.Client fake on mainnet (chain id 1, so RegistryFor
// returns the canonical registry the mock answers at) wired to m's reads.
func newENSFake(m *mockENS) *fake.Client {
	c := fake.New() // chain id 1
	c.CallContractFn = m.callFn()
	return c
}

// ─────────────────────────────────────────────────────────────────────────────
// Forward resolution.
// ─────────────────────────────────────────────────────────────────────────────

func TestResolveHappyPath(t *testing.T) {
	m := newMockENS()
	want := common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045") // vitalik.eth
	m.setAddr("vitalik.eth", want)

	got, err := (&Resolver{}).Resolve(context.Background(), newENSFake(m), "vitalik.eth")
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if got != want {
		t.Fatalf("Resolve(vitalik.eth) = %s, want %s", got.Hex(), want.Hex())
	}
}

// TestResolveCaseInsensitive proves normalization makes resolution case-insensitive
// even though Namehash is not: a record set under the lowercase name resolves for a
// mixed-case query.
func TestResolveCaseInsensitive(t *testing.T) {
	m := newMockENS()
	want := common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
	m.setAddr("vitalik.eth", want)

	got, err := (&Resolver{}).Resolve(context.Background(), newENSFake(m), "Vitalik.ETH")
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if got != want {
		t.Fatalf("Resolve(Vitalik.ETH) = %s, want %s (normalization should case-fold)", got.Hex(), want.Hex())
	}
}

// TestResolveUnresolvedNoResolver: a name with no resolver set is ErrUnresolved.
func TestResolveUnresolvedNoResolver(t *testing.T) {
	m := newMockENS()
	// Mark the node resolverless even though we add an addr (resolverless wins).
	m.setAddr("ghost.eth", common.HexToAddress("0x1111111111111111111111111111111111111111"))
	m.resolverless[Namehash(mustNorm("ghost.eth"))] = true

	_, err := (&Resolver{}).Resolve(context.Background(), newENSFake(m), "ghost.eth")
	if !errors.Is(err, ErrUnresolved) {
		t.Fatalf("Resolve(no resolver) err = %v, want ErrUnresolved", err)
	}
}

// TestResolveUnresolvedNoAddr: a name with a resolver but a zero addr record is
// ErrUnresolved (not a zero-address destination).
func TestResolveUnresolvedNoAddr(t *testing.T) {
	m := newMockENS()
	// A name() record exists (so the node has a resolver) but no addr record.
	m.names[Namehash(mustNorm("namedonly.eth"))] = "namedonly.eth"

	_, err := (&Resolver{}).Resolve(context.Background(), newENSFake(m), "namedonly.eth")
	if !errors.Is(err, ErrUnresolved) {
		t.Fatalf("Resolve(no addr record) err = %v, want ErrUnresolved", err)
	}
}

// TestResolveNoRegistryForNetwork: a chain id with no known registry is
// ErrNoRegistry (a clean refusal, not a transport error).
func TestResolveNoRegistryForNetwork(t *testing.T) {
	m := newMockENS()
	m.setAddr("vitalik.eth", common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
	c := newENSFake(m)
	c.ChainIDVal = big.NewInt(137) // Polygon: no ENS registry in our table

	_, err := (&Resolver{}).Resolve(context.Background(), c, "vitalik.eth")
	if !errors.Is(err, ErrNoRegistry) {
		t.Fatalf("Resolve on unknown network err = %v, want ErrNoRegistry", err)
	}
}

// TestResolveTransportErrorPropagates: a network failure propagates UNCHANGED (it
// is NOT relabeled to ErrUnresolved), so the §5.7 rpc.* taxonomy survives.
func TestResolveTransportErrorPropagates(t *testing.T) {
	m := newMockENS()
	c := newENSFake(m)
	boom := errors.New("rpc: dial tcp: connection refused")
	c.Err = boom // every method (incl. ChainID/CallContract) returns this

	_, err := (&Resolver{}).Resolve(context.Background(), c, "vitalik.eth")
	if !errors.Is(err, boom) {
		t.Fatalf("Resolve transport err = %v, want the underlying transport error", err)
	}
}

// TestResolveEmptyAndMalformedName: an empty/all-dots name is ErrUnresolved (no
// valid node), never a panic or a root-node lookup.
func TestResolveEmptyAndMalformedName(t *testing.T) {
	m := newMockENS()
	c := newENSFake(m)
	for _, bad := range []string{"", ".", "..", ".eth", "a..b"} {
		if _, err := (&Resolver{}).Resolve(context.Background(), c, bad); !errors.Is(err, ErrUnresolved) {
			t.Fatalf("Resolve(%q) err = %v, want ErrUnresolved", bad, err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ResolvePinned — the pin-drift refusal, driven entirely by the chain.Client fake
// (the §2.8 test seam): X at allow-time, Y at send-time → ErrPinChanged.
// ─────────────────────────────────────────────────────────────────────────────

func TestResolvePinnedMatch(t *testing.T) {
	m := newMockENS()
	x := common.HexToAddress("0xAAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa")
	m.setAddr("daxchain.eth", x)

	got, err := (&Resolver{}).ResolvePinned(context.Background(), newENSFake(m), "daxchain.eth", x)
	if err != nil {
		t.Fatalf("ResolvePinned(match) err = %v, want nil", err)
	}
	if got != x {
		t.Fatalf("ResolvePinned(match) = %s, want %s", got.Hex(), x.Hex())
	}
}

// TestResolvePinnedDrift is the load-bearing pin-safety test. The SAME fake is
// programmed to return X at allow-time (pin captured) and then re-pointed to Y;
// a later ResolvePinned against the X pin returns (Y, ErrPinChanged) — the signal
// that becomes policy.denied.pin_drift. NOTHING is signed on this path.
func TestResolvePinnedDrift(t *testing.T) {
	m := newMockENS()
	x := common.HexToAddress("0xAAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa")
	y := common.HexToAddress("0xBBbBBBBBbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")
	c := newENSFake(m)
	r := &Resolver{}

	// Allow-time: name resolves to X; we pin X.
	m.setAddr("daxchain.eth", x)
	pinned, err := r.Resolve(context.Background(), c, "daxchain.eth")
	if err != nil {
		t.Fatalf("allow-time Resolve err = %v", err)
	}
	if pinned != x {
		t.Fatalf("allow-time pin = %s, want %s", pinned.Hex(), x.Hex())
	}

	// Send-time, name unchanged: ResolvePinned passes.
	if got, err := r.ResolvePinned(context.Background(), c, "daxchain.eth", pinned); err != nil || got != x {
		t.Fatalf("ResolvePinned(unchanged) = (%s, %v), want (%s, nil)", got.Hex(), err, x.Hex())
	}

	// RE-POINT the name to Y (an attacker / owner mutates the ENS record).
	m.setAddr("daxchain.eth", y)

	got, err := r.ResolvePinned(context.Background(), c, "daxchain.eth", pinned)
	if !errors.Is(err, ErrPinChanged) {
		t.Fatalf("ResolvePinned(re-pointed) err = %v, want ErrPinChanged", err)
	}
	if got != y {
		t.Fatalf("ResolvePinned(re-pointed) returned addr %s, want the fresh %s so the caller can show pinned-vs-now", got.Hex(), y.Hex())
	}
}

// TestResolvePinnedUnresolvedPropagates: a pinned name that no longer resolves
// returns the resolution error (NOT ErrPinChanged), so the caller still refuses —
// a vanished pinned name is unsafe to send to.
func TestResolvePinnedUnresolvedPropagates(t *testing.T) {
	m := newMockENS()
	x := common.HexToAddress("0xAAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa")
	// No record at all for the name → ErrUnresolved.
	_, err := (&Resolver{}).ResolvePinned(context.Background(), newENSFake(m), "gone.eth", x)
	if !errors.Is(err, ErrUnresolved) {
		t.Fatalf("ResolvePinned(unresolved) err = %v, want ErrUnresolved", err)
	}
	if errors.Is(err, ErrPinChanged) {
		t.Fatal("ResolvePinned must not report drift for an unresolved name")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Reverse — forward-verified. A reverse name is trusted ONLY if it forward-
// resolves back to the address.
// ─────────────────────────────────────────────────────────────────────────────

func TestReverseForwardVerified(t *testing.T) {
	m := newMockENS()
	a := common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
	// Reverse record claims "vitalik.eth"; forward record points back to a.
	m.setReverseName(a, "vitalik.eth")
	m.setAddr("vitalik.eth", a)

	got, err := (&Resolver{}).Reverse(context.Background(), newENSFake(m), a)
	if err != nil {
		t.Fatalf("Reverse err = %v", err)
	}
	if got != "vitalik.eth" {
		t.Fatalf("Reverse(verified) = %q, want \"vitalik.eth\"", got)
	}
}

// TestReverseRejectsUnverified: a reverse name that does NOT forward-resolve back
// to the address is UNTRUSTED — Reverse returns "" (no error). This is the
// anti-spoofing wall: any address can claim any reverse name, so the name is only
// trusted when the forward record agrees.
func TestReverseRejectsUnverified(t *testing.T) {
	m := newMockENS()
	a := common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
	other := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// a claims "vitalik.eth" in reverse, but "vitalik.eth" forward-resolves to
	// `other`, not a → untrusted.
	m.setReverseName(a, "vitalik.eth")
	m.setAddr("vitalik.eth", other)

	got, err := (&Resolver{}).Reverse(context.Background(), newENSFake(m), a)
	if err != nil {
		t.Fatalf("Reverse err = %v, want nil", err)
	}
	if got != "" {
		t.Fatalf("Reverse(forward points elsewhere) = %q, want \"\" (untrusted)", got)
	}
}

// TestReverseRejectsNoForwardRecord: a reverse name whose forward record does NOT
// exist at all is also untrusted → "".
func TestReverseRejectsNoForwardRecord(t *testing.T) {
	m := newMockENS()
	a := common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
	m.setReverseName(a, "vitalik.eth") // claimed, but no forward addr record set

	got, err := (&Resolver{}).Reverse(context.Background(), newENSFake(m), a)
	if err != nil {
		t.Fatalf("Reverse err = %v, want nil", err)
	}
	if got != "" {
		t.Fatalf("Reverse(no forward record) = %q, want \"\" (untrusted)", got)
	}
}

// TestReverseNoPrimaryName: an address with no reverse resolver returns "" with a
// nil error (a normal "no primary name" answer, not a failure).
func TestReverseNoPrimaryName(t *testing.T) {
	m := newMockENS()
	a := common.HexToAddress("0x2222222222222222222222222222222222222222")

	got, err := (&Resolver{}).Reverse(context.Background(), newENSFake(m), a)
	if err != nil {
		t.Fatalf("Reverse err = %v, want nil", err)
	}
	if got != "" {
		t.Fatalf("Reverse(no reverse record) = %q, want \"\"", got)
	}
}

// TestReverseNoRegistryForNetwork: reverse on a network without a registry is
// ErrNoRegistry.
func TestReverseNoRegistryForNetwork(t *testing.T) {
	m := newMockENS()
	c := newENSFake(m)
	c.ChainIDVal = big.NewInt(137)

	_, err := (&Resolver{}).Reverse(context.Background(), c, common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
	if !errors.Is(err, ErrNoRegistry) {
		t.Fatalf("Reverse on unknown network err = %v, want ErrNoRegistry", err)
	}
}

// TestReverseTransportErrorPropagates: a transport failure during reverse
// propagates unchanged.
func TestReverseTransportErrorPropagates(t *testing.T) {
	m := newMockENS()
	c := newENSFake(m)
	boom := errors.New("rpc: connection reset")
	c.Err = boom

	_, err := (&Resolver{}).Reverse(context.Background(), c, common.HexToAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
	if !errors.Is(err, boom) {
		t.Fatalf("Reverse transport err = %v, want the underlying error", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// RegistryFor table.
// ─────────────────────────────────────────────────────────────────────────────

func TestRegistryForTable(t *testing.T) {
	canonical := common.HexToAddress(RegistryAddr)
	for _, id := range []*big.Int{big.NewInt(1), big.NewInt(11155111)} {
		got, err := RegistryFor(id)
		if err != nil {
			t.Fatalf("RegistryFor(%s) err = %v", id, err)
		}
		if got != canonical {
			t.Fatalf("RegistryFor(%s) = %s, want %s", id, got.Hex(), canonical.Hex())
		}
	}
	for _, id := range []*big.Int{nil, big.NewInt(137), big.NewInt(31337), big.NewInt(10)} {
		if _, err := RegistryFor(id); !errors.Is(err, ErrNoRegistry) {
			t.Fatalf("RegistryFor(%v) err = %v, want ErrNoRegistry", id, err)
		}
	}
}
