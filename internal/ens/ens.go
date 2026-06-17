// Package ens is the ENS resolution provider leaf (design §2.8 / §4.8): EIP-137
// namehash, the registry→resolver→addr forward lookup, the EIP-181 reverse
// lookup (forward-verified), and the ResolvePinned helper that turns a re-pointed
// name into a refusal. It is a provider leaf — it imports chain (for the Client
// param on every read), domain (the error taxonomy, mirrored from erc) and the
// go-ethereum value/behavioral packages (common, crypto), and NEVER service, a
// frontend, policy, or registry.
//
// Per §2.8 / requirements §6 (every invocation may choose its network + endpoint),
// Resolver is a STATELESS CONCRETE struct that takes a chain.Client PER CALL — one
// value serves every network; service hands in the request's client resolved from
// req.Network/req.RPC. There is deliberately NO ens.Resolver interface (§2.1.1):
// the ENS-pin-refusal test seam is the chain.Client fake ONE LAYER DOWN (the
// universal seam), so a second mock would only duplicate behaviour the chain.Client
// fake already exercises.
//
// PIN SAFETY (the load-bearing reason this package exists, §4.8):
//   - The resolved address is what the caller is actually paying; service echoes
//     it (EvResolved) before signing so an agent/human sees the real 0x, never a
//     bare name.
//   - ENS records are MUTABLE. ResolvePinned re-resolves a name fresh and returns
//     ErrPinChanged when the result differs from the allow-time pin, so a
//     re-pointed name refuses the send (policy.denied.pin_drift) instead of
//     silently following the new target.
//   - A reverse name is UNAUTHENTICATED on its own; Reverse forward-verifies it
//     (the name must resolve back to the address) and returns "" otherwise.
package ens

import (
	"context"
	"errors"
	"strings"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/ethereum/go-ethereum/common"
)

// ErrPinChanged is returned by ResolvePinned when the name now resolves to a
// DIFFERENT address than the allow-time pin (§4.8 / requirements §4). It is the
// signal the policy stage-4 pin-drift gate maps to policy.denied.pin_drift
// (reason ens_drift): an agent must never silently follow a re-pointed name. The
// fresh (changed) address is returned alongside the error so the caller can show
// "pinned X, now resolves to Y". A resolution FAILURE on a pinned name is a
// separate refusal (the caller compares a returned error / zero result), not this
// sentinel.
var ErrPinChanged = errors.New("ens: name resolves to a different address than the pinned one")

// ErrNoRegistry is returned when the connected network has no known ENS registry
// (RegistryFor found no entry for cc's chain id). Distinct so service maps it to a
// clean ens.* usage refusal rather than a transport error — "ENS is not available
// on this network", not "the RPC failed".
var ErrNoRegistry = errors.New("ens: no ENS registry for this network")

// ErrUnresolved is returned when a name has no resolver, or the resolver returns
// the zero address / an empty record (the name does not resolve to an address).
// It is DISTINCT from a transport error so the caller maps it to a clean
// ens.*/ref.not_found refusal (exit 10) rather than rpc.* (exit 6) — "that name
// doesn't resolve" vs "the network is down".
var ErrUnresolved = errors.New("ens: name does not resolve")

// Resolver is the stateless ENS resolution namespace (§2.8). The struct carries
// NO state, so a single zero value serves every network and every concurrent
// request; the per-request endpoint is the chain.Client passed to each method.
// Concrete by design (§2.1.1): NO interface — the test seam is the chain.Client
// fake one layer down.
type Resolver struct{}

// Resolve performs the EIP-137 forward lookup name → address for the network
// behind cc:
//
//  1. node = Namehash(normalize(name))
//  2. registry.resolver(node) → resolver address (eth_call); zero ⇒ ErrUnresolved
//  3. resolver.addr(node)     → the resolved 0x address (eth_call); zero ⇒ ErrUnresolved
//
// The registry address is chosen from cc's chain id (cc.ChainID → RegistryFor);
// an unknown chain id is ErrNoRegistry. The name is normalized (ASCII case-fold +
// empty-label rejection) before hashing; an empty/malformed name is ErrUnresolved
// (no valid node to look up). Transport errors propagate UNCHANGED (rpc.*).
func (r *Resolver) Resolve(ctx context.Context, cc chain.Client, name string) (common.Address, error) {
	reg, err := registryForClient(ctx, cc)
	if err != nil {
		return common.Address{}, err
	}
	return resolveNode(ctx, cc, reg, name)
}

// resolveNode is the shared forward-resolution body once the registry address is
// known. Reverse reuses it (for forward-verification) without re-reading the chain
// id, and ResolvePinned/Resolve drive it after RegistryFor. A normalized name that
// is empty (the root, or an all-dots input) is ErrUnresolved — the root node has
// no address record and is never a valid destination.
func resolveNode(ctx context.Context, cc chain.Client, registry common.Address, name string) (common.Address, error) {
	norm, _, ok := normalize(name)
	if !ok || norm == "" {
		return common.Address{}, ErrUnresolved
	}
	node := Namehash(norm)

	// 1. registry.resolver(node) → the resolver contract for this node.
	out, err := callNode(ctx, cc, registry, sigResolver, node)
	if err != nil {
		return common.Address{}, err // transport — propagate unchanged (rpc.*)
	}
	resolver, ok := decodeAddress(out)
	if !ok || (resolver == common.Address{}) {
		return common.Address{}, ErrUnresolved // no resolver set for this name
	}

	// 2. resolver.addr(node) → the forward address record.
	out, err = callNode(ctx, cc, resolver, sigAddr, node)
	if err != nil {
		return common.Address{}, err // transport — propagate unchanged (rpc.*)
	}
	addr, ok := decodeAddress(out)
	if !ok || (addr == common.Address{}) {
		return common.Address{}, ErrUnresolved // resolver has no addr record
	}
	return addr, nil
}

// Reverse performs the EIP-181 reverse lookup address → primary name, FORWARD-
// VERIFIED (the only trusted form):
//
//  1. rnode = reverseNode(addr) = Namehash("<lowerhex(addr)>.addr.reverse")
//  2. registry.resolver(rnode) → reverse resolver; zero ⇒ "" (no primary name)
//  3. resolver.name(rnode)     → the claimed primary name; empty ⇒ ""
//  4. FORWARD-VERIFY: Resolve(name) MUST equal addr, else "" (untrusted)
//
// A reverse record that does not forward-resolve back to the address is NOT
// returned — a reverse name is unauthenticated, so trusting it without the forward
// check would let any address claim any name (§ pin safety). The absence of a
// trusted primary name is the empty string with a nil error (NOT an error): "this
// address has no verified primary name" is a normal, successful answer. Transport
// errors propagate UNCHANGED. ErrNoRegistry surfaces when the network has no
// registry.
func (r *Resolver) Reverse(ctx context.Context, cc chain.Client, a common.Address) (string, error) {
	reg, err := registryForClient(ctx, cc)
	if err != nil {
		return "", err
	}
	rnode := reverseNode(a)

	// 1. registry.resolver(rnode) → the reverse resolver.
	out, err := callNode(ctx, cc, reg, sigResolver, rnode)
	if err != nil {
		return "", err
	}
	resolver, ok := decodeAddress(out)
	if !ok || (resolver == common.Address{}) {
		return "", nil // no reverse resolver: no primary name (not an error)
	}

	// 2. resolver.name(rnode) → the claimed primary name.
	out, err = callNode(ctx, cc, resolver, sigName, rnode)
	if err != nil {
		return "", err
	}
	name, ok := decodeString(out)
	if !ok {
		return "", nil // malformed/empty return: no primary name
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil // empty claimed name: no primary name
	}

	// 3. FORWARD-VERIFY: the claimed name must resolve back to a, else untrusted.
	// Reuse the same registry (same network) — a reverse name pointing at a name
	// that doesn't resolve, or resolves elsewhere, is NOT trusted.
	fwd, err := resolveNode(ctx, cc, reg, name)
	if err != nil {
		if errors.Is(err, ErrUnresolved) {
			return "", nil // claimed name doesn't forward-resolve: untrusted
		}
		return "", err // transport — propagate
	}
	if fwd != a {
		return "", nil // forward record points elsewhere: untrusted
	}
	return name, nil
}

// ResolvePinned resolves name FRESH (per-invocation, against the network behind
// cc) and returns ErrPinChanged if the fresh result differs from the allow-time
// `pinned` address (§2.8 / §4.8). This is the helper that turns a re-pointed name
// into a refusal: ENS records are mutable, so a name allowlisted to address X must
// refuse a send the moment it resolves to Y. A resolution FAILURE (ErrUnresolved /
// transport) is returned UNCHANGED so the caller refuses (a pinned name that no
// longer resolves is also unsafe to send to). On a match the fresh address is
// returned with a nil error. The pin-refusal TEST SEAM is the chain.Client fake:
// program X at allow-time, Y at send-time → (Y, ErrPinChanged).
func (r *Resolver) ResolvePinned(ctx context.Context, cc chain.Client, name string, pinned common.Address) (common.Address, error) {
	got, err := r.Resolve(ctx, cc, name)
	if err != nil {
		return common.Address{}, err
	}
	if got != pinned {
		return got, ErrPinChanged
	}
	return got, nil
}

// registryForClient reads cc's chain id and selects the ENS registry address for
// it (RegistryFor). The chain id is read PER CALL (the per-request endpoint
// binding, §2.8). A transport failure reading the chain id propagates unchanged;
// an unknown chain id is ErrNoRegistry.
func registryForClient(ctx context.Context, cc chain.Client) (common.Address, error) {
	id, err := cc.ChainID(ctx)
	if err != nil {
		return common.Address{}, err
	}
	return RegistryFor(id)
}
