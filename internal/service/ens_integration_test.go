//go:build integration

// ens_integration_test.go drives the M7 ENS resolution + pin-drift activation
// end-to-end through the REAL ChainProvider + keystore signer + journal/policy
// against a local anvil with a DEPLOYED mock ENS registry+resolver (§2.9):
//
//   - EnsResolve returns the registered address (registry→resolver→addr sequence).
//   - `tx send --to name.eth` resolves + echoes the address (EvResolved) and the
//     on-chain transfer lands at the resolved address.
//   - `policy allow name.eth` pins name+resolved-address+resolved-at; a send to the
//     name SUCCEEDS while the pin matches, then RE-POINTING the resolver makes the
//     next send DENY with policy.denied.pin_drift (reason ens_drift, exit 3),
//     NOTHING signed — the §4.3 stage-4 gate M7 activates.
//   - Reverse is forward-verified: a reverse name that forward-resolves back to the
//     address is returned; breaking the forward record yields "" (unverified).
//
// Gated by //go:build integration so it compiles only under `go test -tags
// integration` with anvil + the mock-ENS bytecode.
package service

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ens"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/testchain"
	"github.com/ethereum/go-ethereum/common"
)

// deployMockENS deploys the mock ENS to anvil and installs it as the chain-31337
// registry via the integration-only ens.SetTestRegistry hook (§2.8: the mock is at a
// non-canonical address, so RegistryFor(31337) is told about it here). It returns the
// deployed registry address and registers cleanup that clears the override.
func deployMockENS(t *testing.T, a *testchain.Anvil) common.Address {
	t.Helper()
	reg := testchain.DeployENS(t, a)
	ens.SetTestRegistry(big.NewInt(testchain.AnvilChainID), reg)
	t.Cleanup(func() { ens.SetTestRegistry(big.NewInt(testchain.AnvilChainID), common.Address{}) })
	return reg
}

// TestIntegration_ENSResolveAndSend: register daxchain.eth → addrA on the mock,
// resolve it, and send to the NAME — the transfer lands at addrA.
func TestIntegration_ENSResolveAndSend(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, _ := openSendAnvil(t, anvil.URL())
	reg := deployMockENS(t, anvil)

	addrA := common.HexToAddress("0x00000000000000000000000000000000000000e1")
	node := ens.Namehash("daxchain.eth")
	anvil.ENSSetAddr(t, reg, node, addrA)

	// EnsResolve returns addrA (the registry→resolver→addr sequence over the mock).
	rr, err := svc.EnsResolve(context.Background(), domain.LocalCLI(),
		domain.EnsResolveRequest{Name: "daxchain.eth", Network: "localanvil"}, nil)
	if err != nil {
		t.Fatalf("EnsResolve: %v", err)
	}
	if !strings.EqualFold(rr.Address, addrA.Hex()) {
		t.Fatalf("EnsResolve = %s, want %s", rr.Address, addrA.Hex())
	}

	// `tx send --to daxchain.eth` resolves + sends; the transfer lands at addrA.
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: "daxchain.eth", Amount: "1", Yes: true,
			Wait: domain.WaitOpts{Enabled: true}}, nil)
	if err != nil {
		t.Fatalf("SendTx --to daxchain.eth: %v", err)
	}
	if res.Status != domain.TxStatusConfirmed {
		t.Fatalf("status = %q, want confirmed", res.Status)
	}
	// The echoed destination carries the resolved address + the ENS name.
	if res.To.Address != addrA || res.To.ENSName != "daxchain.eth" || res.To.Via != "ens" {
		t.Fatalf("echoed dest = %+v, want addr=%s ens=daxchain.eth via=ens", res.To, addrA.Hex())
	}
	cc, _ := svc.chains.ClientFor(context.Background(), ChainRequest{Network: "localanvil"})
	defer cc.Close()
	bal, _ := cc.Balance(context.Background(), addrA, nil)
	if bal.Cmp(big.NewInt(1_000_000_000_000_000_000)) != 0 {
		t.Errorf("resolved recipient balance = %s wei, want exactly 1e18", bal)
	}
}

// TestIntegration_ENSPinDrift is the load-bearing M7 test: allow daxchain.eth (pins
// name+addrA), confirm a send to the name SUCCEEDS, then RE-POINT the resolver to
// addrB and assert the next send to the name DENIES with policy.denied.pin_drift
// (reason ens_drift, exit 3) and nothing is signed/broadcast.
func TestIntegration_ENSPinDrift(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())
	reg := deployMockENS(t, anvil)

	addrA := common.HexToAddress("0x00000000000000000000000000000000000000e2")
	addrB := common.HexToAddress("0x00000000000000000000000000000000000000e3")
	node := ens.Namehash("payee.eth")
	anvil.ENSSetAddr(t, reg, node, addrA)

	// Limits + allowlist ON, include_self ON (so gas-side self spends pass), then
	// `policy allow payee.eth` — resolves NOW → pins name+addrA+resolved_at.
	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:       strPtrIT("5eth"),
		MaxDay:      strPtrIT("100eth"),
		Allowlist:   strPtrIT("on"),
		IncludeSelf: strPtrIT("on"),
	})
	allowRes, err := svc.PolicyAllow(context.Background(), domain.LocalCLI(),
		PolicyAllowRequest{Source: "ens", Name: "payee.eth"}, AdminInput{})
	if err != nil {
		t.Fatalf("PolicyAllow ens payee.eth: %v", err)
	}
	// §4.8 / cli-spec: the resolved address is ALWAYS echoed (and in --json) BEFORE the
	// seal — the operator must authorize the 0x being trusted, not a bare name. The
	// allow result surfaces source+name+pinned-addr+resolved_at.
	if allowRes.Source != "ens" || allowRes.Name != "payee.eth" {
		t.Fatalf("allow echo source/name = (%q,%q), want (ens,payee.eth)", allowRes.Source, allowRes.Name)
	}
	if !strings.EqualFold(allowRes.Pinned, addrA.Hex()) {
		t.Fatalf("allow echo pinned = %q, want resolved %s", allowRes.Pinned, addrA.Hex())
	}
	if allowRes.ResolvedAt == "" {
		t.Fatalf("allow echo resolved_at is empty, want the §4.8 snapshot timestamp")
	}

	// While the pin matches (fresh == addrA == pin), a send to the name SUCCEEDS.
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: "payee.eth", Amount: "1", Yes: true,
			Wait: domain.WaitOpts{Enabled: true}}, nil)
	if err != nil {
		t.Fatalf("send to pinned matching name: %v", err)
	}
	if res.Status != domain.TxStatusConfirmed {
		t.Fatalf("matching-pin send status = %q, want confirmed", res.Status)
	}

	// RE-POINT the name to addrB (the ENS record is mutable — the attack the pin
	// defends against). The pin still records addrA.
	anvil.ENSSetAddr(t, reg, node, addrB)

	// The next send to the name re-resolves (→ addrB), the stage-4 gate compares it to
	// the pin (addrA), and DENIES with policy.denied.pin_drift (ens_drift, exit 3).
	_, err = svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: "payee.eth", Amount: "1", Yes: true}, nil)
	wantDenied(t, err, "policy.denied.pin_drift")
	de := domain.AsError(err)
	if r, _ := de.Data["reason"].(string); r != "ens_drift" {
		t.Errorf("pin_drift reason = %v, want ens_drift (data %+v)", de.Data["reason"], de.Data)
	}

	// Nothing was broadcast/confirmed for the drifted send (refused before sign). The
	// only confirmed record is the FIRST (matching-pin) send.
	recs, lerr := svc.journal.List(context.Background(), 31337, from)
	if lerr != nil {
		t.Fatalf("journal List: %v", lerr)
	}
	confirmed := 0
	for _, r := range recs {
		if r.Status == journal.StatusBroadcast || r.Status == journal.StatusConfirmed {
			confirmed++
		}
	}
	if confirmed != 1 {
		t.Fatalf("broadcast/confirmed records = %d, want exactly 1 (the matching-pin send; the drifted send must not sign)", confirmed)
	}
}

// TestIntegration_ENSReverseForwardVerified: set the reverse name(reverseNode) +
// the matching forward record; EnsReverse returns the verified name. Then break the
// forward record (re-point to a different addr) and assert reverse returns ""
// (unverified) — a reverse name is only trusted when it forward-resolves back.
func TestIntegration_ENSReverseForwardVerified(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, _ := openSendAnvil(t, anvil.URL())
	reg := deployMockENS(t, anvil)

	subject := common.HexToAddress("0x00000000000000000000000000000000000000e4")
	const primary = "daxchain.eth"

	// Forward record: daxchain.eth → subject. Reverse record: reverseNode(subject) →
	// "daxchain.eth". reverseNode = namehash("<lowerhex(addr) no 0x>.addr.reverse").
	fwdNode := ens.Namehash(primary)
	anvil.ENSSetAddr(t, reg, fwdNode, subject)
	revName := strings.ToLower(strings.TrimPrefix(subject.Hex(), "0x")) + ".addr.reverse"
	revNode := ens.Namehash(revName)
	anvil.ENSSetName(t, reg, revNode, primary)

	rr, err := svc.EnsReverse(context.Background(), domain.LocalCLI(),
		domain.EnsReverseRequest{Address: subject.Hex(), Network: "localanvil"}, nil)
	if err != nil {
		t.Fatalf("EnsReverse: %v", err)
	}
	if !rr.Verified || rr.Name != primary {
		t.Fatalf("EnsReverse = %+v, want verified name %q", rr, primary)
	}

	// Break the forward record (point daxchain.eth at a DIFFERENT address). The
	// reverse name no longer forward-resolves back to subject → untrusted → "".
	anvil.ENSSetAddr(t, reg, fwdNode, common.HexToAddress("0x00000000000000000000000000000000000000e5"))
	rr2, err := svc.EnsReverse(context.Background(), domain.LocalCLI(),
		domain.EnsReverseRequest{Address: subject.Hex(), Network: "localanvil"}, nil)
	if err != nil {
		t.Fatalf("EnsReverse (broken forward): %v", err)
	}
	if rr2.Verified || rr2.Name != "" {
		t.Fatalf("EnsReverse after broken forward = %+v, want unverified empty name", rr2)
	}
}
