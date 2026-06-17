//go:build integration

// contact_drift_integration_test.go drives the §4.3 stage-4 CONTACT pin-drift gate
// and the §4.8 denylist NAME-broadening rule end-to-end through the REAL send
// pipeline against a local anvil — the contact-name analogues of ens_integration's
// TestIntegration_ENSPinDrift.
//
// Both gates bind ONLY because the send path threads the resolved destination's
// provenance (domain.Dest.Via=="contact" + the typed Name) into
// Check.ToSrc/ToInput/ENSResolved (tx.go applyDestProvenance). If that wiring
// regresses, the drifted/re-pointed sends would slip through and these tests fail.
package service

import (
	"context"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/testchain"
	"github.com/ethereum/go-ethereum/common"
)

// repointContactIT re-points an existing contact at a NEW address — the drift the
// pin defends against. Contacts.Add refuses an in-place duplicate, so a re-point is
// remove-then-add (the human would `contacts remove` + `contacts add`).
func repointContactIT(t *testing.T, svc *Service, name string, addr common.Address) {
	t.Helper()
	if _, err := svc.ContactRemove(context.Background(), domain.LocalCLI(),
		domain.ContactRemoveRequest{Name: name}); err != nil {
		t.Fatalf("ContactRemove %s: %v", name, err)
	}
	if _, err := svc.ContactAdd(context.Background(), domain.LocalCLI(),
		domain.ContactAddRequest{Name: name, Address: addr.Hex()}); err != nil {
		t.Fatalf("ContactAdd %s -> %s: %v", name, addr.Hex(), err)
	}
}

// confirmedCountIT counts broadcast/confirmed journal records for `from` on the
// anvil chain. A policy-denied send refuses before sign, so it leaves no such record.
func confirmedCountIT(t *testing.T, svc *Service, from common.Address) int {
	t.Helper()
	recs, err := svc.journal.List(context.Background(), testchain.AnvilChainID, from)
	if err != nil {
		t.Fatalf("journal List: %v", err)
	}
	n := 0
	for _, r := range recs {
		if r.Status == journal.StatusBroadcast || r.Status == journal.StatusConfirmed {
			n++
		}
	}
	return n
}

// TestIntegration_ContactPinDrift: add contact "payee"→addrA, `policy allow` it
// (pins addrA), confirm a send to the NAME succeeds, then RE-POINT the contact to
// addrB and assert the next send DENIES with policy.denied.pin_drift (reason
// contact_drift, exit 3) and nothing is signed/broadcast.
func TestIntegration_ContactPinDrift(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())

	addrA := common.HexToAddress("0x00000000000000000000000000000000000000c1")
	addrB := common.HexToAddress("0x00000000000000000000000000000000000000c2")

	// A contact "payee" currently pointing at addrA.
	if _, err := svc.ContactAdd(context.Background(), domain.LocalCLI(),
		domain.ContactAddRequest{Name: "payee", Address: addrA.Hex()}); err != nil {
		t.Fatalf("ContactAdd payee: %v", err)
	}

	// Limits + allowlist ON, include_self ON (gas-side self spends pass), then
	// `policy allow` the contact — snapshots name+addrA+resolved_at (the allow-time
	// pin). A later send re-reads the contact; the stage-4 gate refuses if it moved.
	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:       strPtrIT("5eth"),
		MaxDay:      strPtrIT("100eth"),
		Allowlist:   strPtrIT("on"),
		IncludeSelf: strPtrIT("on"),
	})
	allowRes, err := svc.PolicyAllow(context.Background(), domain.LocalCLI(),
		PolicyAllowRequest{Source: "contact", Name: "payee"}, AdminInput{})
	if err != nil {
		t.Fatalf("PolicyAllow contact payee: %v", err)
	}
	// The allow echoes the resolved 0x (the snapshot) the operator is authorizing.
	if allowRes.Source != "contact" || !strings.EqualFold(allowRes.Pinned, addrA.Hex()) {
		t.Fatalf("allow echo = (%q,%q), want (contact,%s)", allowRes.Source, allowRes.Pinned, addrA.Hex())
	}
	if allowRes.ResolvedAt == "" {
		t.Fatalf("allow echo resolved_at is empty, want the §4.8 snapshot timestamp")
	}

	// While the contact still points at the pin (fresh == addrA == pin), a send to the
	// NAME succeeds.
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: "payee", Amount: "1", Yes: true,
			Wait: domain.WaitOpts{Enabled: true}}, nil)
	if err != nil {
		t.Fatalf("send to pinned matching contact: %v", err)
	}
	if res.Status != domain.TxStatusConfirmed {
		t.Fatalf("matching-pin send status = %q, want confirmed", res.Status)
	}

	// RE-POINT the contact to addrB (the snapshot still records addrA — the attack the
	// pin defends against). The next send re-resolves (→ addrB), the stage-4 gate
	// compares it to the pin (addrA), and DENIES with policy.denied.pin_drift.
	repointContactIT(t, svc, "payee", addrB)
	_, err = svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: "payee", Amount: "1", Yes: true}, nil)
	wantDenied(t, err, "policy.denied.pin_drift")
	if r, _ := domain.AsError(err).Data["reason"].(string); r != "contact_drift" {
		t.Errorf("pin_drift reason = %v, want contact_drift (data %+v)", r, domain.AsError(err).Data)
	}

	// The drifted send refused BEFORE signing: exactly one broadcast/confirmed record
	// (the first, matching-pin send).
	if n := confirmedCountIT(t, svc, from); n != 1 {
		t.Fatalf("broadcast/confirmed records = %d, want exactly 1 (the matching-pin send; the drifted send must not sign)", n)
	}
}

// TestIntegration_DenylistContactNameBroadening: deny contact "scammer" (pinned at
// addrA), confirm a send to it is blocked by the pinned address, then RE-POINT the
// contact to a fresh addrB and assert the send STAYS blocked via the §4.8 name-
// broadening clause (the pinned address no longer matches; only the typed name does).
func TestIntegration_DenylistContactNameBroadening(t *testing.T) {
	anvil := testchain.Spawn(t)
	svc, from := openSendAnvil(t, anvil.URL())

	addrA := common.HexToAddress("0x00000000000000000000000000000000000000d1")
	addrB := common.HexToAddress("0x00000000000000000000000000000000000000d2")

	// A contact "scammer" pointing at addrA.
	if _, err := svc.ContactAdd(context.Background(), domain.LocalCLI(),
		domain.ContactAddRequest{Name: "scammer", Address: addrA.Hex()}); err != nil {
		t.Fatalf("ContactAdd scammer: %v", err)
	}

	// Generous limits, allowlist OFF — so absent the denylist a 1 ETH send would pass;
	// the denylist is the SOLE gate under test.
	setPolicyIT(t, svc, PolicySetRequest{
		MaxTx:     strPtrIT("5eth"),
		MaxDay:    strPtrIT("100eth"),
		Allowlist: strPtrIT("off"),
	})
	// Deny the contact by name, pinned at its current address (addrA).
	if _, err := svc.PolicyDeny(context.Background(), domain.LocalCLI(),
		PolicyDenyRequest{Source: "contact", Name: "scammer", Address: addrA.Hex()}, AdminInput{}); err != nil {
		t.Fatalf("PolicyDeny contact scammer: %v", err)
	}

	// A send to the denied contact (still addrA) is blocked by the pinned ADDRESS.
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: "scammer", Amount: "1", Yes: true}, nil)
	wantDenied(t, err, "policy.denied.allowlist")
	if r, _ := domain.AsError(err).Data["reason"].(string); r != "denylisted" {
		t.Errorf("deny-by-address reason = %v, want denylisted", r)
	}

	// RE-POINT the contact to a FRESH address (addrB ≠ the pinned addrA). The pinned-
	// address clause no longer matches, but the NAME-broadening clause (Check.ToInput,
	// threaded from the contact name) MUST keep it blocked (§4.8).
	repointContactIT(t, svc, "scammer", addrB)
	_, err = svc.SendTx(context.Background(), domain.LocalCLI(),
		domain.TxRequest{From: "funded", To: "scammer", Amount: "1", Yes: true}, nil)
	wantDenied(t, err, "policy.denied.allowlist")
	if r, _ := domain.AsError(err).Data["reason"].(string); r != "denylisted" {
		t.Errorf("re-pointed deny (name broadening) reason = %v, want denylisted", r)
	}

	// Both sends to the denied contact refused before signing: no broadcast/confirmed.
	if n := confirmedCountIT(t, svc, from); n != 0 {
		t.Fatalf("broadcast/confirmed records = %d, want 0 (every send to the denied contact refused pre-sign)", n)
	}
}
