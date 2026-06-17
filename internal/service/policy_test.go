package service

import (
	"context"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/policy"
)

// policy_test.go covers the service-owned policy-mutation glue that is independent of
// the scrypt-heavy seal path (which is exercised end-to-end against anvil in
// ens_integration_test.go / tx_integration_test.go and at the cli funnel in
// internal/cli/policy_test.go). Here we pin the §4.8 resolution-ECHO mapping: an
// allow/deny that pinned a NAME (ENS/contact) by resolving it NOW must surface the
// resolved 0x so the operator authorizes the address — not a bare name — before the
// seal is written (cli-spec: "the resolved address is always echoed").

// withPinEcho carries the resolution echo for an ENS/contact pin that actually
// resolved, and is a no-op for raw-0x pins, --remove, and the deny-by-name
// best-effort path that left no resolved address.
func TestWithPinEcho(t *testing.T) {
	const (
		ens     = "ens"
		contact = "contact"
		addr    = "0x00000000000000000000000000000000000000a1"
		at      = "2026-06-16T00:00:00Z"
	)
	cases := []struct {
		name       string
		pinSource  string
		pinName    string
		pinAddr    string
		pinAt      string
		remove     bool
		wantEcho   bool
		wantSource string
	}{
		{name: "ens add echoes resolved addr", pinSource: ens, pinName: "payee.eth", pinAddr: addr, pinAt: at, wantEcho: true, wantSource: ens},
		{name: "contact add echoes snapshot addr", pinSource: contact, pinName: "bob", pinAddr: addr, pinAt: at, wantEcho: true, wantSource: contact},
		{name: "raw 0x is not echoed", pinSource: "address", pinAddr: addr, wantEcho: false},
		{name: "ens remove is not echoed", pinSource: ens, pinName: "payee.eth", remove: true, wantEcho: false},
		{name: "deny-by-name unresolved is not echoed", pinSource: ens, pinName: "gone.eth", pinAddr: "", pinAt: "", wantEcho: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pin := policy.PinEntry{Source: tc.pinSource, Name: tc.pinName, Address: tc.pinAddr, ResolvedAt: tc.pinAt}
			got := withPinEcho(PolicyMutateResult{Nonce: 7, Watermark: 7}, pin, tc.remove)
			// The base result is always preserved.
			if got.Nonce != 7 || got.Watermark != 7 {
				t.Fatalf("base result mutated: %+v", got)
			}
			if !tc.wantEcho {
				if got.Pinned != "" || got.Source != "" || got.Name != "" || got.ResolvedAt != "" {
					t.Fatalf("expected NO echo, got source=%q name=%q pinned=%q resolved_at=%q",
						got.Source, got.Name, got.Pinned, got.ResolvedAt)
				}
				return
			}
			if got.Source != tc.wantSource || got.Name != tc.pinName || got.Pinned != tc.pinAddr || got.ResolvedAt != tc.pinAt {
				t.Fatalf("echo = source=%q name=%q pinned=%q resolved_at=%q, want source=%q name=%q pinned=%q resolved_at=%q",
					got.Source, got.Name, got.Pinned, got.ResolvedAt, tc.wantSource, tc.pinName, tc.pinAddr, tc.pinAt)
			}
		})
	}
}

// typedAdminService seals a policy and wires the admin passphrase through the env
// channel so the PolicyTypedAllow/Remove USE CASES (which acquire the admin pass via
// AdminInput → DAXIE_ADMIN_PASSPHRASE) authenticate end-to-end against the same anchor.
func typedAdminService(t *testing.T) *Service {
	t.Helper()
	svc, _ := signService(t)
	sealPolicy(t, svc, policy.Change{WrittenBy: "test"})
	svc.secretIO = SecretIO{LookupEnv: func(k string) (string, bool) {
		switch k {
		case "DAXIE_ADMIN_PASSPHRASE":
			return "unit-admin-pass", true
		case "DAXIE_PASSPHRASE":
			return "test-pass", true
		}
		return "", false
	}}
	return svc
}

// TestPolicyTypedAllowUseCase confirms the service use case admits a triple under the
// admin passphrase, echoes the (chain, contract, primaryType), seals it into the
// engine registry, and that PolicyTypedRemove drops it.
func TestPolicyTypedAllowUseCase(t *testing.T) {
	svc := typedAdminService(t)
	contract := "0x00000000000000ADC04C56Bf30aC9d3c0aAF14dC"

	res, err := svc.PolicyTypedAllow(context.Background(), domain.LocalCLI(), PolicyTypedAllowRequest{
		ChainID:           1,
		VerifyingContract: contract,
		PrimaryType:       "OrderComponents",
		Label:             "seaport",
	}, AdminInput{})
	if err != nil {
		t.Fatalf("PolicyTypedAllow: %v", err)
	}
	// The echo surfaces WHAT was sealed (lowercased contract), so the operator confirms.
	if res.TypedChainID != 1 || res.TypedPrimaryType != "OrderComponents" {
		t.Fatalf("echo = %+v, want chain 1 / OrderComponents", res)
	}
	if res.TypedContract != strings.ToLower(contract) {
		t.Fatalf("echo contract = %q, want lowercased %q", res.TypedContract, strings.ToLower(contract))
	}
	if res.TypedRemoved {
		t.Fatal("an allow must not echo typed_removed")
	}

	// The triple is actually sealed (an unrecognized typed message on it now passes).
	pol, _, err := svc.policy.Show()
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if len(pol.TypedData.Allowed) != 1 || pol.TypedData.Allowed[0].PrimaryType != "OrderComponents" {
		t.Fatalf("Allowed[] = %+v, want one OrderComponents entry", pol.TypedData.Allowed)
	}

	// Remove drops it + echoes typed_removed.
	rmRes, err := svc.PolicyTypedRemove(context.Background(), domain.LocalCLI(), PolicyTypedAllowRequest{
		ChainID:           1,
		VerifyingContract: contract,
		PrimaryType:       "OrderComponents",
	}, AdminInput{})
	if err != nil {
		t.Fatalf("PolicyTypedRemove: %v", err)
	}
	if !rmRes.TypedRemoved {
		t.Fatal("remove must echo typed_removed=true")
	}
	pol2, _, _ := svc.policy.Show()
	if len(pol2.TypedData.Allowed) != 0 {
		t.Fatalf("after remove, Allowed[] = %+v, want empty", pol2.TypedData.Allowed)
	}
}

// TestPolicyTypedAllowWrongAdminDenied confirms the use case is admin-gated: a wrong
// admin passphrase is refused and seals nothing.
func TestPolicyTypedAllowWrongAdminDenied(t *testing.T) {
	svc, _ := signService(t)
	sealPolicy(t, svc, policy.Change{WrittenBy: "test"})
	svc.secretIO = SecretIO{LookupEnv: func(k string) (string, bool) {
		if k == "DAXIE_ADMIN_PASSPHRASE" {
			return "WRONG-admin", true
		}
		return "", false
	}}
	_, err := svc.PolicyTypedAllow(context.Background(), domain.LocalCLI(), PolicyTypedAllowRequest{
		ChainID: 1, VerifyingContract: "0x00000000000000adc04c56bf30ac9d3c0aaf14dc", PrimaryType: "X",
	}, AdminInput{})
	if err == nil {
		t.Fatal("a wrong admin passphrase must be refused")
	}
	if domain.AsError(err).Code != domain.CodePolicyAdminAuth {
		t.Fatalf("code = %q, want policy.admin_auth", domain.AsError(err).Code)
	}
}
