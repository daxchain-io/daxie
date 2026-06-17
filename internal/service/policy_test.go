package service

import (
	"testing"

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
