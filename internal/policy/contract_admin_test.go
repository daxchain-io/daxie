package policy

import (
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/secret"
	"github.com/ethereum/go-ethereum/common"
)

// contract_admin_test.go pins the M10 stage-5b unknown-calldata allow registry admin
// surface (ContractAllow): admin-gated upsert/remove, the wrong-passphrase refusal, the
// nonce bump + reseal, dedupe by the (network, contract, selector) triple, the
// malformed-entry rejection (fail-closed), and the selector normalization.

const (
	vaultContract = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
	stakeSelector = "0xa694fc3a" // stake(uint256)
)

// TestContractAllowAddsEntryAndBumpsNonce confirms an allow seals the triple into
// ContractsAllowed[] under the admin passphrase, bumps the nonce + watermark, reseals, and
// stamps AddedAt.
func TestContractAllowAddsEntryAndBumpsNonce(t *testing.T) {
	e, anchor := sealedEngine(t, "admin-pass")
	pass := secret.NewString("admin-pass")
	defer pass.Zero()

	anchor2, err := e.ContractAllow(pass, ContractAllowEntry{
		Network:   "mainnet",
		Contract:  vaultContract,
		Selector:  stakeSelector,
		Label:     "vault-stake",
		WrittenBy: "test",
	})
	if err != nil {
		t.Fatalf("ContractAllow: %v", err)
	}
	if anchor2.NonceWatermark != anchor.NonceWatermark+1 {
		t.Fatalf("watermark = %d, want %d", anchor2.NonceWatermark, anchor.NonceWatermark+1)
	}

	res, err := loadPolicy(e.dir, anchor2, true)
	if err != nil {
		t.Fatalf("load after allow: %v", err)
	}
	if !res.status.Verified {
		t.Fatal("the resealed policy must verify under the new anchor")
	}
	got := res.policy.ContractsAllowed
	if len(got) != 1 {
		t.Fatalf("ContractsAllowed[] len = %d, want 1 (%+v)", len(got), got)
	}
	a := got[0]
	if a.Network != "mainnet" || a.Selector != stakeSelector || a.Label != "vault-stake" {
		t.Fatalf("entry = %+v, want mainnet / %s / vault-stake", a, stakeSelector)
	}
	if a.Contract != vaultContract {
		t.Fatalf("contract = %q, want lowercased %q", a.Contract, vaultContract)
	}
	if a.AddedAt == "" {
		t.Fatal("AddedAt must be stamped on add")
	}

	// The sealed entry must satisfy the stage-5b gate's exact-triple match.
	if !contractAllowMatch(got, "MAINNET", common.HexToAddress(vaultContract), "0xA694FC3A") {
		t.Fatal("contractAllowMatch must be case-insensitive on network/contract/selector")
	}
}

// TestContractAllowNormalizesSelectorAndAddress confirms a mixed-case selector + checksummed
// contract are stored lowercased/normalized.
func TestContractAllowNormalizesSelectorAndAddress(t *testing.T) {
	e, _ := sealedEngine(t, "admin-pass")
	pass := secret.NewString("admin-pass")
	defer pass.Zero()

	anchor2, err := e.ContractAllow(pass, ContractAllowEntry{
		Network:   "mainnet",
		Contract:  "0x7A250D5630B4CF539739DF2C5DACB4C659F2488D", // checksummed
		Selector:  "0xA694FC3A",                                 // upper-case
		WrittenBy: "test",
	})
	if err != nil {
		t.Fatalf("ContractAllow: %v", err)
	}
	res, _ := loadPolicy(e.dir, anchor2, true)
	a := res.policy.ContractsAllowed[0]
	if a.Contract != vaultContract {
		t.Fatalf("contract = %q, want lowercased", a.Contract)
	}
	if a.Selector != stakeSelector {
		t.Fatalf("selector = %q, want lowercased %q", a.Selector, stakeSelector)
	}
}

// TestContractAllowRemoveByTriple confirms Remove deletes by triple and is idempotent.
func TestContractAllowRemoveByTriple(t *testing.T) {
	e, _ := sealedEngine(t, "admin-pass")
	pass := secret.NewString("admin-pass")
	defer pass.Zero()

	if _, err := e.ContractAllow(pass, ContractAllowEntry{
		Network: "mainnet", Contract: vaultContract, Selector: stakeSelector, WrittenBy: "test",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	anchor3, err := e.ContractAllow(pass, ContractAllowEntry{
		Network: "mainnet", Contract: vaultContract, Selector: stakeSelector, Remove: true, WrittenBy: "test",
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	res, _ := loadPolicy(e.dir, anchor3, true)
	if len(res.policy.ContractsAllowed) != 0 {
		t.Fatalf("after remove, len = %d, want 0", len(res.policy.ContractsAllowed))
	}
}

// TestContractAllowUpsertRefreshesLabel confirms re-adding the same triple updates the
// label rather than duplicating.
func TestContractAllowUpsertRefreshesLabel(t *testing.T) {
	e, _ := sealedEngine(t, "admin-pass")
	pass := secret.NewString("admin-pass")
	defer pass.Zero()

	_, _ = e.ContractAllow(pass, ContractAllowEntry{
		Network: "mainnet", Contract: vaultContract, Selector: stakeSelector, Label: "v1", WrittenBy: "test",
	})
	anchor3, err := e.ContractAllow(pass, ContractAllowEntry{
		Network: "mainnet", Contract: vaultContract, Selector: stakeSelector, Label: "v2", WrittenBy: "test",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	res, _ := loadPolicy(e.dir, anchor3, true)
	if len(res.policy.ContractsAllowed) != 1 {
		t.Fatalf("upsert must not duplicate; len = %d", len(res.policy.ContractsAllowed))
	}
	if res.policy.ContractsAllowed[0].Label != "v2" {
		t.Fatalf("label = %q, want refreshed v2", res.policy.ContractsAllowed[0].Label)
	}
}

// TestContractAllowWrongPassIsAdminAuth confirms the registry is admin-gated.
func TestContractAllowWrongPassIsAdminAuth(t *testing.T) {
	e, _ := sealedEngine(t, "admin-pass")
	wrong := secret.NewString("nope")
	defer wrong.Zero()

	_, err := e.ContractAllow(wrong, ContractAllowEntry{
		Network: "mainnet", Contract: vaultContract, Selector: stakeSelector, WrittenBy: "test",
	})
	if err == nil {
		t.Fatal("a wrong admin passphrase must be refused")
	}
	if domain.AsError(err).Code != "policy.admin_auth" {
		t.Fatalf("code = %q, want policy.admin_auth", domain.AsError(err).Code)
	}
}

// TestContractAllowValidatesEntry confirms a malformed allow is rejected (fail-closed,
// usage.bad_contract_allow) BEFORE any seal mutation.
func TestContractAllowValidatesEntry(t *testing.T) {
	e, _ := sealedEngine(t, "admin-pass")
	pass := secret.NewString("admin-pass")
	defer pass.Zero()

	cases := []struct {
		name  string
		entry ContractAllowEntry
	}{
		{"empty network", ContractAllowEntry{Contract: vaultContract, Selector: stakeSelector, WrittenBy: "t"}},
		{"bad contract", ContractAllowEntry{Network: "mainnet", Contract: "0x1234", Selector: stakeSelector, WrittenBy: "t"}},
		{"empty selector", ContractAllowEntry{Network: "mainnet", Contract: vaultContract, WrittenBy: "t"}},
		{"short selector", ContractAllowEntry{Network: "mainnet", Contract: vaultContract, Selector: "0xa694", WrittenBy: "t"}},
		{"no 0x selector", ContractAllowEntry{Network: "mainnet", Contract: vaultContract, Selector: "a694fc3a", WrittenBy: "t"}},
		{"non-hex selector", ContractAllowEntry{Network: "mainnet", Contract: vaultContract, Selector: "0xZZZZFC3A", WrittenBy: "t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.ContractAllow(pass, tc.entry)
			if err == nil {
				t.Fatalf("%s: a malformed entry must be rejected", tc.name)
			}
			if domain.AsError(err).Code != domain.CodeUsage+".bad_contract_allow" {
				t.Fatalf("%s: code = %q, want usage.bad_contract_allow", tc.name, domain.AsError(err).Code)
			}
		})
	}
}
