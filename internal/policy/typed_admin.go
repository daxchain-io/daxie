package policy

import (
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/policyseal"
	"github.com/daxchain-io/daxie/internal/secret"
	"github.com/ethereum/go-ethereum/common"
)

// typed_admin.go is the M9 admin surface for the §4.3 stage-5 per-domain typed-data
// allow registry (the sealed Policy.TypedData.Allowed[] the M4 file format already
// carries). An entry PINS the triple (chain_id, verifying_contract, primary_type) +
// an operator label: an UNRECOGNIZED typed message whose
// (domain.chainId, domain.verifyingContract, primaryType) matches a pinned entry
// passes the stage-5 gate; everything else is deny-by-default once a policy is active.
//
// It mirrors Allow/Deny exactly: authenticate under the admin passphrase → mutate the
// sealed body → bump the nonce → reseal → return the new Anchor (service writes the
// config-class anchor SECOND). The registry is admin-gated because admitting an
// unrecognized typed-data domain widens what a hijacked agent may sign — "I can't
// classify it" is never treated as harmless, so opening it is an admin act.

// TypedAllowEntry is the `policy typed allow/remove` request. The triple
// (ChainID, VerifyingContract, PrimaryType) is the identity; Label is operator
// metadata. Remove deletes the entry by triple. RefreshSelf/WrittenBy mirror the
// other mutations (re-seal the self snapshot + stamp the writer version).
type TypedAllowEntry struct {
	ChainID           int
	VerifyingContract string // 0x (lowercased on store)
	PrimaryType       string
	Label             string
	Remove            bool
	RefreshSelf       []common.Address
	WrittenBy         string
}

// TypedAllow adds (Remove=false) or removes (Remove=true) a typed-data allow entry
// under the admin passphrase (§4.3 stage-5 / §4.5 typed_data.allowed[]). It validates
// the triple on an ADD (a valid 0x verifyingContract, a non-empty primaryType, a
// positive chainId) so a malformed allow can never silently widen the gate. Mirrors
// Allow/Deny: authenticate → mutate body → bump nonce → reseal → return the anchor.
func (e *Engine) TypedAllow(adminPass *secret.Bytes, entry TypedAllowEntry) (policyseal.Anchor, error) {
	if !entry.Remove {
		if err := validateTypedAllow(entry); err != nil {
			return policyseal.Anchor{}, err
		}
	}
	ta := TypedAllow{
		ChainID:           entry.ChainID,
		VerifyingContract: strings.ToLower(strings.TrimSpace(entry.VerifyingContract)),
		PrimaryType:       strings.TrimSpace(entry.PrimaryType),
		Label:             entry.Label,
	}
	return e.mutate(adminPass, entry.WrittenBy, entry.RefreshSelf, func(p *Policy) error {
		if entry.Remove {
			p.TypedData.Allowed = removeTypedAllow(p.TypedData.Allowed, ta)
			return nil
		}
		p.TypedData.Allowed = upsertTypedAllow(p.TypedData.Allowed, ta)
		return nil
	})
}

// validateTypedAllow rejects a malformed allow entry (usage.bad_typed_allow, exit 2)
// BEFORE any seal mutation. A bad address / empty primary / non-positive chain could
// never match a real message but would pollute the sealed registry, so fail closed.
func validateTypedAllow(entry TypedAllowEntry) error {
	if entry.ChainID <= 0 {
		return domain.Newf(domain.CodeUsage+".bad_typed_allow",
			"--chain-id must be a positive chain id, got %d", entry.ChainID)
	}
	vc := strings.TrimSpace(entry.VerifyingContract)
	if !common.IsHexAddress(vc) {
		return domain.Newf(domain.CodeUsage+".bad_typed_allow",
			"--contract must be a 0x verifying-contract address, got %q", entry.VerifyingContract)
	}
	if strings.TrimSpace(entry.PrimaryType) == "" {
		return domain.New(domain.CodeUsage+".bad_typed_allow",
			"--primary-type is required (the EIP-712 primaryType to admit)")
	}
	return nil
}

// upsertTypedAllow adds ta, or updates the Label of an existing entry with the same
// triple (chain_id, verifying_contract, primary_type). The verifying-contract compare
// is case-insensitive (entries are stored lowercased).
func upsertTypedAllow(list []TypedAllow, ta TypedAllow) []TypedAllow {
	for i := range list {
		if sameTypedAllow(list[i], ta) {
			list[i].Label = ta.Label
			return list
		}
	}
	return append(list, ta)
}

// removeTypedAllow drops the entry matching ta's triple (case-insensitive address).
func removeTypedAllow(list []TypedAllow, ta TypedAllow) []TypedAllow {
	out := list[:0]
	for _, a := range list {
		if sameTypedAllow(a, ta) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// sameTypedAllow reports whether two entries denote the same triple
// (chain_id, verifying_contract case-insensitive, primary_type).
func sameTypedAllow(a, b TypedAllow) bool {
	return a.ChainID == b.ChainID &&
		strings.EqualFold(a.VerifyingContract, b.VerifyingContract) &&
		a.PrimaryType == b.PrimaryType
}
