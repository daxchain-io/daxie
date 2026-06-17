package policy

import (
	"strings"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/policyseal"
	"github.com/daxchain-io/daxie/internal/secret"
	"github.com/ethereum/go-ethereum/common"
)

// contract_admin.go is the M10 admin surface for the §4.3 stage-5b unknown-calldata allow
// registry (the sealed Policy.ContractsAllowed[] the M4 file format already carries +
// writes). An entry PINS the triple (network, contract, selector) + an operator label: a
// `contract send` whose calldata ClassifyCalldata could NOT classify passes the stage-5b
// gate ONLY when its (network, contract, selector) matches a pinned entry (or the contract
// address is allowlisted); everything else is deny-by-default once a policy is active.
//
// It is the structural twin of typed_admin.go: authenticate under the admin passphrase →
// mutate the sealed body → bump the nonce → reseal → return the new Anchor (service writes
// the config-class anchor SECOND). The registry is admin-gated because admitting an
// arbitrary (contract, selector) widens what a hijacked agent may sign — "I can't classify
// it" is never treated as harmless, so opening it is an admin act. There is deliberately no
// blanket override (the §4.3 stage-5b "per-triple ack only" rule): one wrong arbitrary
// call's blast radius is unbounded.

// ContractAllowEntry is the `policy contract allow/remove` request. The triple
// (Network, Contract, Selector) is the identity; Label is operator metadata. Remove
// deletes the entry by triple. RefreshSelf/WrittenBy mirror the other mutations (re-seal
// the self snapshot + stamp the writer version).
type ContractAllowEntry struct {
	Network     string
	Contract    string // 0x (lowercased on store)
	Selector    string // 0x 4-byte (normalized lowercase, 0x-prefixed, len 10) on store
	Label       string
	Remove      bool
	RefreshSelf []common.Address
	WrittenBy   string
}

// ContractAllow adds (Remove=false) or removes (Remove=true) a stage-5b unknown-calldata
// allow entry under the admin passphrase (§4.3 stage-5b / §4.5 contracts_allowed[]). It
// validates the triple on an ADD (a valid 0x contract, a 4-byte 0x selector, a non-empty
// network) so a malformed allow can never silently widen the gate. Mirrors TypedAllow:
// authenticate → mutate body → bump nonce → reseal → return the anchor. AddedAt is stamped
// from the engine clock on add. An upsert (same triple) refreshes Label + AddedAt.
func (e *Engine) ContractAllow(adminPass *secret.Bytes, entry ContractAllowEntry) (policyseal.Anchor, error) {
	if !entry.Remove {
		if err := validateContractAllow(entry); err != nil {
			return policyseal.Anchor{}, err
		}
	}
	ca := ContractAllow{
		Network:  strings.TrimSpace(entry.Network),
		Contract: strings.ToLower(strings.TrimSpace(entry.Contract)),
		Selector: normalizeSelector(entry.Selector),
		Label:    entry.Label,
	}
	return e.mutate(adminPass, entry.WrittenBy, entry.RefreshSelf, func(p *Policy) error {
		if entry.Remove {
			p.ContractsAllowed = removeContractAllow(p.ContractsAllowed, ca)
			return nil
		}
		ca.AddedAt = e.now().UTC().Format(time.RFC3339)
		p.ContractsAllowed = upsertContractAllow(p.ContractsAllowed, ca)
		return nil
	})
}

// validateContractAllow rejects a malformed allow entry (usage.bad_contract_allow, exit 2)
// BEFORE any seal mutation. A bad address / bad selector / empty network could never match
// a real contract send but would pollute the sealed registry, so fail closed.
func validateContractAllow(entry ContractAllowEntry) error {
	if strings.TrimSpace(entry.Network) == "" {
		return domain.New(domain.CodeUsage+".bad_contract_allow",
			"--network is required (the network the contract lives on)")
	}
	contract := strings.TrimSpace(entry.Contract)
	if !common.IsHexAddress(contract) {
		return domain.Newf(domain.CodeUsage+".bad_contract_allow",
			"the contract must be a 0x contract address, got %q", entry.Contract)
	}
	if !isSelectorHex(entry.Selector) {
		return domain.Newf(domain.CodeUsage+".bad_contract_allow",
			"--selector must be a 0x 4-byte function selector (10 hex chars, e.g. 0x095ea7b3), got %q", entry.Selector)
	}
	return nil
}

// isSelectorHex reports whether s is a well-formed 4-byte selector: 0x-prefixed, exactly
// 8 hex digits after the prefix (10 chars total). Whitespace is trimmed first.
func isSelectorHex(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 10 {
		return false
	}
	if s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return false
	}
	for i := 2; i < 10; i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// normalizeSelector lowercases + 0x-prefixes a selector to the canonical stored form
// ("0x" + 8 lowercase hex). Validation is done by isSelectorHex before this is called on
// the add path; on the remove path a malformed selector simply won't match any entry.
func normalizeSelector(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// upsertContractAllow adds ca, or updates the Label + AddedAt of an existing entry with the
// same triple (network, contract, selector). The compares are case-insensitive (entries
// are stored network-verbatim, contract+selector lowercased).
func upsertContractAllow(list []ContractAllow, ca ContractAllow) []ContractAllow {
	for i := range list {
		if sameContractAllow(list[i], ca) {
			list[i].Label = ca.Label
			list[i].AddedAt = ca.AddedAt
			return list
		}
	}
	return append(list, ca)
}

// removeContractAllow drops the entry matching ca's triple (case-insensitive network +
// contract, exact selector after normalization).
func removeContractAllow(list []ContractAllow, ca ContractAllow) []ContractAllow {
	out := list[:0]
	for _, a := range list {
		if sameContractAllow(a, ca) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// sameContractAllow reports whether two entries denote the same triple (network
// case-insensitive, contract case-insensitive, selector exact after normalization).
func sameContractAllow(a, b ContractAllow) bool {
	return strings.EqualFold(a.Network, b.Network) &&
		strings.EqualFold(a.Contract, b.Contract) &&
		normalizeSelector(a.Selector) == normalizeSelector(b.Selector)
}
