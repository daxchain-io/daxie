package service

import (
	"context"
	"math/big"
	"strings"
	"time"

	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
	"github.com/daxchain-io/daxie/internal/policy"
	"github.com/daxchain-io/daxie/internal/policyseal"
	"github.com/daxchain-io/daxie/internal/secret"
	"github.com/daxchain-io/daxie/internal/version"
	"github.com/ethereum/go-ethereum/common"
)

// policy.go is the M4 admin use-case bridge: the cli `daxie policy …` surface
// (§4.7) → the policy engine's admin mutation API. It owns three responsibilities
// the engine deliberately leaves to the composition root:
//
//  1. ADMIN-PASSPHRASE ACQUISITION via the §3.6 resolver under DISTINCT names
//     (DAXIE_ADMIN_PASSPHRASE[_FILE], --admin-passphrase-*) — INDEPENDENT of the
//     keystore passphrase (§3.7). The *secret.Bytes is zeroed on defer, never
//     logged, never placed in an error.
//  2. The §4.7 K8s TWO-DOMAIN WRITE ORDERING: the engine writes the sealed
//     policy.json (state PVC) and RETURNS the new anchor; service then writes the
//     anchor to the config class (ConfigMap) SECOND. A read-only config maps to
//     config.read_only — the caller emits the anchor JSON to stdout / --anchor-out
//     so the operator lands it out of band (the loader accepts file.nonce >
//     watermark, so the policy-first ordering self-heals).
//  3. The self_addresses SNAPSHOT: every mutation re-seals the live keystore
//     address set into the body (§4.8 J11) so an agent that imports an attacker key
//     cannot mint itself an allowlisted destination.
//
// The cli imports service+domain only; it fills these channel-selection Inputs and
// renders the returned results. Business logic lives here, never in the frontend.

// ── admin-passphrase channels (§3.7; DISTINCT from the keystore passphrase) ──

// adminPassphraseSpec is the §4.7 admin-passphrase channel set. The env names are
// deliberately DISTINCT from the keystore passphrase (DAXIE_PASSPHRASE) so an
// agent pod that legitimately holds the keystore secret never holds the admin one.
func adminPassphraseSpec(stdin bool, file string) secretSpec {
	return secretSpec{
		StdinFlag:   stdin,
		FilePath:    file,
		EnvFileVar:  "DAXIE_ADMIN_PASSPHRASE_FILE",
		EnvVar:      "DAXIE_ADMIN_PASSPHRASE",
		PromptLabel: "Admin passphrase: ",
	}
}

// newAdminPassphraseSpec is the change-admin-passphrase ROTATION-TARGET channel
// (§4.6). Distinct names again so a staged rotation never reuses the current
// passphrase's channel.
func newAdminPassphraseSpec(stdin bool, file string) secretSpec {
	return secretSpec{
		StdinFlag:   stdin,
		FilePath:    file,
		EnvFileVar:  "DAXIE_NEW_ADMIN_PASSPHRASE_FILE",
		EnvVar:      "DAXIE_NEW_ADMIN_PASSPHRASE",
		PromptLabel: "New admin passphrase: ",
	}
}

// AdminInput is the admin-passphrase channel selection the cli fills for every
// mutating `policy` command (the keystore-passphrase analogue for policy).
type AdminInput struct {
	Stdin bool
	File  string
}

// NewAdminInput is the rotation-target channel selection (change-admin-passphrase).
type NewAdminInput struct {
	Stdin bool
	File  string
}

// ── result wire types (rendered by the cli; --json shape) ────────────────────

// PolicyShowResult is the `policy show`/`verify` view: seal status + the limits +
// the allow/deny pins + a per-network usage/headroom summary (§4.7). It carries no
// secret. The Active flag is the opt-in signal (an anchor is pinned).
type PolicyShowResult struct {
	Active       bool             `json:"active"`        // an anchor is pinned (guardrails on)
	Present      bool             `json:"present"`       // policy.json exists
	Verified     bool             `json:"verified"`      // seal verifies under the pinned key
	Nonce        uint64           `json:"nonce"`         // body nonce
	Watermark    uint64           `json:"watermark"`     // anchor watermark
	WrittenBy    string           `json:"written_by"`    // version that wrote the body
	AnchorSource string           `json:"anchor_source"` // "config" when found
	Reason       string           `json:"reason,omitempty"`
	Messages     string           `json:"messages,omitempty"`
	Default      PolicyLimitsView `json:"default"`
	Networks     []PolicyNetView  `json:"networks,omitempty"`
	Allowlist    []PolicyPinView  `json:"allowlist,omitempty"`
	Denylist     []PolicyPinView  `json:"denylist,omitempty"`
	Self         []string         `json:"self_addresses,omitempty"`
}

// PolicyLimitsView renders a limit block in human-friendly tri-state form: ""
// (absent/inherit), "none" (explicit no-limit), or a decimal-wei value.
type PolicyLimitsView struct {
	MaxTxWei       string `json:"max_tx_wei,omitempty"`
	MaxDayWei      string `json:"max_day_wei,omitempty"`
	MaxGasPriceWei string `json:"max_gas_price_wei,omitempty"`
	Allowlist      string `json:"allowlist_enabled,omitempty"`
	IncludeSelf    string `json:"include_self,omitempty"`
}

// PolicyNetView is a per-network override row.
type PolicyNetView struct {
	Network string `json:"network"`
	PolicyLimitsView
}

// PolicyPinView is one allowlist/denylist entry.
type PolicyPinView struct {
	Source  string `json:"source"`
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
	Label   string `json:"label,omitempty"`
}

// PolicyMutateResult is what a mutation (set/allow/deny/reset/change-admin) returns:
// the new nonce/watermark + whether the anchor was WRITTEN to the config class or
// EMITTED (the read-only K8s case). AnchorJSON carries the anchor bytes when emitted
// (or always, so the cli can echo it under --json).
type PolicyMutateResult struct {
	Nonce         uint64 `json:"nonce"`
	Watermark     uint64 `json:"watermark"`
	AnchorWritten bool   `json:"anchor_written"` // false ⇒ read-only config; AnchorJSON must be landed out of band
	AnchorPath    string `json:"anchor_path,omitempty"`
	AnchorJSON    string `json:"anchor,omitempty"` // the anchor JSON (always present; the operator lands it on read-only config)
	VerifyKey     string `json:"verify_key,omitempty"`
	VerifyKeyNext string `json:"verify_key_next,omitempty"` // set after change-admin-passphrase --stage
	Bootstrapped  bool   `json:"bootstrapped,omitempty"`    // first set created the anchor

	// allow/deny RESOLUTION ECHO (§4.8 / cli-spec "the resolved address is always
	// echoed"): when an allow/deny pinned a name (ENS or contact) by resolving it NOW,
	// these surface WHAT 0x was sealed so the operator authorizes the address — not a
	// bare name — before the seal is written. Source is "ens"|"contact"; Pinned is the
	// resolved 0x; ResolvedAt is the snapshot timestamp. Empty for a raw-0x pin (the
	// address was already on screen) and for --remove (no resolution happened).
	Source     string `json:"source,omitempty"`
	Name       string `json:"name,omitempty"`
	Pinned     string `json:"pinned,omitempty"`      // the resolved 0x that was sealed
	ResolvedAt string `json:"resolved_at,omitempty"` // the §4.8 resolved-at timestamp
}

// PolicyCheckResult is the `policy check` what-if verdict (§4.7): the full Decision,
// no reservation. Allowed=false carries the §4.9 code + every accumulated violation.
type PolicyCheckResult struct {
	Allowed    bool             `json:"allowed"`
	Code       string           `json:"code,omitempty"`
	Reason     string           `json:"reason,omitempty"`
	RetryAfter string           `json:"retry_after,omitempty"`
	Violations []PolicyViolView `json:"violations,omitempty"`
}

// PolicyViolView is one accumulated violation.
type PolicyViolView struct {
	Code   string         `json:"code"`
	Reason string         `json:"reason,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
}

// PolicyPinResult is `policy pin --print|--verify`.
type PolicyPinResult struct {
	VerifyKey     string `json:"verify_key,omitempty"`
	VerifyKeyNext string `json:"verify_key_next,omitempty"`
	AnchorJSON    string `json:"anchor,omitempty"`
	Verifies      bool   `json:"verifies"` // pin --verify outcome
}

// ── set request (limits / gates) the cli fills ───────────────────────────────

// PolicySetRequest is the `policy set` mutation request. All amount fields are
// human strings ("0.1eth", "100gwei", "none", "" inherit); the bool gates are
// tri-state strings ("on"|"off"|""=unchanged). Network scopes the override.
type PolicySetRequest struct {
	Network       string // "" ⇒ the default block
	MaxTx         *string
	MaxDay        *string
	MaxGasPrice   *string
	Allowlist     *string // "on"|"off"
	IncludeSelf   *string // "on"|"off"
	TypedUnknown  *string // "allow"|"deny"
	Messages      *string // "allow"|"deny"
	TokensNoAllow *string // "on"|"off"  (--allow-tokens-without-allowlist)
	AnchorOut     string  // --anchor-out staging path (read-only config)
}

// PolicyAllowRequest / PolicyDenyRequest carry the pre-resolved pin + --remove. The
// cli resolves a contact/ENS name to a pinned 0x BEFORE calling (v1 ENS is M7; for
// M4 the cli pins raw 0x and snapshots contacts). Source is "address"|"contact"|"ens".
type PolicyAllowRequest struct {
	Source    string
	Address   string // pinned 0x (lowercased by the engine)
	Name      string
	Label     string
	Remove    bool
	AnchorOut string
}
type PolicyDenyRequest = PolicyAllowRequest

// ── use cases ────────────────────────────────────────────────────────────────

// PolicyShow renders the current policy + seal status (UNAUTHENTICATED, §4.7). A
// halted seal (verify failure) is NOT an error here — show reports the halted state
// so an operator can diagnose without a non-zero exit.
func (s *Service) PolicyShow(_ context.Context, _ domain.Principal) (PolicyShowResult, error) {
	pol, st, err := s.policy.Show()
	res := PolicyShowResult{
		Active:       st.AnchorFound,
		Present:      st.Present,
		Verified:     st.Verified,
		Nonce:        st.Nonce,
		Watermark:    st.Watermark,
		WrittenBy:    st.WrittenBy,
		AnchorSource: st.AnchorSource,
		Reason:       st.Reason,
	}
	if err != nil {
		// A seal/rollback/version halt: report it in the view, not as a hard error,
		// so `policy show` always succeeds (the agent inspects Verified/Reason).
		return res, nil
	}
	res.Messages = pol.Messages
	res.Default = limitsView(pol.Rules.Default)
	for _, n := range pol.Rules.Networks {
		res.Networks = append(res.Networks, PolicyNetView{Network: n.Network, PolicyLimitsView: limitsView(n.Limits)})
	}
	res.Allowlist = pinsView(pol.Allowlist)
	res.Denylist = pinsView(pol.Denylist)
	res.Self = pol.SelfAddresses
	return res, nil
}

// PolicyVerify is the anchor-based, passphrase-free seal check (exit 0/8, §4.7).
// It returns a domain error (exit 8) on a seal/rollback/version failure so CI/K8s
// readiness probes branch on the exit code.
func (s *Service) PolicyVerify(_ context.Context, _ domain.Principal) (PolicyShowResult, error) {
	ok, st, err := s.policy.Verify()
	res := PolicyShowResult{
		Active: st.AnchorFound, Present: st.Present, Verified: ok && st.Verified,
		Nonce: st.Nonce, Watermark: st.Watermark, WrittenBy: st.WrittenBy,
		AnchorSource: st.AnchorSource, Reason: st.Reason,
	}
	if err != nil {
		return res, err // exit 8 (policy.seal_violation / rollback / version)
	}
	return res, nil
}

// PolicyCheckRequest is the `policy check` what-if input: a raw 0x from/to + an ETH
// amount + an optional gas price, all human strings. (M4 `policy check` resolves
// raw 0x only — ENS/contact resolution for the what-if path is M7.)
type PolicyCheckRequest struct {
	From        string
	To          string
	Amount      string
	MaxGasPrice string
	Network     string
}

// PolicyCheck runs the what-if Evaluate (no reservation, §4.7). A denied verdict is
// returned as a domain error (exit 3) carrying the §4.9 code + every violation, so
// `policy check` exits like a real send would.
func (s *Service) PolicyCheck(ctx context.Context, _ domain.Principal, req PolicyCheckRequest) (PolicyCheckResult, error) {
	from, ferr := parsePolicyAddr(req.From, "--from")
	if ferr != nil {
		return PolicyCheckResult{}, ferr
	}
	to, terr := parsePolicyAddr(req.To, "--to")
	if terr != nil {
		return PolicyCheckResult{}, terr
	}
	amt, aerr := parseEthAmount(req.Amount)
	if aerr != nil {
		return PolicyCheckResult{}, aerr
	}
	var gas *big.Int
	if req.MaxGasPrice != "" {
		g, gerr := parseFee(req.MaxGasPrice, "--max-gas-price")
		if gerr != nil {
			return PolicyCheckResult{}, gerr
		}
		gas = g
	}
	network := req.Network
	if network == "" {
		network = s.defaultNetwork
	}
	check := policy.Check{
		Account:      from,
		Dest:         to,
		SpendWei:     amt,
		MaxGasWei:    big.NewInt(0),
		MaxFeePerGas: gas,
		Kind:         "transfer",
		Network:      network,
		Asset:        "eth",
	}
	dec, err := s.policy.WhatIf(ctx, check)
	if err != nil {
		return PolicyCheckResult{}, err
	}
	res := PolicyCheckResult{Allowed: dec.Allowed, Code: dec.Code, Reason: dec.Reason, RetryAfter: dec.RetryAfter}
	for _, v := range dec.Violations {
		res.Violations = append(res.Violations, PolicyViolView{Code: v.Code, Reason: v.Reason, Data: v.Data})
	}
	if !dec.Allowed {
		de := domain.New(deniedCode(dec.Code), dec.Reason)
		if dec.RetryAfter != "" {
			de = domain.WithData(de, map[string]any{"retry_after": dec.RetryAfter})
		}
		if len(dec.Violations) > 0 {
			de = domain.WithData(de, map[string]any{"violations": res.Violations})
		}
		return res, de
	}
	return res, nil
}

// PolicySet applies a `policy set` mutation under the admin passphrase. The FIRST
// set bootstraps the anchor (§4.6). The engine writes policy.json + returns the
// anchor; service writes the anchor to the config class SECOND (the K8s ordering)
// or emits it on a read-only config.
func (s *Service) PolicySet(_ context.Context, _ domain.Principal, req PolicySetRequest, in AdminInput) (PolicyMutateResult, error) {
	change, cerr := s.buildChange(req)
	if cerr != nil {
		return PolicyMutateResult{}, cerr
	}
	adminPass, _, err := s.acquireAdmin(in)
	if err != nil {
		return PolicyMutateResult{}, err
	}
	defer adminPass.Zero()

	// Whether THIS set bootstraps the anchor — read the unauthenticated status
	// before mutating (Show never errors fatally). First set ⇒ no anchor yet.
	_, st, _ := s.policy.Show()
	bootstrapped := !st.AnchorFound
	anchor, serr := s.policy.Set(adminPass, change)
	if serr != nil {
		return PolicyMutateResult{}, serr
	}
	return s.finishMutation(anchor, req.AnchorOut, bootstrapped)
}

// PolicyAllow / PolicyDeny pin (or --remove) an allow/deny entry under the admin
// passphrase. The cli pre-resolves the input to a pinned 0x address (§4.8).
func (s *Service) PolicyAllow(ctx context.Context, _ domain.Principal, req PolicyAllowRequest, in AdminInput) (PolicyMutateResult, error) {
	adminPass, _, err := s.acquireAdmin(in)
	if err != nil {
		return PolicyMutateResult{}, err
	}
	defer adminPass.Zero()
	pin := policy.PinEntry{Source: req.Source, Address: strings.ToLower(req.Address), Name: req.Name, Label: req.Label}
	// M7 ENS allow-time pin (§4.8): `policy allow vitalik.eth` resolves the name NOW
	// and pins BOTH the name AND the resolved 0x + the resolved-at timestamp. A later
	// send to that name re-resolves and the §4.3 stage-4 gate refuses with
	// policy.denied.pin_drift if the resolution moved. We store the resolved address —
	// never a bare name (the engine pins exactly what it is handed). A --remove is
	// by-name only (no resolution needed).
	if req.Source == "ens" && !req.Remove {
		addr, rerr := s.resolveENSForPin(ctx, req.Name)
		if rerr != nil {
			return PolicyMutateResult{}, rerr
		}
		pin.Address = strings.ToLower(addr.Hex())
		pin.ResolvedAt = s.Now().UTC().Format(time.RFC3339)
	}
	// A contact ADD pins the contact's CURRENT address (the snapshot, §4.8): a later
	// send re-reads the contact and the §4.3 stage-4 contact_drift gate refuses if it
	// moved. An unknown contact name is ref.not_found (exit 10).
	if req.Source == "contact" && !req.Remove {
		addr, found, rerr := s.contacts.Resolve(ctx, req.Name)
		if rerr != nil {
			return PolicyMutateResult{}, rerr
		}
		if !found {
			return PolicyMutateResult{}, domain.Newf(domain.CodeRefNotFound,
				"contact %q is not in the address book (add it with `daxie contacts add`)", req.Name)
		}
		pin.Address = strings.ToLower(addr.Hex())
		pin.ResolvedAt = s.Now().UTC().Format(time.RFC3339)
	}
	entry := policy.AllowEntry{
		PinEntry:    pin,
		Remove:      req.Remove,
		RefreshSelf: s.selfSnapshot(),
		WrittenBy:   version.Version,
	}
	anchor, serr := s.policy.Allow(adminPass, entry)
	if serr != nil {
		return PolicyMutateResult{}, serr
	}
	res, ferr := s.finishMutation(anchor, req.AnchorOut, false)
	if ferr != nil {
		return PolicyMutateResult{}, ferr
	}
	return withPinEcho(res, pin, req.Remove), nil
}

// PolicyDeny mirrors PolicyAllow into the denylist (§4.8).
func (s *Service) PolicyDeny(ctx context.Context, _ domain.Principal, req PolicyDenyRequest, in AdminInput) (PolicyMutateResult, error) {
	adminPass, _, err := s.acquireAdmin(in)
	if err != nil {
		return PolicyMutateResult{}, err
	}
	defer adminPass.Zero()
	pin := policy.PinEntry{Source: req.Source, Address: strings.ToLower(req.Address), Name: req.Name, Label: req.Label}
	// M7: a deny on an ENS name is matched by NAME (stageDenylist broadens ens/contact
	// deny entries by typed name so a re-pointed denied name stays blocked, §4.8), but
	// resolving + pinning the address NOW also blocks the resolved 0x directly. Best
	// effort: if the name does not resolve, the by-name deny still stands (an empty
	// Address keeps the name match working). A --remove is by-name only.
	if req.Source == "ens" && !req.Remove {
		if addr, rerr := s.resolveENSForPin(ctx, req.Name); rerr == nil {
			pin.Address = strings.ToLower(addr.Hex())
			pin.ResolvedAt = s.Now().UTC().Format(time.RFC3339)
		}
	}
	entry := policy.DenyEntry{
		PinEntry:    pin,
		Remove:      req.Remove,
		RefreshSelf: s.selfSnapshot(),
		WrittenBy:   version.Version,
	}
	anchor, serr := s.policy.Deny(adminPass, entry)
	if serr != nil {
		return PolicyMutateResult{}, serr
	}
	res, ferr := s.finishMutation(anchor, req.AnchorOut, false)
	if ferr != nil {
		return PolicyMutateResult{}, ferr
	}
	return withPinEcho(res, pin, req.Remove), nil
}

// PolicyCountersRelease releases a stuck reservation by id under the admin
// passphrase (`policy counters release <id>`, §4.7). No anchor changes (the counter
// is state class).
func (s *Service) PolicyCountersRelease(ctx context.Context, _ domain.Principal, id string, in AdminInput) error {
	adminPass, _, err := s.acquireAdmin(in)
	if err != nil {
		return err
	}
	defer adminPass.Zero()
	return s.policy.CountersRelease(ctx, adminPass, id)
}

// PolicyPinPrint re-emits the anchor JSON (passphrase-free, §4.6).
func (s *Service) PolicyPinPrint(_ context.Context, _ domain.Principal) (PolicyPinResult, error) {
	anchor, err := s.policy.PinPrint()
	if err != nil {
		return PolicyPinResult{}, err
	}
	b, merr := anchor.Marshal()
	if merr != nil {
		return PolicyPinResult{}, domain.Wrap("policy.state_error", "cannot marshal the anchor", merr)
	}
	return PolicyPinResult{
		VerifyKey: anchor.VerifyKey, VerifyKeyNext: anchor.VerifyKeyNext,
		AnchorJSON: string(b), Verifies: true,
	}, nil
}

// PolicyPinVerify is the passphrase-free canary (`policy pin --verify <key>`,
// §4.6). It returns exit 8 (seal_violation) when the on-disk policy does NOT verify
// under the supplied key, so a one-off K8s Job is a canary, not a fleet refusal.
func (s *Service) PolicyPinVerify(_ context.Context, _ domain.Principal, candidateKey string) (PolicyPinResult, error) {
	ok, err := s.policy.PinVerify(candidateKey)
	if err != nil {
		return PolicyPinResult{}, err
	}
	if !ok {
		return PolicyPinResult{Verifies: false},
			domain.New("policy.seal_violation", "the on-disk policy.json does NOT verify under the supplied key")
	}
	return PolicyPinResult{Verifies: true}, nil
}

// PolicyChangeAdminPassphrase runs the staged/committed rotation (§4.6). --stage
// authenticates the current passphrase + prints the new verify key; --commit
// reseals under the new family. Returns the new anchor for the K8s write ordering.
func (s *Service) PolicyChangeAdminPassphrase(_ context.Context, _ domain.Principal, stage, commit bool, anchorOut string, cur AdminInput, next NewAdminInput) (PolicyMutateResult, error) {
	curPass, _, err := s.acquireAdmin(cur)
	if err != nil {
		return PolicyMutateResult{}, err
	}
	defer curPass.Zero()
	// The new passphrase is required for --stage; for --commit it is re-supplied so
	// the engine re-derives from the staged salt and asserts the key match.
	nextPass, _, nerr := s.acquire(newAdminPassphraseSpec(next.Stdin, next.File))
	if nerr != nil {
		return PolicyMutateResult{}, nerr
	}
	defer nextPass.Zero()

	anchor, serr := s.policy.ChangeAdminPassphrase(curPass, nextPass, stage, commit)
	if serr != nil {
		return PolicyMutateResult{}, serr
	}
	res, ferr := s.finishMutation(anchor, anchorOut, false)
	if ferr != nil {
		return PolicyMutateResult{}, ferr
	}
	res.VerifyKeyNext = anchor.VerifyKeyNext
	return res, nil
}

// PolicyResetForce reseals a fresh default body, authenticating against the ANCHOR
// not the file (§4.7 J12). NO --yes bypass: the cli does not pass one through.
func (s *Service) PolicyResetForce(_ context.Context, _ domain.Principal, anchorOut string, in AdminInput) (PolicyMutateResult, error) {
	adminPass, _, err := s.acquireAdmin(in)
	if err != nil {
		return PolicyMutateResult{}, err
	}
	defer adminPass.Zero()
	anchor, serr := s.policy.ResetForce(adminPass, s.selfSnapshot(), version.Version)
	if serr != nil {
		return PolicyMutateResult{}, serr
	}
	return s.finishMutation(anchor, anchorOut, false)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// acquireAdmin resolves the admin passphrase through the §3.6 resolver under the
// DISTINCT admin env names. The returned *secret.Bytes is owned by the caller,
// which MUST Zero() it.
func (s *Service) acquireAdmin(in AdminInput) (*secret.Bytes, secret.Source, error) {
	return s.acquire(adminPassphraseSpec(in.Stdin, in.File))
}

// finishMutation persists the engine-returned anchor to the config class SECOND
// (the policy file was already written by the engine — the K8s ordering, §4.7). A
// read-only config maps to config.read_only: instead of failing, it EMITS the
// anchor JSON (to AnchorJSON / --anchor-out) for the operator to land out of band.
func (s *Service) finishMutation(anchor policyseal.Anchor, anchorOut string, bootstrapped bool) (PolicyMutateResult, error) {
	b, merr := anchor.Marshal()
	if merr != nil {
		return PolicyMutateResult{}, domain.Wrap("policy.state_error", "cannot marshal the new anchor", merr)
	}
	res := PolicyMutateResult{
		Nonce:        anchor.NonceWatermark, // body nonce == watermark after a write (§4.6)
		Watermark:    anchor.NonceWatermark,
		AnchorJSON:   string(b),
		VerifyKey:    anchor.VerifyKey,
		Bootstrapped: bootstrapped,
		AnchorPath:   s.paths.AnchorPath(),
	}

	// --anchor-out <path>: write the anchor to an explicit staging path (the
	// operator lands it into the ConfigMap). This is the documented read-only path.
	if anchorOut != "" {
		if werr := writeAnchorStaging(anchorOut, b); werr != nil {
			return PolicyMutateResult{}, werr
		}
		res.AnchorWritten = false // staged, not the live config — operator lands it
		res.AnchorPath = anchorOut
		return res, nil
	}

	// Default: write the anchor to the config class. On a read-only mount, do NOT
	// fail — emit it (AnchorJSON already carries it) so `policy set` still succeeds
	// and the operator lands the anchor into the ConfigMap (§4.6).
	if werr := s.paths.WriteAnchor(b); werr != nil {
		if configAnchorReadOnly(werr) {
			res.AnchorWritten = false
			return res, nil
		}
		return PolicyMutateResult{}, werr
	}
	res.AnchorWritten = true
	return res, nil
}

// withPinEcho surfaces the §4.8 resolution echo on an allow/deny result: when the
// pin was produced by resolving a name NOW (ENS or contact), it carries the source,
// the name, the resolved 0x that was sealed, and the resolved-at timestamp so the
// operator authorizes the ADDRESS — not a bare name — before the seal is written
// (cli-spec: "the resolved address is always echoed (and included in --json output)
// before signing"). It is a no-op for a raw-0x pin (the address was already on the
// command line) and for --remove (no resolution happens). The signal that a
// resolution occurred is a non-empty ResolvedAt: the deny-by-name best-effort path
// (§4.8) leaves both Address and ResolvedAt empty when the name does not resolve, so
// there is nothing resolved to echo.
func withPinEcho(res PolicyMutateResult, pin policy.PinEntry, remove bool) PolicyMutateResult {
	if remove || pin.ResolvedAt == "" || (pin.Source != "ens" && pin.Source != "contact") {
		return res
	}
	res.Source = pin.Source
	res.Name = pin.Name
	res.Pinned = pin.Address
	res.ResolvedAt = pin.ResolvedAt
	return res
}

// selfSnapshot returns the live keystore addresses to seal into self_addresses
// (§4.8 J11). A keystore read error yields an empty snapshot rather than failing
// the mutation — the worst case is include_self matching nothing, which is the safe
// (more restrictive) direction.
func (s *Service) selfSnapshot() []common.Address {
	if s.keys == nil {
		return nil
	}
	accts, err := s.keys.ListAccounts(context.Background(), "")
	if err != nil {
		return nil
	}
	out := make([]common.Address, 0, len(accts))
	for _, a := range accts {
		out = append(out, a.Address)
	}
	return out
}

// buildChange translates a PolicySetRequest's human strings into the engine's
// tri-state policy.Change (nil=unchanged, null-sentinel=none/no-limit, value=enforce).
func (s *Service) buildChange(req PolicySetRequest) (policy.Change, error) {
	var lim policy.Limits
	touched := false
	setWei := func(dst **string, raw *string, isFee bool, label string) error {
		if raw == nil {
			return nil
		}
		touched = true
		v := strings.TrimSpace(*raw)
		switch strings.ToLower(v) {
		case "none", "null":
			*dst = policyNullStr()
			return nil
		case "", "inherit":
			*dst = nil // leave absent (inherit)
			return nil
		}
		var (
			wei *big.Int
			err error
		)
		if isFee {
			wei, err = parseFee(v, label)
		} else {
			wei, err = parseEthAmount(v)
		}
		if err != nil {
			return err
		}
		ws := wei.String()
		*dst = &ws
		return nil
	}
	if err := setWei(&lim.MaxTxWei, req.MaxTx, false, "--max-tx"); err != nil {
		return policy.Change{}, err
	}
	if err := setWei(&lim.MaxDayWei, req.MaxDay, false, "--max-day"); err != nil {
		return policy.Change{}, err
	}
	if err := setWei(&lim.MaxGasPriceWei, req.MaxGasPrice, true, "--max-gas-price"); err != nil {
		return policy.Change{}, err
	}
	if b, err := parseOnOff(req.Allowlist, "--allowlist"); err != nil {
		return policy.Change{}, err
	} else if b != nil {
		lim.AllowlistEnabled = b
		touched = true
	}
	if b, err := parseOnOff(req.IncludeSelf, "--include-self"); err != nil {
		return policy.Change{}, err
	} else if b != nil {
		lim.IncludeSelf = b
		touched = true
	}

	change := policy.Change{WrittenBy: version.Version, RefreshSelf: s.selfSnapshot()}
	if touched {
		if req.Network == "" {
			change.Default = &lim
		} else {
			change.Networks = []policy.NetworkRule{{Network: strings.ToLower(req.Network), Limits: lim}}
		}
	}
	if req.TypedUnknown != nil {
		v := strings.ToLower(strings.TrimSpace(*req.TypedUnknown))
		if v != "allow" && v != "deny" {
			return policy.Change{}, domain.Newf(domain.CodeUsage+".bad_flag", "--typed-unknown must be allow|deny, got %q", *req.TypedUnknown)
		}
		change.TypedUnknown = &v
	}
	if req.Messages != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Messages))
		if v != "allow" && v != "deny" {
			return policy.Change{}, domain.Newf(domain.CodeUsage+".bad_flag", "--messages must be allow|deny, got %q", *req.Messages)
		}
		change.Messages = &v
	}
	if b, err := parseOnOff(req.TokensNoAllow, "--allow-tokens-without-allowlist"); err != nil {
		return policy.Change{}, err
	} else if b != nil {
		change.TokensNoAllowOK = b
	}
	return change, nil
}

// parseOnOff maps "on"/"off" (case-insensitive) to a *bool; nil/"" ⇒ unchanged.
func parseOnOff(raw *string, label string) (*bool, error) {
	if raw == nil {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(*raw)) {
	case "on", "true", "yes":
		t := true
		return &t, nil
	case "off", "false", "no":
		f := false
		return &f, nil
	case "":
		return nil, nil
	default:
		return nil, domain.Newf(domain.CodeUsage+".bad_flag", "%s must be on|off, got %q", label, *raw)
	}
}

// parsePolicyAddr parses a 0x address for the what-if check (no name resolution in
// the M4 `policy check` — raw 0x only; ENS is M7).
func parsePolicyAddr(s, label string) (common.Address, error) {
	ref, err := domain.ParseAccountRef(strings.TrimSpace(s))
	if err != nil || ref.Kind != domain.RefAddress {
		return common.Address{}, domain.Newf(domain.CodeUsage+".bad_address", "%s must be a 0x address, got %q", label, s)
	}
	return ref.Addr, nil
}

// deniedCode normalizes an empty decision code to the umbrella policy.denied.
func deniedCode(code string) string {
	if code == "" {
		return domain.CodePolicyDenied
	}
	return code
}

// limitsView renders an engine Limits block into the human-friendly view: "" for
// an absent (inherit) field, "none" for the explicit-null sentinel, and the decimal
// wei otherwise; the bool gates render "on"/"off"/"".
func limitsView(l policy.Limits) PolicyLimitsView {
	return PolicyLimitsView{
		MaxTxWei:       triStr(l.MaxTxWei),
		MaxDayWei:      triStr(l.MaxDayWei),
		MaxGasPriceWei: triStr(l.MaxGasPriceWei),
		Allowlist:      boolTri(l.AllowlistEnabled),
		IncludeSelf:    boolTri(l.IncludeSelf),
	}
}

// triStr renders a tri-state limit *string for display.
func triStr(p *string) string {
	if p == nil {
		return "" // absent ⇒ inherit
	}
	if *p == policy.NullSentinel() {
		return "none" // explicit no-limit
	}
	return *p
}

// boolTri renders a tri-state *bool as on/off/"" (absent).
func boolTri(p *bool) string {
	if p == nil {
		return ""
	}
	if *p {
		return "on"
	}
	return "off"
}

// pinsView maps engine pins to the wire view.
func pinsView(pins []policy.PinEntry) []PolicyPinView {
	if len(pins) == 0 {
		return nil
	}
	out := make([]PolicyPinView, 0, len(pins))
	for _, p := range pins {
		out = append(out, PolicyPinView{Source: p.Source, Address: p.Address, Name: p.Name, Label: p.Label})
	}
	return out
}

// policyNullStr returns the engine's explicit-null limit sentinel pointer (the
// "no limit on this network" tri-state value). It mirrors policy's internal
// nullStr() without exporting it: the engine renders any *string whose value is
// this exact sentinel as a literal JSON null in the sealed body.
func policyNullStr() *string { s := policy.NullSentinel(); return &s }

// writeAnchorStaging writes the anchor bytes to an explicit --anchor-out path
// (the read-only-config K8s staging step, §4.6). It is a plain atomic write to an
// operator-chosen path, NOT the config-class anchor (that is paths.WriteAnchor).
func writeAnchorStaging(path string, b []byte) error {
	if err := fsx.WriteAtomic(path, b, 0o600); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.Newf(domain.CodeConfigReadOnly, "the --anchor-out path %q is not writable", path)
		}
		return domain.Wrap("policy.state_error", "cannot write the anchor to "+path, err)
	}
	return nil
}

// configAnchorReadOnly reports whether a WriteAnchor failure is the read-only
// config-mount case (the K8s ConfigMap) — the signal to emit the anchor instead of
// failing the mutation (§4.6).
func configAnchorReadOnly(err error) bool { return config.AnchorIsReadOnly(err) }
