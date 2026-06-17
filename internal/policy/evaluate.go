package policy

import (
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// evaluate.go is the PURE §4.3 evaluation pipeline. Evaluate takes the already
// seal-verified, decoded Policy, the built Check, the impure shell's
// rolling-24h window total, and the clock instant — and returns the Decision. It
// does NO I/O, reads NO clock, takes NO lock, touches NO network: the impure
// Engine.Evaluate wrapper (policy.go) does all that and hands the result here, so
// the whole verdict is a deterministic, table-testable function (the v2
// signer-daemon transplant the design promises, §4.11).
//
// Stage map (§4.3): 1 seal/freshness is done UPSTREAM (loadPolicy). This function
// runs stages 2-8 (2 classification arrives pre-built in Check; 3 denylist→
// allowlist→fail-closed; 4 pin-drift; 5 typed-data gate [for permits]; 5b
// unknown-calldata gate is structural/M10; 6 per-tx; 7 daily; 8 gas-cap). Stages
// 3-8 ALL run and ACCUMULATE violations so an agent gets the complete fix list in
// one denial; the exit code is the highest-precedence violation (§4.9). Stage 6's
// unlimited-ack is its own code (unlimited_unacked).

// the canonical §4.9 denied sub-codes (the policy part owns this taxonomy; D7).
// Group C maps these to retryable defaults + domain consts; here they are the
// authoritative strings the Decision carries.
const (
	codeDenied           = "policy.denied"
	codeTxLimit          = "policy.denied.tx_limit"
	codeDayLimit         = "policy.denied.day_limit"
	codeAllowlist        = "policy.denied.allowlist"
	codeNoAllowlist      = "policy.denied.no_allowlist"
	codeGasCap           = "policy.denied.gas_cap"
	codePinDrift         = "policy.denied.pin_drift"
	codeTypedData        = "policy.denied.typed_data"
	codeUnlimitedUnacked = "policy.denied.unlimited_unacked"
	codeContractCall     = "policy.denied.contract_call"
)

// precedence is the §4.9 precedence ranking (lower index = higher precedence).
// The process exits with the highest-precedence violation's code; ALL violations
// still ride in Decision.Violations. allowlist/no_allowlist share a rank, as do
// typed_data/contract_call ("can't classify; deny-by-default" band).
var precedence = map[string]int{
	codeAllowlist:        1,
	codeNoAllowlist:      1,
	codePinDrift:         2,
	codeTypedData:        3,
	codeContractCall:     3,
	codeUnlimitedUnacked: 4, // a per-tx-band refusal (stage 6 sibling of tx_limit)
	codeTxLimit:          5,
	codeDayLimit:         6,
	codeGasCap:           7,
}

// Evaluate runs the pure §4.3 pipeline (stages 2-8) over a seal-verified Policy.
// spentWindowWei is the impure shell's rolling-24h sum (Σ debits with ts>now−24h);
// now is the injected clock instant (used only to compute day_limit's retry_after).
// The window POLICY (rolling-24h) lives in HOW the shell computes spentWindowWei —
// Evaluate is window-agnostic (§4.1).
func Evaluate(p Policy, req Check, spentWindowWei *big.Int, now time.Time) Decision {
	lim := resolveLimits(p, req.Network)
	kind := req.effectiveKind()
	var vs []Violation

	// ── M9 unknown-typed-data short-circuit (§4.3 stage 5). An UNRECOGNIZED EIP-712
	// message carries no ETH dest, no SpendWei, no gas — the value-path stages (3
	// allowlist, 6 per-tx, 7 daily, 8 gas-cap) have nothing to bound and would
	// otherwise mis-fire (e.g. the allowlist gate would deny the zero Dest with the
	// higher-precedence allowlist code, masking the correct typed_data verdict). Run
	// ONLY the typed-data gate for it. (A RECOGNIZED permit does NOT take this branch —
	// it rides the full pipeline as KindPermit, exactly like an on-chain approval.) ──
	if req.TypedUnknown {
		if v, ok := stageTypedData(p, lim, req); ok {
			return composeDenial([]Violation{v})
		}
		return Decision{Allowed: true}
	}

	// ── Stage 3: denylist → allowlist → fail-closed no-allowlist ──
	if v, ok := stageDenylist(p, req); ok {
		vs = append(vs, v)
	} else {
		// Denylist beats allowlist + include_self; only run the allowlist gate when
		// the denylist did NOT already refuse (a denylisted dest is decided).
		if v, ok := stageAllowlist(p, lim, req); ok {
			vs = append(vs, v)
		}
		if v, ok := stageNoAllowlist(p, lim, req, kind); ok {
			vs = append(vs, v)
		}
	}

	// ── Stage 4: pin drift (ENS/contact fresh-resolution mismatch) ──
	if v, ok := stagePinDrift(req); ok {
		vs = append(vs, v)
	}

	// ── Stage 5: typed-data gate (permits not matched as spend-equivalent run 3-8;
	// a chain-mismatch on a recognized permit is surfaced here). The structural
	// hook for unknown typed data / stage-5b unknown calldata is M9/M10; in M4 the
	// Check carries the classification result and this stage refuses a denied
	// (chain-mismatch) permit. ──
	if v, ok := stageTypedData(p, lim, req); ok {
		vs = append(vs, v)
	}

	// ── Stage 6: per-tx ETH limit + unlimited-ack ceremony ──
	if v, ok := stagePerTx(lim, req, kind); ok {
		vs = append(vs, v)
	}
	if v, ok := stageUnlimited(p, req, kind); ok {
		vs = append(vs, v)
	}

	// ── Stage 7: rolling-24h daily limit ──
	if v, ok := stageDaily(lim, req, spentWindowWei, now); ok {
		vs = append(vs, v)
	}

	// ── Stage 8: gas cap ──
	if v, ok := stageGasCap(lim, req); ok {
		vs = append(vs, v)
	}

	if len(vs) == 0 {
		return Decision{Allowed: true}
	}
	return composeDenial(vs)
}

// composeDenial selects the highest-precedence violation as the Decision.Code and
// rides ALL violations in Decision.Violations (§4.9). RetryAfter/Data come from
// the winning violation.
func composeDenial(vs []Violation) Decision {
	winner := vs[0]
	for _, v := range vs[1:] {
		if rank(v.Code) < rank(winner.Code) {
			winner = v
		}
	}
	dec := Decision{
		Allowed:    false,
		Code:       winner.Code,
		Reason:     winner.Reason,
		Violations: vs,
		Data:       map[string]any{"violations": violationsPayload(vs)},
	}
	// Merge the winning violation's own data into the top-level Data (the §4.9
	// per-code details payload) and surface retry_after when present.
	for k, v := range winner.Data {
		dec.Data[k] = v
		if k == "retry_after" {
			if s, ok := v.(string); ok {
				dec.RetryAfter = s
			}
		}
	}
	return dec
}

// rank returns a violation code's precedence (unknown codes sort last).
func rank(code string) int {
	if r, ok := precedence[code]; ok {
		return r
	}
	return 1 << 30
}

// violationsPayload renders the accumulated violations for details.violations[].
func violationsPayload(vs []Violation) []map[string]any {
	out := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		m := map[string]any{"code": v.Code, "reason": v.Reason}
		for k, dv := range v.Data {
			m[k] = dv
		}
		out = append(out, m)
	}
	return out
}

// ── Stage 3a: denylist (beats allowlist + include_self) ──────────────────────

// stageDenylist refuses unconditionally when the resolved Dest matches a denylist
// entry by pinned address, OR — for contact/ens entries — by typed name (so a
// re-pointed denied name stays blocked, §4.8). Returns the violation when matched.
func stageDenylist(p Policy, req Check) (Violation, bool) {
	dest := lowerHex(req.Dest)
	for _, d := range p.Denylist {
		if matchPin(d, dest, req.ToInput) {
			return Violation{
				Code:   codeAllowlist,
				Reason: "the destination is on the policy denylist",
				Data:   map[string]any{"address": dest, "role": destRole(req), "reason": "denylisted"},
			}, true
		}
	}
	return Violation{}, false
}

// matchPin reports whether a pin entry matches the resolved address, or (for
// contact/ens sources) the typed input name (the deny broadening rule).
func matchPin(p PinEntry, dest, toInput string) bool {
	if strings.EqualFold(p.Address, dest) && dest != "" {
		return true
	}
	if (p.Source == "contact" || p.Source == "ens") && p.Name != "" && toInput != "" {
		return strings.EqualFold(p.Name, toInput)
	}
	return false
}

// ── Stage 3b: allowlist ──────────────────────────────────────────────────────

// stageAllowlist enforces the per-network allowlist when allowlist_enabled. The
// resolved Dest must match a pinned allowlist address; own accounts pass when
// include_self against the SEALED self_addresses snapshot (never the live
// keystore). Uniform across transfers/NFT sends/approvals/permits (§4.3 stage 3b).
func stageAllowlist(p Policy, lim resolvedLimits, req Check) (Violation, bool) {
	if !lim.allowlistEnabled {
		return Violation{}, false
	}
	dest := lowerHex(req.Dest)
	// include_self: an own account passes when include_self is set and the dest is
	// in the sealed snapshot.
	if lim.includeSelf && inSelf(p, dest) {
		return Violation{}, false
	}
	for _, a := range p.Allowlist {
		if strings.EqualFold(a.Address, dest) && dest != "" {
			return Violation{}, false
		}
	}
	return Violation{
		Code:   codeAllowlist,
		Reason: "the destination is not on the policy allowlist",
		Data:   map[string]any{"address": dest, "role": destRole(req), "reason": "not_allowlisted"},
	}, true
}

// stageNoAllowlist is §4.3 stage 3c: for token/NFT transfers and approvals/
// permits, if limits are set but allowlist_enabled is false ⇒ deny unless
// tokens_no_allowlist_ok is set (the admin-acknowledged gap). ETH transfers are
// exempt (the ETH limit caps them directly).
func stageNoAllowlist(p Policy, lim resolvedLimits, req Check, kind Kind) (Violation, bool) {
	if lim.allowlistEnabled {
		return Violation{}, false // the allowlist gate already covers this path
	}
	if !isTokenOrApproval(req, kind) {
		return Violation{}, false // ETH transfers are exempt
	}
	if !lim.anySet {
		return Violation{}, false // no limits configured ⇒ fail-closed rule does not bind
	}
	if p.TokensNoAllowlistOK {
		return Violation{}, false // admin acknowledged the gap
	}
	return Violation{
		Code:   codeNoAllowlist,
		Reason: "token/approval operations are refused when limits are set but no allowlist is enabled (fail-closed); set --allow-tokens-without-allowlist under the admin passphrase to override",
		Data:   map[string]any{"network": req.Network},
	}, true
}

// isTokenOrApproval reports whether the request is a token/NFT transfer or an
// approval/permit (the paths stage 3c binds; ETH transfers are exempt).
func isTokenOrApproval(req Check, kind Kind) bool {
	if kind == KindApprove || kind == KindPermit {
		return true
	}
	// A token transfer is a KindTransfer carrying a token asset (Token/Asset set
	// to a contract, not "eth").
	if kind == KindTransfer {
		asset := strings.ToLower(req.Asset)
		if req.Token != "" && strings.ToLower(req.Token) != "eth" {
			return true
		}
		if asset != "" && asset != "eth" {
			return true
		}
	}
	return false
}

// ── Stage 4: pin drift ───────────────────────────────────────────────────────

// stagePinDrift refuses when an ENS/contact input's fresh resolution (carried in
// req.ENSResolved by the service pre-lock) differs from the allow-time pinned
// address. A zero fresh resolution on an ENS input is ens_unresolved (resolution
// failure also refuses, §4.8). The engine only compares — it never does network
// I/O. raw 0x inputs are not drift-checked (a literal address cannot drift).
func stagePinDrift(req Check) (Violation, bool) {
	switch req.ToSrc {
	case SourceENS:
		dest := lowerHex(req.Dest)
		fresh := lowerHex(req.ENSResolved)
		if fresh == "" || req.ENSResolved == (common.Address{}) {
			return Violation{
				Code:   codePinDrift,
				Reason: "the ENS name did not resolve; refusing until re-allowed",
				Data:   map[string]any{"reason": "ens_unresolved", "name": req.ENSName, "pinned": dest, "current": ""},
			}, true
		}
		if fresh != dest {
			return Violation{
				Code:   codePinDrift,
				Reason: "the ENS name resolves to a different address than the allow-time pin; refusing until re-allowed",
				Data:   map[string]any{"reason": "ens_drift", "name": req.ENSName, "pinned": dest, "current": fresh},
			}, true
		}
	case SourceContact:
		dest := lowerHex(req.Dest)
		fresh := lowerHex(req.ENSResolved)
		if fresh != "" && fresh != dest {
			return Violation{
				Code:   codePinDrift,
				Reason: "the contact resolves to a different address than the allow-time pin; refusing until re-allowed",
				Data:   map[string]any{"reason": "contact_drift", "name": req.ToInput, "pinned": dest, "current": fresh},
			}, true
		}
	}
	return Violation{}, false
}

// ── Stage 5: typed-data gate (chain mismatch + the unknown-typed deny-by-default) ─

// stageTypedData is the §4.3 stage-5 typed-data gate. Two paths:
//
//   - RECOGNIZED spend-equivalent permit (KindPermit): a chain mismatch — a permit
//     for another chain signed on the active network, the §4.2 exfiltration trick —
//     is marked by service setting Asset="chain_mismatch:<id>" (via
//     ClassifyTypedDataFor). The pure engine refuses it. The permit otherwise runs
//     stages 3/3c/6 like an on-chain approval (spender allowlist + fail-closed +
//     unlimited-ack); this stage adds only the chain-mismatch deny.
//
//   - UNRECOGNIZED typed message (Check.TypedUnknown, set only by SignTyped's
//     authorizeSignature once a policy is active): DENY BY DEFAULT. Order:
//     (a) a chain mismatch (Asset marker) ⇒ deny chain_mismatch;
//     (b) the (chain_id, verifying_contract, primary_type) triple in
//     TypedData.Allowed[] ⇒ ALLOW (pass the gate);
//     (c) typed_data.unknown == "allow" (per-network override) ⇒ allow;
//     (d) otherwise ⇒ deny typed_data.unknown. "I can't classify it" is NEVER
//     "harmless" (§4.2 table row 4).
//
// This stage runs only when a policy is present (the impure Evaluate calls the pure
// pipeline only for present policies), which is exactly the "once a policy is active"
// condition the deny-by-default rule requires.
func stageTypedData(p Policy, lim resolvedLimits, req Check) (Violation, bool) {
	chainMismatch := strings.HasPrefix(req.Asset, "chain_mismatch")

	// Recognized spend-equivalent permit: only the chain-mismatch deny lives here.
	if req.effectiveKind() == KindPermit && chainMismatch {
		return Violation{
			Code:   codeTypedData,
			Reason: "the typed-data permit targets a different chain than the active network (chain_mismatch)",
			Data:   map[string]any{"reason": "chain_mismatch"},
		}, true
	}

	if !req.TypedUnknown {
		return Violation{}, false
	}

	// (a) chain mismatch on unrecognized typed data ⇒ deny.
	if chainMismatch {
		return Violation{
			Code:   codeTypedData,
			Reason: "the typed-data message targets a different chain than the active network (chain_mismatch)",
			Data: map[string]any{
				"reason":             "chain_mismatch",
				"primary_type":       req.TypedPrimary,
				"verifying_contract": req.TypedVerifying,
				"chain_id":           req.TypedChainID,
			},
		}, true
	}

	// (b) the per-domain allow registry: an exact triple match passes the gate.
	if typedAllowMatch(p.TypedData.Allowed, req) {
		return Violation{}, false
	}

	// (c) the resolved disposition: "allow" lets unrecognized typed data through.
	if strings.EqualFold(strings.TrimSpace(lim.typedUnknown), "allow") {
		return Violation{}, false
	}

	// (d) deny-by-default: unknown typed data with no allow entry and no allow switch.
	return Violation{
		Code:   codeTypedData,
		Reason: "this typed-data message is not a recognized spend-equivalent and no policy allow entry covers it; refusing (typed_data.unknown). Add it with `daxie policy typed allow`",
		Data: map[string]any{
			"reason":             "unknown",
			"primary_type":       req.TypedPrimary,
			"verifying_contract": req.TypedVerifying,
			"chain_id":           req.TypedChainID,
		},
	}, true
}

// typedAllowMatch reports whether the unrecognized typed message matches a pinned
// TypedData.Allowed[] entry on the EXACT triple (chain_id, verifying_contract,
// primary_type). The verifying_contract compare is case-insensitive (addresses are
// stored lowercased; the message value is lowercased by service). chain_id 0 in the
// message never matches a real entry (a triple pins a positive chain).
func typedAllowMatch(allowed []TypedAllow, req Check) bool {
	for _, a := range allowed {
		if int64(a.ChainID) != req.TypedChainID {
			continue
		}
		if !strings.EqualFold(a.VerifyingContract, req.TypedVerifying) {
			continue
		}
		if a.PrimaryType != req.TypedPrimary {
			continue
		}
		return true
	}
	return false
}

// ── Stage 6: per-tx ETH limit + unlimited ceremony ───────────────────────────

// stagePerTx enforces the per-tx ETH limit: SpendWei + MaxGasWei ≤ max_tx_wei,
// for every broadcasting Kind. Permits carry no ETH/gas debit and are exempt.
func stagePerTx(lim resolvedLimits, req Check, kind Kind) (Violation, bool) {
	if kind == KindPermit {
		return Violation{}, false // gasless; no per-tx wei debit
	}
	if lim.maxTx == nil {
		return Violation{}, false // no per-tx limit configured / explicit null
	}
	attempted := new(big.Int).Add(req.spendWei(), req.maxGasWei())
	if attempted.Cmp(lim.maxTx) > 0 {
		return Violation{
			Code:   codeTxLimit,
			Reason: "the transaction value plus worst-case gas exceeds the per-tx limit",
			Data: map[string]any{
				"limit":     lim.maxTx.String(),
				"attempted": attempted.String(),
				"network":   req.Network,
			},
		}, true
	}
	return Violation{}, false
}

// stageUnlimited enforces the §4.3 stage-6 unlimited approval/permit ceremony: an
// unlimited approval/permit is denied unless Acked AND the policy does not set
// allow_unlimited:false for that token. allow_unlimited:false is a hard deny
// regardless of the ceremony.
//
// Defense in depth (§4.2): Unlimited is re-derived from the ENCODED amount
// (req.TokenAmt) against the §4.2 sentinel set, not merely trusted from the
// caller-supplied req.Unlimited flag. A builder that fails to set Unlimited for a
// sentinel --amount cannot slip an infinite allowance past this gate — the engine
// matches the wire value itself. (The builder still sets the flag too, so a typed
// --unlimited with no amount, e.g. a permit, is also covered.)
func stageUnlimited(p Policy, req Check, kind Kind) (Violation, bool) {
	if kind != KindApprove && kind != KindPermit {
		return Violation{}, false
	}
	if !req.Unlimited && !isUnlimitedAmount(req.TokenAmt) {
		return Violation{}, false
	}
	token := strings.ToLower(req.Token)
	if token == "" {
		token = strings.ToLower(req.Asset)
	}
	// allow_unlimited:false on the token rule is a hard deny (beats the ack).
	if hard := tokenHardDeny(p, req.Network, token); hard {
		return Violation{
			Code:   codeUnlimitedUnacked,
			Reason: "unlimited approval is hard-denied for this token by policy (allow_unlimited:false)",
			Data:   map[string]any{"token": token, "spender": lowerHex(req.Dest)},
		}, true
	}
	if !req.Acked {
		return Violation{
			Code:   codeUnlimitedUnacked,
			Reason: "unlimited approval/permit requires the explicit --unlimited --yes acknowledgement",
			Data:   map[string]any{"token": token, "spender": lowerHex(req.Dest)},
		}, true
	}
	return Violation{}, false
}

// tokenHardDeny reports whether a token rule sets allow_unlimited:false for the
// (network, token) pair (the operator hard-deny).
func tokenHardDeny(p Policy, network, token string) bool {
	for _, t := range p.Tokens {
		if strings.EqualFold(t.Network, network) && strings.EqualFold(t.Address, token) {
			return t.AllowUnlimited != nil && !*t.AllowUnlimited
		}
	}
	return false
}

// ── Stage 7: rolling-24h daily limit ─────────────────────────────────────────

// stageDaily enforces the rolling-24h window: spentWindowWei + thisDebit ≤
// max_day_wei. thisDebit is the ETH value + worst-case gas of THIS request
// (permits debit nothing). On denial it computes retry_after — the earliest
// instant enough debits age out — but the pure engine cannot know individual
// entry timestamps, so it returns a conservative retry_after of now+24h when it
// cannot do better; the impure shell overrides it with the precise instant it can
// compute from the counter file. (§4.9 retry_after; §4.1.)
func stageDaily(lim resolvedLimits, req Check, spentWindowWei *big.Int, now time.Time) (Violation, bool) {
	if lim.maxDay == nil {
		return Violation{}, false
	}
	if req.effectiveKind() == KindPermit {
		return Violation{}, false
	}
	used := spentWindowWei
	if used == nil {
		used = big.NewInt(0)
	}
	thisDebit := new(big.Int).Add(req.spendWei(), req.maxGasWei())
	total := new(big.Int).Add(used, thisDebit)
	if total.Cmp(lim.maxDay) > 0 {
		// A conservative retry_after: now + 24h (the latest the whole window could
		// age out). The shell tightens this from the actual entry timestamps.
		retry := now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
		return Violation{
			Code:   codeDayLimit,
			Reason: "the rolling-24h spend window plus this transaction exceeds the daily limit",
			Data: map[string]any{
				"limit":       lim.maxDay.String(),
				"used_24h":    used.String(),
				"attempted":   thisDebit.String(),
				"retry_after": retry,
			},
		}, true
	}
	return Violation{}, false
}

// ── Stage 8: gas cap ─────────────────────────────────────────────────────────

// stageGasCap refuses when MaxFeePerGas exceeds max_gas_price_wei. No silent
// clamping (clamping under the market base fee produces stuck txs); the payload
// carries current_base_fee so the caller distinguishes "fee spike, retry" from
// "my flags are wrong". current_base_fee is best-effort: the engine echoes
// MaxFeePerGas as the attempted value; the service overlays the live base fee.
func stageGasCap(lim resolvedLimits, req Check) (Violation, bool) {
	if lim.maxGasPrice == nil {
		return Violation{}, false
	}
	attempted := req.maxFeePerGas()
	if attempted.Sign() == 0 {
		return Violation{}, false // no fee to check (e.g. a permit / dry value)
	}
	if attempted.Cmp(lim.maxGasPrice) > 0 {
		return Violation{
			Code:   codeGasCap,
			Reason: "the max fee per gas exceeds the policy gas-price cap",
			Data: map[string]any{
				"cap":       lim.maxGasPrice.String(),
				"attempted": attempted.String(),
			},
		}, true
	}
	return Violation{}, false
}

// ── limit resolution (default block overridden per network, tri-state) ───────

// resolvedLimits is the per-request effective limit set after applying the
// network override over the default block. A nil amount pointer means "no limit"
// (either absent-with-no-default, or an explicit per-network null). anySet
// records whether ANY limit is configured (for the fail-closed stage-3c trigger).
type resolvedLimits struct {
	maxTx            *big.Int
	maxDay           *big.Int
	maxGasPrice      *big.Int
	allowlistEnabled bool
	includeSelf      bool
	anySet           bool
	// typedUnknown is the resolved §4.3 stage-5 disposition for UNRECOGNIZED typed
	// data: the policy-wide typed_data.unknown ("allow"|"deny") overridden by the
	// per-network typed_data_unknown field. "" is treated as "deny" by the gate
	// (deny-by-default once a policy is active).
	typedUnknown string
}

// resolveLimits computes the effective limits for req.Network: start from the
// default block, then apply the matching per-network override field-by-field with
// the tri-state rule (absent → inherit default; null → no limit; value → enforce).
func resolveLimits(p Policy, network string) resolvedLimits {
	d := p.Rules.Default
	out := resolvedLimits{
		maxTx:            parseLimit(d.MaxTxWei),
		maxDay:           parseLimit(d.MaxDayWei),
		maxGasPrice:      parseLimit(d.MaxGasPriceWei),
		allowlistEnabled: boolOr(d.AllowlistEnabled, false),
		includeSelf:      boolOr(d.IncludeSelf, false),
		// The policy-wide typed_data.unknown is the base; a per-network
		// typed_data_unknown field overrides it below.
		typedUnknown: p.TypedData.Unknown,
	}
	for _, n := range p.Rules.Networks {
		if !strings.EqualFold(n.Network, network) {
			continue
		}
		out.maxTx = overrideLimit(out.maxTx, n.MaxTxWei)
		out.maxDay = overrideLimit(out.maxDay, n.MaxDayWei)
		out.maxGasPrice = overrideLimit(out.maxGasPrice, n.MaxGasPriceWei)
		if n.AllowlistEnabled != nil {
			out.allowlistEnabled = *n.AllowlistEnabled
		}
		if n.IncludeSelf != nil {
			out.includeSelf = *n.IncludeSelf
		}
		if n.TypedDataUnknown != nil {
			out.typedUnknown = *n.TypedDataUnknown
		}
		break
	}
	out.anySet = out.maxTx != nil || out.maxDay != nil || out.maxGasPrice != nil
	return out
}

// parseLimit converts a tri-state limit pointer into a *big.Int limit: absent
// (nil) or explicit null ⇒ nil (no limit); a value ⇒ the parsed amount.
func parseLimit(p *string) *big.Int {
	if p == nil || isNull(p) {
		return nil
	}
	v, ok := new(big.Int).SetString(*p, 10)
	if !ok {
		return nil
	}
	return v
}

// overrideLimit applies a per-network limit field over a current value with the
// tri-state rule: absent (nil) ⇒ keep current; explicit null ⇒ no limit (nil);
// value ⇒ the network value.
func overrideLimit(current *big.Int, p *string) *big.Int {
	if p == nil {
		return current // absent ⇒ inherit
	}
	if isNull(p) {
		return nil // explicit null ⇒ no limit
	}
	if v, ok := new(big.Int).SetString(*p, 10); ok {
		return v
	}
	return current
}

// boolOr dereferences a *bool with a default.
func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// inSelf reports whether dest is in the SEALED self_addresses snapshot (§4.3
// include_self; never the live keystore).
func inSelf(p Policy, dest string) bool {
	for _, s := range p.SelfAddresses {
		if strings.EqualFold(s, dest) {
			return true
		}
	}
	return false
}

// destRole returns "spender" for approvals/permits, "recipient" otherwise, for
// the allowlist payload role field.
func destRole(req Check) string {
	switch req.effectiveKind() {
	case KindApprove, KindPermit:
		return "spender"
	default:
		return "recipient"
	}
}

// lowerHex returns the lowercase 0x hex of an address ("" for the zero address).
func lowerHex(a common.Address) string {
	if a == (common.Address{}) {
		return ""
	}
	return strings.ToLower(a.Hex())
}
