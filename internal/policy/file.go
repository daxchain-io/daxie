package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/policyseal"
)

// file.go owns the §4.5 policy file: the decoded body struct, the two-member
// signed envelope ({version, body_b64, seal}), the hand-built ordered body writer
// (tri-state absent/null/value, fixed key order, decimal-string amounts), the
// two-pass decode (permissive {Version,WrittenBy} then strict
// DisallowUnknownFields), and loadPolicy (verify seal + watermark + version).
//
// THE SEAL COVERS THE EXACT STORED BODY BYTES, never a re-marshaled projection
// (§4.5): on write the body bytes are produced ONCE by writeBody and stored
// verbatim in body_b64; on read the seal is verified over base64decode(body_b64)
// with the "daxie/policy/v1\n" domain prefix, and the body is NEVER re-marshaled
// through structs before verification — so a newer binary verifies an older file
// and unknown fields cannot brick the seal. policyseal is body-agnostic: it
// signs/verifies whatever bytes it is handed.

// policyFileName is the state-class sealed policy file.
const policyFileName = "policy.json"

// envelopeVersion is the current envelope (outer) format version.
const envelopeVersion = 1

// bodyVersion is the current decoded-body schema version. A body whose version is
// newer than this binary's is a fail-closed policy.version refusal (§4.5).
const bodyVersion = 1

// envelope is the two-member signed wrapper stored at policy.json (§4.5). A
// mutation is a single-file atomic write so no torn body/seal pair is possible.
type envelope struct {
	Version int       `json:"version"`
	BodyB64 string    `json:"body_b64"`
	Seal    sealBlock `json:"seal"`
}

// sealBlock carries the detached Ed25519 signature over the canonical body bytes.
// The salt and verify key live in the anchor (§4.6), NOT here — the file alone is
// not self-verifying, which is the point.
type sealBlock struct {
	Alg string `json:"alg"` // "scrypt/ed25519"
	Sig string `json:"sig"` // base64(64B)
}

const sealAlg = "scrypt/ed25519"

// Policy is the decoded policy body (§4.5 schema). Sealed; nonce-covered.
//
// Limits are tri-state nullable decimal strings via *string (nil pointer ⇒ absent
// ⇒ inherit; pointer to JSON null is handled by the custom writer/decoder via the
// Limits struct's pointer fields). The hand-built writeBody renders the tri-state.
type Policy struct {
	Version             int             `json:"version"`
	Nonce               uint64          `json:"nonce"`
	UpdatedAt           string          `json:"updated_at"`
	WrittenBy           string          `json:"written_by"`
	Messages            string          `json:"messages"` // "allow"|"deny" EIP-191 kill switch
	TokensNoAllowlistOK bool            `json:"tokens_no_allowlist_ok"`
	Rules               Rules           `json:"rules"`
	Tokens              []TokenRule     `json:"tokens"`
	Allowlist           []PinEntry      `json:"allowlist"`
	Denylist            []PinEntry      `json:"denylist"`
	SelfAddresses       []string        `json:"self_addresses"`
	TypedData           TypedDataCfg    `json:"typed_data"`
	ContractsAllowed    []ContractAllow `json:"contracts_allowed"`
}

// Rules carries the default limit block + per-network overrides.
type Rules struct {
	Default  Limits        `json:"default"`
	Networks []NetworkRule `json:"networks"`
}

// Limits is a tri-state limit block. Each amount field is *string: a nil pointer
// means ABSENT (inherit the default block); a non-nil pointer to "" is the
// explicit-null sentinel meaning "no limit on this network"; any other value is
// the enforced decimal-wei limit. The bool/enum fields follow the same
// nil=absent convention via pointers. The hand-built writeLimits renders the
// tri-state distinctly (absent → omit; null → literal null; value → marshaled).
type Limits struct {
	MaxTxWei         *string `json:"max_tx_wei"`
	MaxDayWei        *string `json:"max_day_wei"`
	MaxGasPriceWei   *string `json:"max_gas_price_wei"`
	AllowlistEnabled *bool   `json:"allowlist_enabled"`
	IncludeSelf      *bool   `json:"include_self"`
	TypedDataUnknown *string `json:"typed_data_unknown,omitempty"`
}

// nullSentinel is the in-memory marker for an explicit JSON null limit ("no limit
// on this network") distinct from an absent field (nil pointer). On decode a JSON
// null becomes a pointer to this sentinel; the writer renders it back to literal
// null. A real value is never this exact pointer.
const nullSentinel = "\x00null\x00"

// nullStr returns a *string carrying the explicit-null sentinel.
func nullStr() *string { s := nullSentinel; return &s }

// isNull reports whether p is the explicit-null sentinel (vs absent vs a value).
func isNull(p *string) bool { return p != nil && *p == nullSentinel }

// NetworkRule is a per-network override; it embeds Limits so the same tri-state
// rendering applies.
type NetworkRule struct {
	Network string `json:"network"`
	Limits
}

// TokenRule is a per-(network,token) rule. AllowUnlimited is tri-state
// (absent|false hard-deny|true permissive).
type TokenRule struct {
	Network        string `json:"network"`
	Address        string `json:"address"`
	AliasAtSet     string `json:"alias_at_set"`
	AllowUnlimited *bool  `json:"allow_unlimited"`
}

// PinEntry is an allowlist[] or denylist[] entry: a PINNED resolved 0x address
// (never a bare name), with the name/source carried for sign-time name matching
// of contact/ens deny entries and for human display (§4.8).
type PinEntry struct {
	Source     string `json:"source"` // "address"|"contact"|"ens"
	Address    string `json:"address"`
	Name       string `json:"name,omitempty"`
	Label      string `json:"label,omitempty"`
	AddedAt    string `json:"added_at,omitempty"`
	ResolvedAt string `json:"resolved_at,omitempty"`
}

// TypedDataCfg is the typed-data gate config. Allowed[] is RESERVED (M9) — sealed
// + carried; no CLI in M4.
type TypedDataCfg struct {
	Unknown string       `json:"unknown"` // "allow"|"deny"
	Allowed []TypedAllow `json:"allowed"`
}

// TypedAllow is a per-domain typed-data allow entry (RESERVED, M9).
type TypedAllow struct {
	ChainID           int    `json:"chain_id"`
	VerifyingContract string `json:"verifying_contract"`
	PrimaryType       string `json:"primary_type"`
	Label             string `json:"label"`
}

// ContractAllow is a stage-5b unknown-calldata allow entry (RESERVED, M10).
type ContractAllow struct {
	Network  string `json:"network"`
	Contract string `json:"contract"`
	Selector string `json:"selector"`
	Label    string `json:"label"`
	AddedAt  string `json:"added_at"`
}

// SealStatus is the unauthenticated seal-health summary `policy show`/`verify`
// report (§4.7). It never carries a secret.
type SealStatus struct {
	Present      bool   `json:"present"`       // policy.json exists
	AnchorFound  bool   `json:"anchor_found"`  // an anchor is pinned
	Verified     bool   `json:"verified"`      // seal verifies under the pinned key
	Nonce        uint64 `json:"nonce"`         // body nonce (0 if unreadable)
	Watermark    uint64 `json:"watermark"`     // anchor watermark
	WrittenBy    string `json:"written_by"`    // version that wrote the body
	Reason       string `json:"reason"`        // failure reason when !Verified
	AnchorSource string `json:"anchor_source"` // "config" when found
}

// ── paths ────────────────────────────────────────────────────────────────────

// policyPath is the state-class sealed policy file under the engine's state dir.
func (e *Engine) policyPath() string { return filepath.Join(e.dir, policyFileName) }

// ── envelope I/O (shared by load + the admin write/verify paths) ─────────────

// readFileNoFollow reads a fixed state-class file. (The name documents that the
// path is a fixed, daxie-controlled location under the state dir, not user input.)
func readFileNoFollow(path string) ([]byte, error) {
	return os.ReadFile(path) // #nosec G304 -- fixed policy.json under the state dir
}

// parseEnvelope decodes the two-member sealed envelope. A structurally-invalid
// file is a seal violation (fail-closed).
func parseEnvelope(b []byte) (envelope, error) {
	var env envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return envelope{}, domain.Wrap("policy.seal_violation", "policy.json is not a valid sealed envelope", err)
	}
	return env, nil
}

// marshalEnvelope renders the envelope to canonical ordered JSON (version,
// body_b64, seal{alg,sig}). Hand-built so the on-disk shape is stable and the
// seal subject (body_b64) is never re-derived.
func marshalEnvelope(env envelope) ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	b.WriteString(jsonString("version"))
	b.WriteByte(':')
	b.WriteString(itoaInt(env.Version))
	b.WriteByte(',')
	b.WriteString(jsonString("body_b64"))
	b.WriteByte(':')
	b.WriteString(jsonString(env.BodyB64))
	b.WriteByte(',')
	b.WriteString(jsonString("seal"))
	b.WriteByte(':')
	b.WriteByte('{')
	b.WriteString(jsonString("alg"))
	b.WriteByte(':')
	b.WriteString(jsonString(env.Seal.Alg))
	b.WriteByte(',')
	b.WriteString(jsonString("sig"))
	b.WriteByte(':')
	b.WriteString(jsonString(env.Seal.Sig))
	b.WriteByte('}')
	b.WriteByte('}')
	return b.Bytes(), nil
}

// ── load / verify ──────────────────────────────────────────────────────────--

// loadResult is the outcome of a policy load: the decoded body plus the raw body
// bytes (the seal subject), the seal status, and whether the file was present.
type loadResult struct {
	policy  Policy
	bodyB64 string // the stored body_b64 (so a mutation re-signs the exact bytes)
	bodyRaw []byte // base64decode(body_b64) — the canonical seal subject
	seal    sealBlock
	present bool
	status  SealStatus
}

// loadPolicy reads, seal-verifies, anti-rollback-checks, and strictly decodes the
// sealed policy file. The fail-closed direction (§4 intro, §4.3 stage 1):
//
//   - anchor present + policy missing/unparseable   ⇒ policy.seal_violation
//   - policy present + anchor missing               ⇒ policy.seal_violation (anchor_missing)
//   - seal fails to verify under the pinned key      ⇒ policy.seal_violation
//   - body.nonce < anchor.NonceWatermark             ⇒ policy.rollback
//   - body version newer than this binary            ⇒ policy.version (seal family, exit 8)
//   - unknown body fields                            ⇒ policy.version
//
// When NO anchor is pinned AND no policy file exists, loadPolicy returns
// (Policy{}, present=false, nil) — the opt-in no-op case the caller handles.
func loadPolicy(stateDir string, anchor policyseal.Anchor, anchorFound bool) (loadResult, error) {
	path := filepath.Join(stateDir, policyFileName)
	raw, rerr := os.ReadFile(path) // #nosec G304 -- fixed policy.json under the state dir
	present := rerr == nil

	switch {
	case !present && !anchorFound:
		// Opt-in: no anchor, no policy ⇒ guardrails are not configured.
		return loadResult{present: false, status: SealStatus{}}, nil
	case !present && anchorFound:
		// "delete the policy to escape it" is itself a violation when an anchor
		// pins a trust root (§4 intro / §4.6 fail-closed-on-absence).
		return loadResult{}, domain.WithData(
			domain.New("policy.seal_violation",
				"a policy anchor is pinned but policy.json is missing; signing is halted (fail-closed)"),
			map[string]any{"seal_status": "missing", "anchor_source": "config"})
	case present && !anchorFound:
		// A sealed file with no trust root cannot be verified — there is no
		// unpinned verification mode (§4.6).
		return loadResult{}, domain.WithData(
			domain.New("policy.seal_violation",
				"policy.json is present but no anchor is pinned; signing is halted (anchor_missing)"),
			map[string]any{"seal_status": "anchor_missing", "anchor_source": "none"})
	}

	// Parse the envelope.
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return loadResult{}, domain.WithData(
			domain.Wrap("policy.seal_violation", "policy.json is not a valid sealed envelope", err),
			map[string]any{"seal_status": "unparseable", "anchor_source": "config"})
	}
	bodyRaw, err := base64.StdEncoding.DecodeString(env.BodyB64)
	if err != nil {
		return loadResult{}, domain.WithData(
			domain.Wrap("policy.seal_violation", "policy.json body_b64 is not valid base64", err),
			map[string]any{"seal_status": "unparseable", "anchor_source": "config"})
	}
	sig, err := base64.StdEncoding.DecodeString(env.Seal.Sig)
	if err != nil {
		return loadResult{}, domain.WithData(
			domain.Wrap("policy.seal_violation", "policy.json seal.sig is not valid base64", err),
			map[string]any{"seal_status": "bad_sig", "anchor_source": "config"})
	}

	// Verify the detached Ed25519 seal over "daxie/policy/v1\n"||bodyRaw against
	// the anchor-pinned verify key (or the staged verify_key_next during rotation).
	if !verifyUnderAnchor(bodyRaw, sig, anchor) {
		return loadResult{}, domain.WithData(
			domain.New("policy.seal_violation",
				"the policy seal does not verify under the pinned anchor key; signing is halted"),
			map[string]any{"seal_status": "bad_sig", "anchor_source": "config"})
	}

	// Pass 1 (permissive): read {version, written_by} for the skew message + the
	// nonce for the rollback check. The seal is already verified, so this read is
	// over trusted bytes.
	var head struct {
		Version   int    `json:"version"`
		Nonce     uint64 `json:"nonce"`
		WrittenBy string `json:"written_by"`
	}
	if err := json.Unmarshal(bodyRaw, &head); err != nil {
		return loadResult{}, domain.WithData(
			domain.Wrap("policy.seal_violation", "the sealed policy body is not valid JSON", err),
			map[string]any{"seal_status": "unparseable", "anchor_source": "config"})
	}

	// Anti-rollback: refuse a body whose nonce is below the anchor watermark. A
	// bare signature verifies any historically-sealed policy forever; the
	// watermark refusal halts signing on a replayed-older-policy move (§4.6).
	if head.Nonce < anchor.NonceWatermark {
		return loadResult{}, domain.WithData(
			domain.Newf("policy.rollback",
				"the policy nonce %d is below the anchor watermark %d; an older sealed policy was replayed",
				head.Nonce, anchor.NonceWatermark),
			map[string]any{"body_nonce": head.Nonce, "watermark": anchor.NonceWatermark})
	}

	// Version skew is fail-closed: a newer body may carry a RESTRICTION this
	// binary would silently drop (§4.5). It is the `policy.version` member of the
	// seal-violation family (§4.3 stage 1 / §4.9): the CODE is
	// policy.seal_violation (exit 8, guaranteed by the domain registry without a
	// new row), with the canonical "policy.version" string carried in the payload
	// so agents/frontends can still distinguish a skew from a bad signature.
	if head.Version > bodyVersion {
		return loadResult{}, domain.WithData(
			domain.Newf("policy.seal_violation",
				"policy.json was written by %q at body version %d; this binary supports version %d — upgrade agent images to ≥ the version that wrote the policy",
				head.WrittenBy, head.Version, bodyVersion),
			map[string]any{"seal_status": "version", "reason": "policy.version", "anchor_source": "config", "written_by": head.WrittenBy})
	}

	// Pass 2 (strict): DisallowUnknownFields. An unknown field is the same
	// fail-closed `policy.version` refusal — it may be a restriction we'd drop.
	pol, derr := decodeBodyStrict(bodyRaw)
	if derr != nil {
		return loadResult{}, domain.WithData(
			domain.Wrap("policy.seal_violation",
				"policy.json (written by "+head.WrittenBy+") carries fields this binary does not understand; upgrade agent images to ≥ the version that wrote the policy",
				derr),
			map[string]any{"seal_status": "version", "reason": "policy.version", "anchor_source": "config", "written_by": head.WrittenBy})
	}

	return loadResult{
		policy:  pol,
		bodyB64: env.BodyB64,
		bodyRaw: bodyRaw,
		seal:    env.Seal,
		present: true,
		status: SealStatus{
			Present: true, AnchorFound: true, Verified: true,
			Nonce: pol.Nonce, Watermark: anchor.NonceWatermark,
			WrittenBy: pol.WrittenBy, AnchorSource: "config",
		},
	}, nil
}

// verifyUnderAnchor verifies the detached seal under the anchor's verify_key, then
// (during a staged rotation) under verify_key_next. Either matching ⇒ verified.
func verifyUnderAnchor(bodyRaw, sig []byte, anchor policyseal.Anchor) bool {
	if pk, err := anchor.VerifyKeyBytes(); err == nil {
		if policyseal.Verify(bodyRaw, sig, pk) {
			return true
		}
	}
	if pk, ok, err := anchor.VerifyKeyNextBytes(); err == nil && ok {
		if policyseal.Verify(bodyRaw, sig, pk) {
			return true
		}
	}
	return false
}

// decodeBodyStrict strictly decodes the body bytes with DisallowUnknownFields.
// Because Limits uses *string for the tri-state and encoding/json maps a JSON
// null to a nil pointer (NOT the null sentinel), we post-process: a field that
// was PRESENT-and-null must become the null sentinel, while an ABSENT field stays
// nil. We detect presence with a raw-map pre-scan keyed only on the limit blocks.
func decodeBodyStrict(bodyRaw []byte) (Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(bodyRaw))
	dec.DisallowUnknownFields()
	var pol Policy
	if err := dec.Decode(&pol); err != nil {
		return Policy{}, err
	}
	// Distinguish present-null from absent for the tri-state limit fields.
	reconcileTriState(bodyRaw, &pol)
	return pol, nil
}

// reconcileTriState walks the raw JSON to mark fields that were present-and-null
// (the "no limit" sentinel) vs absent (inherit). encoding/json collapses both to
// a nil pointer, so the writer cannot otherwise tell them apart on round-trip.
func reconcileTriState(bodyRaw []byte, pol *Policy) {
	var rawTop map[string]json.RawMessage
	if json.Unmarshal(bodyRaw, &rawTop) != nil {
		return
	}
	var rawRules map[string]json.RawMessage
	if rr, ok := rawTop["rules"]; ok {
		_ = json.Unmarshal(rr, &rawRules)
	}
	if dr, ok := rawRules["default"]; ok {
		applyTriState(dr, &pol.Rules.Default)
	}
	if nr, ok := rawRules["networks"]; ok {
		var arr []json.RawMessage
		if json.Unmarshal(nr, &arr) == nil {
			for i := range arr {
				if i < len(pol.Rules.Networks) {
					applyTriState(arr[i], &pol.Rules.Networks[i].Limits)
				}
			}
		}
	}
}

// applyTriState inspects one limit object's raw JSON and converts present-null
// fields from nil to the null sentinel so the writer re-emits literal null.
func applyTriState(rawObj json.RawMessage, lim *Limits) {
	var m map[string]json.RawMessage
	if json.Unmarshal(rawObj, &m) != nil {
		return
	}
	isPresentNull := func(key string) bool {
		v, ok := m[key]
		return ok && string(bytes.TrimSpace(v)) == "null"
	}
	if lim.MaxTxWei == nil && isPresentNull("max_tx_wei") {
		lim.MaxTxWei = nullStr()
	}
	if lim.MaxDayWei == nil && isPresentNull("max_day_wei") {
		lim.MaxDayWei = nullStr()
	}
	if lim.MaxGasPriceWei == nil && isPresentNull("max_gas_price_wei") {
		lim.MaxGasPriceWei = nullStr()
	}
}

// ── canonical body writer (the seal subject producer) ────────────────────────

// writeBody renders the decoded Policy to the canonical ordered body bytes the
// seal covers (§4.5): fixed key order, decimal-string amounts, tri-state
// absent/null/value rendering for nullable limits. Two writers at the same
// version produce byte-identical output (a reproducibility convention, not a
// security property — the seal covers whatever bytes are stored). The output is
// compact (no insignificant whitespace) so byte-stability is robust.
func writeBody(p Policy) []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	w := &fieldWriter{buf: &b}

	w.intField("version", p.Version)
	w.uintField("nonce", p.Nonce)
	w.strField("updated_at", p.UpdatedAt)
	w.strField("written_by", p.WrittenBy)
	w.strField("messages", p.Messages)
	w.boolField("tokens_no_allowlist_ok", p.TokensNoAllowlistOK)

	w.rawKey("rules")
	writeRules(&b, p.Rules)
	w.afterRaw()

	w.rawKey("tokens")
	writeTokens(&b, p.Tokens)
	w.afterRaw()

	w.rawKey("allowlist")
	writePins(&b, p.Allowlist)
	w.afterRaw()

	w.rawKey("denylist")
	writePins(&b, p.Denylist)
	w.afterRaw()

	w.rawKey("self_addresses")
	writeStrings(&b, p.SelfAddresses)
	w.afterRaw()

	w.rawKey("typed_data")
	writeTypedData(&b, p.TypedData)
	w.afterRaw()

	w.rawKey("contracts_allowed")
	writeContracts(&b, p.ContractsAllowed)
	w.afterRaw()

	b.WriteByte('}')
	return b.Bytes()
}

// fieldWriter emits comma-separated "key":value pairs into a JSON object,
// tracking whether a leading comma is needed.
type fieldWriter struct {
	buf  *bytes.Buffer
	some bool
}

func (w *fieldWriter) comma() {
	if w.some {
		w.buf.WriteByte(',')
	}
	w.some = true
}
func (w *fieldWriter) key(k string) {
	w.comma()
	w.buf.WriteString(jsonString(k))
	w.buf.WriteByte(':')
}
func (w *fieldWriter) strField(k, v string) { w.key(k); w.buf.WriteString(jsonString(v)) }
func (w *fieldWriter) intField(k string, v int) {
	w.key(k)
	w.buf.WriteString(itoaInt(v))
}
func (w *fieldWriter) uintField(k string, v uint64) {
	w.key(k)
	w.buf.WriteString(utoa(v))
}
func (w *fieldWriter) boolField(k string, v bool) {
	w.key(k)
	if v {
		w.buf.WriteString("true")
	} else {
		w.buf.WriteString("false")
	}
}

// rawKey writes the key and a colon, leaving the caller to write the raw value;
// afterRaw marks the field present so the next field gets its leading comma.
func (w *fieldWriter) rawKey(k string) { w.key(k) }
func (w *fieldWriter) afterRaw()       {}

// writeRules renders the rules block (default + networks).
func writeRules(b *bytes.Buffer, r Rules) {
	b.WriteByte('{')
	b.WriteString(jsonString("default"))
	b.WriteByte(':')
	writeLimits(b, r.Default, false)
	b.WriteByte(',')
	b.WriteString(jsonString("networks"))
	b.WriteByte(':')
	b.WriteByte('[')
	for i, n := range r.Networks {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('{')
		b.WriteString(jsonString("network"))
		b.WriteByte(':')
		b.WriteString(jsonString(n.Network))
		b.WriteByte(',')
		writeLimitsInline(b, n.Limits, true)
		b.WriteByte('}')
	}
	b.WriteByte(']')
	b.WriteByte('}')
}

// writeLimits renders a limit block as its own object. perNetwork toggles the
// optional typed_data_unknown field. The tri-state rule: absent (nil) → OMIT;
// null sentinel → literal null; value → the decimal string / literal.
func writeLimits(b *bytes.Buffer, l Limits, perNetwork bool) {
	b.WriteByte('{')
	writeLimitsInline(b, l, perNetwork)
	b.WriteByte('}')
}

// writeLimitsInline writes the limit fields without the surrounding braces (so a
// network rule can prefix "network" first).
func writeLimitsInline(b *bytes.Buffer, l Limits, perNetwork bool) {
	first := true
	emit := func(key string, p *string) {
		if p == nil {
			return // absent ⇒ omit
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(jsonString(key))
		b.WriteByte(':')
		if isNull(p) {
			b.WriteString("null")
		} else {
			b.WriteString(jsonString(*p))
		}
	}
	emitBool := func(key string, p *bool) {
		if p == nil {
			return
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(jsonString(key))
		b.WriteByte(':')
		if *p {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	}
	emit("max_tx_wei", l.MaxTxWei)
	emit("max_day_wei", l.MaxDayWei)
	emit("max_gas_price_wei", l.MaxGasPriceWei)
	emitBool("allowlist_enabled", l.AllowlistEnabled)
	emitBool("include_self", l.IncludeSelf)
	if l.TypedDataUnknown != nil && perNetwork {
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(jsonString("typed_data_unknown"))
		b.WriteByte(':')
		b.WriteString(jsonString(*l.TypedDataUnknown))
	}
}

// writeTokens renders the tokens[] array, sorted by (network,address) for
// byte-stability and with allow_unlimited tri-state.
func writeTokens(b *bytes.Buffer, ts []TokenRule) {
	sorted := append([]TokenRule(nil), ts...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Network != sorted[j].Network {
			return sorted[i].Network < sorted[j].Network
		}
		return sorted[i].Address < sorted[j].Address
	})
	b.WriteByte('[')
	for i, t := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('{')
		b.WriteString(jsonString("network"))
		b.WriteByte(':')
		b.WriteString(jsonString(t.Network))
		b.WriteByte(',')
		b.WriteString(jsonString("address"))
		b.WriteByte(':')
		b.WriteString(jsonString(t.Address))
		b.WriteByte(',')
		b.WriteString(jsonString("alias_at_set"))
		b.WriteByte(':')
		b.WriteString(jsonString(t.AliasAtSet))
		b.WriteByte(',')
		b.WriteString(jsonString("allow_unlimited"))
		b.WriteByte(':')
		if t.AllowUnlimited == nil {
			b.WriteString("null")
		} else if *t.AllowUnlimited {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
		b.WriteByte('}')
	}
	b.WriteByte(']')
}

// writePins renders an allowlist[]/denylist[] array, sorted by (source,address,name)
// for byte-stability. Omitted optional fields are not emitted.
func writePins(b *bytes.Buffer, ps []PinEntry) {
	sorted := append([]PinEntry(nil), ps...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Source != sorted[j].Source {
			return sorted[i].Source < sorted[j].Source
		}
		if sorted[i].Address != sorted[j].Address {
			return sorted[i].Address < sorted[j].Address
		}
		return sorted[i].Name < sorted[j].Name
	})
	b.WriteByte('[')
	for i, p := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		fw := &fieldWriter{buf: b}
		b.WriteByte('{')
		fw.strField("source", p.Source)
		fw.strField("address", p.Address)
		if p.Name != "" {
			fw.strField("name", p.Name)
		}
		if p.Label != "" {
			fw.strField("label", p.Label)
		}
		if p.AddedAt != "" {
			fw.strField("added_at", p.AddedAt)
		}
		if p.ResolvedAt != "" {
			fw.strField("resolved_at", p.ResolvedAt)
		}
		b.WriteByte('}')
	}
	b.WriteByte(']')
}

// writeStrings renders a []string sorted ascending for byte-stability.
func writeStrings(b *bytes.Buffer, ss []string) {
	sorted := append([]string(nil), ss...)
	sort.Strings(sorted)
	b.WriteByte('[')
	for i, s := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString(s))
	}
	b.WriteByte(']')
}

// writeTypedData renders the typed_data block (unknown + allowed[]).
func writeTypedData(b *bytes.Buffer, td TypedDataCfg) {
	b.WriteByte('{')
	b.WriteString(jsonString("unknown"))
	b.WriteByte(':')
	b.WriteString(jsonString(td.Unknown))
	b.WriteByte(',')
	b.WriteString(jsonString("allowed"))
	b.WriteByte(':')
	sorted := append([]TypedAllow(nil), td.Allowed...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ChainID != sorted[j].ChainID {
			return sorted[i].ChainID < sorted[j].ChainID
		}
		if sorted[i].VerifyingContract != sorted[j].VerifyingContract {
			return sorted[i].VerifyingContract < sorted[j].VerifyingContract
		}
		return sorted[i].PrimaryType < sorted[j].PrimaryType
	})
	b.WriteByte('[')
	for i, a := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('{')
		fw := &fieldWriter{buf: b}
		fw.intField("chain_id", a.ChainID)
		fw.strField("verifying_contract", a.VerifyingContract)
		fw.strField("primary_type", a.PrimaryType)
		fw.strField("label", a.Label)
		b.WriteByte('}')
	}
	b.WriteByte(']')
	b.WriteByte('}')
}

// writeContracts renders the contracts_allowed[] array, sorted by
// (network,contract,selector).
func writeContracts(b *bytes.Buffer, cs []ContractAllow) {
	sorted := append([]ContractAllow(nil), cs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Network != sorted[j].Network {
			return sorted[i].Network < sorted[j].Network
		}
		if sorted[i].Contract != sorted[j].Contract {
			return sorted[i].Contract < sorted[j].Contract
		}
		return sorted[i].Selector < sorted[j].Selector
	})
	b.WriteByte('[')
	for i, c := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('{')
		fw := &fieldWriter{buf: b}
		fw.strField("network", c.Network)
		fw.strField("contract", c.Contract)
		fw.strField("selector", c.Selector)
		fw.strField("label", c.Label)
		fw.strField("added_at", c.AddedAt)
		b.WriteByte('}')
	}
	b.WriteByte(']')
}

// ── small JSON encoding helpers (no float, no reflect) ────────────────────────

// jsonString encodes s as a JSON string with the minimal, deterministic escape
// set. We hand-roll it (rather than json.Marshal) so the body bytes are byte
// stable and never HTML-escaped — the seal covers exactly these bytes.
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				const hex = "0123456789abcdef"
				b.WriteByte(hex[(r>>4)&0xf])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// itoaInt formats a non-negative-ish int (versions are small) in base 10.
func itoaInt(v int) string { return big.NewInt(int64(v)).String() }

// utoa formats a uint64 in base 10.
func utoa(v uint64) string { return new(big.Int).SetUint64(v).String() }
