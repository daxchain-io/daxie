package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
	"github.com/daxchain-io/daxie/internal/policyseal"
	"github.com/daxchain-io/daxie/internal/secret"
	"github.com/ethereum/go-ethereum/common"
)

// admin.go is the §4.7 admin-auth mutation surface. Two secrets, never
// interchangeable (§4.7): the keystore passphrase signs WITHIN policy; the admin
// passphrase DEFINES policy. The admin passphrase is secret.Bytes — never string,
// never logged; its revealed bytes flow only into policyseal.DeriveSealKey and are
// zeroed by that package.
//
// Every mutating command runs the §4.7 pipeline: read policy + anchor; derive
// (sk, pk) from the supplied passphrase + anchor.salt; pk != anchor.VerifyKey (and
// != VerifyKeyNext) ⇒ policy.admin_auth, stop; verify the seal over the decoded
// body (policy.seal_violation on mismatch); apply the mutation; nonce++; refresh
// self_addresses; re-sign over the exact new bytes; write the envelope atomically
// (state class); bump anchor.NonceWatermark; RETURN the new Anchor so the service
// writes the config-class anchor SECOND (the K8s two-domain ordering, §4.7).
//
// The engine writes ONLY policy.json (state class). It never writes the anchor —
// config (Group C) owns the config-class write, fed the returned Anchor. This
// keeps the "policy file first, then anchor" ordering and supports the K8s
// read-only-config case (the caller emits the anchor to stdout/--anchor-out).

// Change is the request the cli fills for `policy set` (limits/gas-cap/allowlist/
// include-self/typed-unknown/messages/allow-tokens-without-allowlist/per-token
// allow-unlimited/per-network overrides). A nil pointer field means "leave
// unchanged"; the tri-state literals none/inherit are encoded by the cli into the
// Limits pointers (nil=inherit, nullStr()=none/no-limit, value=enforce).
type Change struct {
	Default         *Limits          // nil ⇒ leave the default block unchanged
	Networks        []NetworkRule    // upserted per-network overrides (replace-by-network)
	Messages        *string          // "allow"|"deny"
	TokensNoAllowOK *bool            // --allow-tokens-without-allowlist
	TypedUnknown    *string          // typed_data.unknown "allow"|"deny"
	Tokens          []TokenRule      // upserted token rules (replace-by-(network,address))
	RefreshSelf     []common.Address // the live keystore snapshot to seal into self_addresses
	WrittenBy       string           // the binary version stamping written_by
}

// AllowEntry / DenyEntry are the `policy allow`/`policy deny` request structs. The
// cli resolves the input to a pinned 0x address BEFORE calling (ENS resolved now,
// contacts snapshotted) — the engine pins exactly what it is handed (§4.8).
type AllowEntry struct {
	PinEntry
	Remove      bool             // --remove
	RefreshSelf []common.Address // the live keystore snapshot to re-seal
	WrittenBy   string
}
type DenyEntry struct {
	PinEntry
	Remove      bool
	RefreshSelf []common.Address
	WrittenBy   string
}

// Show reports the current policy + seal status (UNAUTHENTICATED, §4.7). When no
// anchor + no policy, it returns a zero Policy with present=false in the status.
func (e *Engine) Show() (Policy, SealStatus, error) {
	res, err := loadPolicy(e.dir, e.anchor, e.anchorFound)
	if err != nil {
		// Surface the seal status alongside the error so `policy show` can render a
		// halted state without exiting non-zero on a read.
		var de *domain.Error
		if errors.As(err, &de) {
			st := SealStatus{AnchorFound: e.anchorFound, Watermark: e.anchor.NonceWatermark, Reason: de.Msg}
			if e.anchorFound {
				st.AnchorSource = "config"
			}
			return Policy{}, st, err
		}
		return Policy{}, SealStatus{}, err
	}
	return res.policy, res.status, nil
}

// Verify reports whether the on-disk policy seal verifies under the pinned anchor
// (exit 0/8, anchor-based, NO passphrase — CI-friendly, §4.7). It returns
// (true, status, nil) on a good seal and (false, status, err) on any
// seal/rollback/version failure.
func (e *Engine) Verify() (bool, SealStatus, error) {
	res, err := loadPolicy(e.dir, e.anchor, e.anchorFound)
	if err != nil {
		var de *domain.Error
		if errors.As(err, &de) {
			st := SealStatus{AnchorFound: e.anchorFound, Watermark: e.anchor.NonceWatermark, Reason: de.Msg}
			if e.anchorFound {
				st.AnchorSource = "config"
			}
			return false, st, err
		}
		return false, SealStatus{}, err
	}
	if !res.present {
		// Opt-in (no anchor, no policy): nothing to verify, not a failure.
		return true, res.status, nil
	}
	return true, res.status, nil
}

// WhatIf runs the pure Evaluate against a Check WITHOUT a reservation (`policy
// check`, §4.7). It is Evaluate's read-only twin — same verdict, no durable write.
func (e *Engine) WhatIf(ctx context.Context, req Check) (Decision, error) {
	return e.Evaluate(ctx, req)
}

// PinPrint re-emits the current anchor JSON (the passphrase-free `policy pin
// --print`, §4.6). The caller writes it to stdout / --anchor-out.
func (e *Engine) PinPrint() (policyseal.Anchor, error) {
	if !e.anchorFound {
		return policyseal.Anchor{}, domain.New("policy.seal_violation",
			"no anchor is pinned; run `daxie policy set` to bootstrap one")
	}
	return e.anchor, nil
}

// PinVerify reports whether the on-disk policy.json verifies under a SUPPLIED
// candidate verify key (the passphrase-free canary `policy pin --verify <key>`,
// §4.6). Run as a one-off K8s Job against the candidate ConfigMap value BEFORE
// cutover so a fat-finger becomes a canary, not a fleet-wide refusal.
func (e *Engine) PinVerify(candidateKey string) (bool, error) {
	cand := policyseal.Anchor{VerifyKey: candidateKey}
	pk, err := cand.VerifyKeyBytes()
	if err != nil {
		return false, domain.New("usage.bad_key", "the supplied candidate key is not a valid ed25519 verify key")
	}
	res, rerr := e.readEnvelopeForVerify()
	if rerr != nil {
		return false, rerr
	}
	return policyseal.Verify(res.bodyRaw, res.sig, pk), nil
}

// envelopeRaw is the decoded envelope bytes for a passphrase-free verify.
type envelopeRaw struct {
	bodyRaw []byte
	sig     []byte
}

// readEnvelopeForVerify reads + base64-decodes the policy.json envelope WITHOUT
// verifying it (PinVerify supplies its own key). A missing file is a seal
// violation.
func (e *Engine) readEnvelopeForVerify() (envelopeRaw, error) {
	b, err := readFileNoFollow(e.policyPath())
	if err != nil {
		return envelopeRaw{}, domain.New("policy.seal_violation", "policy.json is missing; nothing to verify")
	}
	env, perr := parseEnvelope(b)
	if perr != nil {
		return envelopeRaw{}, perr
	}
	bodyRaw, derr := base64.StdEncoding.DecodeString(env.BodyB64)
	if derr != nil {
		return envelopeRaw{}, domain.New("policy.seal_violation", "policy.json body_b64 is not valid base64")
	}
	sig, serr := base64.StdEncoding.DecodeString(env.Seal.Sig)
	if serr != nil {
		return envelopeRaw{}, domain.New("policy.seal_violation", "policy.json seal.sig is not valid base64")
	}
	return envelopeRaw{bodyRaw: bodyRaw, sig: sig}, nil
}

// InitSeal bootstraps the anchor on the FIRST `policy set` (§4.6): generate the
// salt, derive the verify key from the admin passphrase, and return the anchor
// with watermark 0. It does NOT write the policy file — Set calls it then writes a
// default sealed body at nonce 1. Refuses to replace an existing trust root.
func (e *Engine) InitSeal(adminPass *secret.Bytes) (policyseal.Anchor, error) {
	if e.anchorFound {
		return policyseal.Anchor{}, domain.New("policy.admin_auth",
			"an anchor is already pinned; `policy set` updates it but will not replace the trust root")
	}
	if adminPass == nil || adminPass.Len() == 0 {
		return policyseal.Anchor{}, domain.New("policy.admin_auth", "an admin passphrase is required to bootstrap the policy anchor")
	}
	salt, err := policyseal.NewSalt()
	if err != nil {
		return policyseal.Anchor{}, domain.Wrap("policy.state_error", "cannot generate the anchor salt", err)
	}
	params := policyseal.DefaultScryptParams()
	sk, pk, err := policyseal.DeriveSealKey(adminPass.Reveal(), salt, params)
	if err != nil {
		return policyseal.Anchor{}, domain.New("policy.admin_auth", "cannot derive the seal key from the admin passphrase")
	}
	zeroKey(sk)
	return policyseal.Anchor{
		VerifyKey:      policyseal.EncodeKey(pk),
		Salt:           policyseal.EncodeSalt(salt),
		Scrypt:         params,
		NonceWatermark: 0,
	}, nil
}

// Set applies a Change under the admin passphrase (§4.7). The FIRST set bootstraps
// the anchor (InitSeal) and seals a default body merged with the Change at nonce 1;
// subsequent sets verify-auth → mutate → nonce++ → refresh self → reseal → bump
// watermark. Returns the new Anchor for the caller to write SECOND.
func (e *Engine) Set(adminPass *secret.Bytes, c Change) (policyseal.Anchor, error) {
	if e.anchorFound {
		return e.mutate(adminPass, c.WrittenBy, c.RefreshSelf, func(p *Policy) error {
			applyChange(p, c)
			return nil
		})
	}
	// Bootstrap path: derive the anchor, build a default body merged with the
	// Change, seal at nonce 1, write policy.json, return the anchor.
	anchor, err := e.InitSeal(adminPass)
	if err != nil {
		return policyseal.Anchor{}, err
	}
	body := defaultPolicy(c.WrittenBy)
	applyChange(&body, c)
	body.SelfAddresses = lowerAll(c.RefreshSelf)
	body.Nonce = 1
	body.UpdatedAt = e.now().UTC().Format(time.RFC3339)
	sealed, serr := e.sealAndWrite(adminPass, anchor, body)
	if serr != nil {
		return policyseal.Anchor{}, serr
	}
	_ = sealed
	anchor.NonceWatermark = 1
	// The engine now trusts the freshly-written anchor for subsequent in-process
	// reads (the caller persists it to the config class).
	e.anchor = anchor
	e.anchorFound = true
	return anchor, nil
}

// Allow adds (or removes with --remove) an allowlist pin under the admin
// passphrase (§4.8). The cli pre-resolves the input to a pinned 0x address.
func (e *Engine) Allow(adminPass *secret.Bytes, entry AllowEntry) (policyseal.Anchor, error) {
	return e.mutate(adminPass, entry.WrittenBy, entry.RefreshSelf, func(p *Policy) error {
		if entry.Remove {
			p.Allowlist = removePin(p.Allowlist, entry.PinEntry)
			return nil
		}
		p.Allowlist = upsertPin(p.Allowlist, entry.PinEntry)
		return nil
	})
}

// Deny adds (or removes) a denylist pin under the admin passphrase (§4.8).
func (e *Engine) Deny(adminPass *secret.Bytes, entry DenyEntry) (policyseal.Anchor, error) {
	return e.mutate(adminPass, entry.WrittenBy, entry.RefreshSelf, func(p *Policy) error {
		if entry.Remove {
			p.Denylist = removePin(p.Denylist, entry.PinEntry)
			return nil
		}
		p.Denylist = upsertPin(p.Denylist, entry.PinEntry)
		return nil
	})
}

// CountersRelease releases a stuck reservation by id under the admin passphrase
// (`policy counters release <id>`, §4.7). It authenticates (the admin owns the
// counters), then releases the reservation if it is still pre-signature (a
// committed reservation is never released — over-count is safe). Returns no anchor
// (the counter is state class, not the sealed file).
func (e *Engine) CountersRelease(ctx context.Context, adminPass *secret.Bytes, id string) error {
	if _, _, err := e.authenticate(adminPass); err != nil {
		return err
	}
	return e.Release(ctx, id)
}

// ChangeAdminPassphrase runs the staged, zero-outage rotation (§4.6/§4.7). With
// stage=true: authenticate cur against the anchor, derive the new key family from
// a fresh salt, record (verify_key_next, staged_salt) into the returned anchor —
// the loader keeps verifying under the old key meanwhile. With commit=true:
// re-derive from staged_salt, assert the derived key equals verify_key_next,
// reseal the body under the new family, promote verify_key_next → verify_key, and
// clear staged_salt. Exactly one of stage/commit must be set.
func (e *Engine) ChangeAdminPassphrase(adminPass *secret.Bytes, next *secret.Bytes, stage, commit bool) (policyseal.Anchor, error) {
	if stage == commit {
		return policyseal.Anchor{}, domain.New("usage.bad_flags", "exactly one of --stage or --commit must be set")
	}
	if !e.anchorFound {
		return policyseal.Anchor{}, domain.New("policy.seal_violation", "no anchor is pinned; nothing to rotate")
	}
	// Authenticate the CURRENT passphrase against the anchor in both phases.
	if _, _, err := e.authenticate(adminPass); err != nil {
		return policyseal.Anchor{}, err
	}
	if next == nil || next.Len() == 0 {
		return policyseal.Anchor{}, domain.New("policy.admin_auth", "a new admin passphrase is required to rotate")
	}

	if stage {
		newKey, stagedSalt, err := policyseal.StageRotation(next.Reveal(), e.anchor.Scrypt)
		if err != nil {
			return policyseal.Anchor{}, domain.New("policy.admin_auth", "cannot derive the new seal key from the new admin passphrase")
		}
		anchor := e.anchor
		anchor.VerifyKeyNext = newKey
		anchor.StagedSalt = policyseal.EncodeSalt(stagedSalt)
		e.anchor = anchor
		return anchor, nil
	}

	// commit: re-derive + assert + reseal under the new key family.
	fam, err := policyseal.CommitRotation(next.Reveal(), e.anchor, e.anchor.Scrypt)
	if err != nil {
		if errors.Is(err, policyseal.ErrRotationKeyMismatch) {
			return policyseal.Anchor{}, domain.New("policy.admin_auth", "the new passphrase does not derive the staged verify key; commit refused")
		}
		if errors.Is(err, policyseal.ErrNoStagedRotation) {
			return policyseal.Anchor{}, domain.New("usage.no_staged_rotation", "no staged rotation to commit; run --stage first")
		}
		return policyseal.Anchor{}, domain.Wrap("policy.admin_auth", "cannot commit the rotation", err)
	}
	defer zeroKey(fam.Private)

	// Load the current body (verifies under the OLD key still pinned), bump nonce,
	// reseal under the new key, write. The new anchor promotes next → current.
	res, lerr := loadPolicy(e.dir, e.anchor, true)
	if lerr != nil {
		return policyseal.Anchor{}, lerr
	}
	body := res.policy
	body.Nonce++
	body.UpdatedAt = e.now().UTC().Format(time.RFC3339)
	newBodyBytes := writeBody(body)
	sig := policyseal.Sign(newBodyBytes, fam.Private)
	if werr := e.writeEnvelope(newBodyBytes, sig); werr != nil {
		return policyseal.Anchor{}, werr
	}
	anchor := e.anchor
	anchor.VerifyKey = policyseal.EncodeKey(fam.Public)
	anchor.VerifyKeyNext = ""
	anchor.Salt = policyseal.EncodeSalt(fam.Salt)
	anchor.StagedSalt = ""
	if body.Nonce > anchor.NonceWatermark {
		anchor.NonceWatermark = body.Nonce
	}
	e.anchor = anchor
	return anchor, nil
}

// ResetForce reseals a fresh DEFAULT body under the EXISTING key family,
// authenticating against the ANCHOR not the file (§4.7 J12). The one carve-out
// exempt from the file checks (it recovers exactly the files the pipeline
// refuses), NEVER from authentication: a prompt-compromised agent that trashes
// policy.json cannot reset under a passphrase of its OWN choosing, because its
// passphrase never derives the pinned key. There is NO --yes bypass. When the
// anchor is missing/destroyed, reset refuses (recovery is out-of-band).
func (e *Engine) ResetForce(adminPass *secret.Bytes, refreshSelf []common.Address, writtenBy string) (policyseal.Anchor, error) {
	if !e.anchorFound {
		return policyseal.Anchor{}, domain.New("policy.admin_auth",
			"no anchor is pinned; reset cannot authenticate — remove the anchor and re-run the bootstrap `policy set` out-of-band")
	}
	sk, _, err := e.authenticate(adminPass)
	if err != nil {
		return policyseal.Anchor{}, err
	}
	defer zeroKey(sk)

	// Fresh default body; nonce restarts at watermark+1; self re-snapshotted.
	body := defaultPolicy(writtenBy)
	body.Nonce = e.anchor.NonceWatermark + 1
	body.SelfAddresses = lowerAll(refreshSelf)
	body.UpdatedAt = e.now().UTC().Format(time.RFC3339)
	newBodyBytes := writeBody(body)
	sig := policyseal.Sign(newBodyBytes, sk)
	if werr := e.writeEnvelope(newBodyBytes, sig); werr != nil {
		return policyseal.Anchor{}, werr
	}
	anchor := e.anchor
	anchor.NonceWatermark = body.Nonce
	e.anchor = anchor
	return anchor, nil
}

// ── the shared §4.7 mutation pipeline ────────────────────────────────────────

// mutate is the common verify→mutate→nonce++→refresh-self→reseal→bump-watermark
// flow for Set/Allow/Deny. It authenticates against the anchor, loads + verifies
// the current body, applies mut, bumps the nonce, refreshes self_addresses, re-
// signs the EXACT new bytes, writes the envelope, and returns the bumped anchor.
func (e *Engine) mutate(adminPass *secret.Bytes, writtenBy string, refreshSelf []common.Address, mut func(*Policy) error) (policyseal.Anchor, error) {
	sk, _, err := e.authenticate(adminPass)
	if err != nil {
		return policyseal.Anchor{}, err
	}
	defer zeroKey(sk)

	res, lerr := loadPolicy(e.dir, e.anchor, e.anchorFound)
	if lerr != nil {
		return policyseal.Anchor{}, lerr
	}
	body := res.policy
	if !res.present {
		body = defaultPolicy(writtenBy)
	}
	if merr := mut(&body); merr != nil {
		return policyseal.Anchor{}, merr
	}
	body.Nonce++
	if body.Nonce <= e.anchor.NonceWatermark {
		body.Nonce = e.anchor.NonceWatermark + 1
	}
	if writtenBy != "" {
		body.WrittenBy = writtenBy
	}
	if refreshSelf != nil {
		body.SelfAddresses = lowerAll(refreshSelf)
	}
	body.UpdatedAt = e.now().UTC().Format(time.RFC3339)

	newBodyBytes := writeBody(body)
	sig := policyseal.Sign(newBodyBytes, sk)
	if werr := e.writeEnvelope(newBodyBytes, sig); werr != nil {
		return policyseal.Anchor{}, werr
	}
	anchor := e.anchor
	if body.Nonce > anchor.NonceWatermark {
		anchor.NonceWatermark = body.Nonce
	}
	e.anchor = anchor
	return anchor, nil
}

// authenticate derives (sk, pk) from the admin passphrase + anchor.salt and
// constant-time compares pk to anchor.VerifyKey (or VerifyKeyNext during a staged
// rotation). A mismatch is policy.admin_auth; a match returns the live sk (the
// CALLER MUST zero it). This is the §4.5 "the pinned key IS the verifier"
// construction — wrong-pass vs tampered-file discrimination without a separate
// verifier blob (pk mismatch ⇒ admin_auth; pk match but bad sig on load ⇒
// seal_violation).
func (e *Engine) authenticate(adminPass *secret.Bytes) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if !e.anchorFound {
		return nil, nil, domain.New("policy.admin_auth", "no anchor is pinned; cannot authenticate an admin mutation")
	}
	if adminPass == nil || adminPass.Len() == 0 {
		return nil, nil, domain.New("policy.admin_auth", "an admin passphrase is required")
	}
	salt, err := e.anchor.SaltBytes()
	if err != nil {
		return nil, nil, domain.Wrap("policy.state_error", "the anchor salt is malformed", err)
	}
	sk, pk, err := policyseal.DeriveSealKey(adminPass.Reveal(), salt, e.anchor.Scrypt)
	if err != nil {
		return nil, nil, domain.New("policy.admin_auth", "cannot derive the seal key from the admin passphrase")
	}
	want, werr := e.anchor.VerifyKeyBytes()
	if werr == nil && subtle.ConstantTimeCompare(pk, want) == 1 {
		return sk, pk, nil
	}
	if next, ok, nerr := e.anchor.VerifyKeyNextBytes(); nerr == nil && ok {
		if subtle.ConstantTimeCompare(pk, next) == 1 {
			return sk, pk, nil
		}
	}
	zeroKey(sk)
	return nil, nil, domain.New("policy.admin_auth",
		"the admin passphrase does not derive the pinned verify key")
}

// sealAndWrite seals body under the anchor's key family (re-deriving sk from the
// admin passphrase) and writes the envelope. Used only by the bootstrap Set path
// (the normal path re-uses the sk from authenticate). Returns the sealed body
// bytes for the caller.
func (e *Engine) sealAndWrite(adminPass *secret.Bytes, anchor policyseal.Anchor, body Policy) ([]byte, error) {
	salt, err := anchor.SaltBytes()
	if err != nil {
		return nil, domain.Wrap("policy.state_error", "the anchor salt is malformed", err)
	}
	sk, _, derr := policyseal.DeriveSealKey(adminPass.Reveal(), salt, anchor.Scrypt)
	if derr != nil {
		return nil, domain.New("policy.admin_auth", "cannot derive the seal key from the admin passphrase")
	}
	defer zeroKey(sk)
	bodyBytes := writeBody(body)
	sig := policyseal.Sign(bodyBytes, sk)
	if werr := e.writeEnvelope(bodyBytes, sig); werr != nil {
		return nil, werr
	}
	return bodyBytes, nil
}

// writeEnvelope atomically writes the two-member sealed envelope to policy.json
// (state class) via fsx.WriteAtomic. A read-only state volume maps to
// config.read_only. The body bytes are stored verbatim in body_b64 (the seal
// subject) so verification never re-marshals through structs (§4.5).
func (e *Engine) writeEnvelope(bodyBytes, sig []byte) error {
	env := envelope{
		Version: envelopeVersion,
		BodyB64: base64.StdEncoding.EncodeToString(bodyBytes),
		Seal:    sealBlock{Alg: sealAlg, Sig: base64.StdEncoding.EncodeToString(sig)},
	}
	b, err := marshalEnvelope(env)
	if err != nil {
		return domain.Wrap("policy.state_error", "cannot encode the sealed policy envelope", err)
	}
	if err := fsx.WriteAtomic(e.policyPath(), b, 0o600); err != nil {
		if fsx.IsReadOnly(err) {
			return domain.New(domain.CodeConfigReadOnly,
				"the state directory is read-only; the sealed policy cannot be written")
		}
		return domain.Wrap("policy.state_error", "cannot write the sealed policy file", err)
	}
	return nil
}

// zeroKey wipes an ed25519 private key after use (defense in depth alongside
// policyseal's own zeroing of intermediates).
func zeroKey(sk ed25519.PrivateKey) {
	for i := range sk {
		sk[i] = 0
	}
}

// ── policy-body mutation helpers ─────────────────────────────────────────────

// defaultPolicy is the fresh body a first `policy set` / `reset --force` seals: a
// safe, restrictive default (allowlist on, include_self on, typed-unknown deny,
// messages allow) with NO limits set yet (the operator sets them via the same set
// command). version/messages/typed defaults follow §4.5.
func defaultPolicy(writtenBy string) Policy {
	allowlistOn := true
	includeSelf := true
	return Policy{
		Version:             bodyVersion,
		Nonce:               0,
		WrittenBy:           writtenBy,
		Messages:            "allow",
		TokensNoAllowlistOK: false,
		Rules: Rules{
			Default: Limits{
				AllowlistEnabled: &allowlistOn,
				IncludeSelf:      &includeSelf,
			},
		},
		TypedData: TypedDataCfg{Unknown: "deny"},
	}
}

// applyChange merges a Change into a policy body. A nil pointer field leaves the
// existing value unchanged; the tri-state limit pointers are carried verbatim
// (the cli already encoded none/inherit/value). Per-network and per-token rules
// are upserted (replace-by-key).
func applyChange(p *Policy, c Change) {
	if c.Default != nil {
		mergeLimits(&p.Rules.Default, *c.Default)
	}
	for _, n := range c.Networks {
		upsertNetwork(p, n)
	}
	if c.Messages != nil {
		p.Messages = *c.Messages
	}
	if c.TokensNoAllowOK != nil {
		p.TokensNoAllowlistOK = *c.TokensNoAllowOK
	}
	if c.TypedUnknown != nil {
		p.TypedData.Unknown = *c.TypedUnknown
	}
	for _, t := range c.Tokens {
		upsertToken(p, t)
	}
}

// mergeLimits applies the non-nil fields of src over dst (a nil src field means
// "leave dst unchanged"; the null sentinel propagates as the explicit-null value).
func mergeLimits(dst *Limits, src Limits) {
	if src.MaxTxWei != nil {
		dst.MaxTxWei = src.MaxTxWei
	}
	if src.MaxDayWei != nil {
		dst.MaxDayWei = src.MaxDayWei
	}
	if src.MaxGasPriceWei != nil {
		dst.MaxGasPriceWei = src.MaxGasPriceWei
	}
	if src.AllowlistEnabled != nil {
		dst.AllowlistEnabled = src.AllowlistEnabled
	}
	if src.IncludeSelf != nil {
		dst.IncludeSelf = src.IncludeSelf
	}
	if src.TypedDataUnknown != nil {
		dst.TypedDataUnknown = src.TypedDataUnknown
	}
}

// upsertNetwork replaces (or appends) a per-network override, merging its limit
// fields over any existing entry for the same network.
func upsertNetwork(p *Policy, n NetworkRule) {
	for i := range p.Rules.Networks {
		if equalFoldStr(p.Rules.Networks[i].Network, n.Network) {
			mergeLimits(&p.Rules.Networks[i].Limits, n.Limits)
			return
		}
	}
	p.Rules.Networks = append(p.Rules.Networks, n)
}

// upsertToken replaces (or appends) a token rule keyed by (network, address).
func upsertToken(p *Policy, t TokenRule) {
	for i := range p.Tokens {
		if equalFoldStr(p.Tokens[i].Network, t.Network) && equalFoldStr(p.Tokens[i].Address, t.Address) {
			p.Tokens[i] = t
			return
		}
	}
	p.Tokens = append(p.Tokens, t)
}

// upsertPin replaces (or appends) a pin entry keyed by (source, address, name) so
// re-allowing a name refreshes its pin rather than duplicating it.
func upsertPin(list []PinEntry, e PinEntry) []PinEntry {
	for i := range list {
		if samePin(list[i], e) {
			list[i] = e
			return list
		}
	}
	return append(list, e)
}

// removePin drops a pin entry matched by (source+address) or by (source+name) so
// `--remove vitalik.eth` works without re-resolving the name.
func removePin(list []PinEntry, e PinEntry) []PinEntry {
	out := list[:0]
	for _, p := range list {
		if samePin(p, e) || (e.Name != "" && equalFoldStr(p.Name, e.Name) && equalFoldStr(p.Source, e.Source)) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// samePin reports whether two pins denote the same entry: same source AND
// (same address OR same name).
func samePin(a, b PinEntry) bool {
	if !equalFoldStr(a.Source, b.Source) {
		return false
	}
	if a.Address != "" && equalFoldStr(a.Address, b.Address) {
		return true
	}
	return a.Name != "" && equalFoldStr(a.Name, b.Name)
}

// lowerAll lowercases a set of addresses to 0x strings for the sealed
// self_addresses snapshot.
func lowerAll(addrs []common.Address) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, lowerHex(a))
	}
	return out
}

// equalFoldStr is a case-insensitive string compare (used for network/source/
// address/name keys, which are stored lowercase but compared defensively).
func equalFoldStr(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
