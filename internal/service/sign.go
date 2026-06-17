package service

import (
	"context"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/policy"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// sign.go is the M9 off-chain signing core (design §2.7, §4.2, §4.3 stage 5;
// cli-spec §`daxie sign`). SignMessage signs an EIP-191 personal_sign message;
// SignTyped signs an EIP-712 typed-data document, routed through authorizeSignature —
// the §2.7 sibling non-tx gate — BEFORE the signer touches the key. verify.go holds
// the ecrecover round-trip.
//
// The load-bearing safety invariants (review hunts these):
//   - EIP-191 ALWAYS applies the \x19Ethereum Signed Message:\n<len> prefix (over the
//     raw bytes OR the 32-byte --no-hash digest). Raw unprefixed eth_sign is NEVER
//     reachable — the prefix is what makes the output unusable as a tx/typed forgery
//     (§4.2 row 2).
//   - A RECOGNIZED spend-equivalent EIP-712 (EIP-2612 / DAI / Permit2) is policy-
//     checked at SIGNATURE time EXACTLY like an on-chain approval: spender allowlist +
//     fail-closed-no-allowlist + the --unlimited --yes ceremony + chain-mismatch deny.
//     Signing a permit moves funds with no tx, so this is load-bearing. No wei debit,
//     no reservation (permits carry no ETH, §4.4).
//   - An UNRECOGNIZED typed message hits the §4.3 stage-5 typed-data gate: deny-by-
//     default once a policy is active + the per-domain allow registry + chain mismatch.
//   - The keystore passphrase is required to sign (the real signature, via the same
//     domain.Unlocker seam tx send uses).

// SignMessage signs an EIP-191 personal_sign message (`daxie sign message`). The
// \x19Ethereum Signed Message:\n<len> prefix is applied here (over the raw bytes, OR
// over the 32-byte --no-hash digest); the digest is keccak256(prefix||payload). EIP-191
// is allowed by default under the `messages` kill switch (§4.2 row 1); SignMessage
// reads that switch and refuses with policy.denied.typed_data only when
// messages=="deny". There is no spend gate (the prefix makes the output unusable as a
// tx/typed forgery).
func (s *Service) SignMessage(ctx context.Context, _ domain.Principal, req domain.SignMessageRequest) (domain.SigResult, error) {
	ref, from, err := s.resolveSigner(ctx, req.Account)
	if err != nil {
		return domain.SigResult{}, err
	}
	if err := s.checkMessagesKillSwitch(); err != nil {
		return domain.SigResult{}, err
	}
	digest := eip191Digest(req.Message) // common.Hash; the prefix is always applied
	sig, serr := s.signDigest(ctx, ref, digest)
	if serr != nil {
		return domain.SigResult{}, serr
	}
	return sigResult(sig, from, digest, "eip191"), nil
}

// SignTyped signs an EIP-712 typed-data document (`daxie sign typed`), routed through
// authorizeSignature (the §2.7 gasless spend-equivalent gate) BEFORE the signer
// touches the key. Order: parse → fetch the active chainId (prefetch-before-gate,
// §2.7) → authorizeSignature (REFUSE here) → eip712Digest → signDigest. No
// reservation, no journal, no nonce (a permit is gasless and never broadcast).
func (s *Service) SignTyped(ctx context.Context, p domain.Principal, req domain.SignTypedRequest) (domain.SigResult, error) {
	ref, from, err := s.resolveSigner(ctx, req.Account)
	if err != nil {
		return domain.SigResult{}, err
	}

	var td apitypes.TypedData
	if uerr := json.Unmarshal(req.Typed, &td); uerr != nil {
		return domain.SigResult{}, domain.Wrap(domain.CodeSignBadTyped,
			"the EIP-712 document is not valid JSON", uerr)
	}

	// The active chainId drives the §4.2 chain-mismatch deny (a permit for chain 1
	// signed "while on Sepolia"). Fetched BEFORE the gate (prefetch-before-lock, §2.7).
	chainID, network, cerr := s.activeChainID(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if cerr != nil {
		return domain.SigResult{}, cerr
	}

	if aerr := s.authorizeSignature(ctx, p, &td, from, network, chainID, req.AckUnlimited); aerr != nil {
		return domain.SigResult{}, aerr // policy.denied.* (exit 3) — REFUSE before SignHash
	}

	digest, herr := eip712Digest(&td)
	if herr != nil {
		return domain.SigResult{}, domain.Wrap(domain.CodeSignBadTyped,
			"cannot hash the EIP-712 document", herr)
	}
	sig, serr := s.signDigest(ctx, ref, digest)
	if serr != nil {
		return domain.SigResult{}, serr
	}
	return sigResult(sig, from, digest, "eip712"), nil
}

// authorizeSignature is the §2.7 gasless spend-equivalent gate. It mirrors the
// approvals check WITHOUT the tx machinery (no reserve, no nonce, no journal):
//
//   - a RECOGNIZED spend-equivalent (EIP-2612 / DAI / Permit2) → a KindPermit
//     policy.Evaluate (spender allowlist + fail-closed + unlimited-ack + chain
//     mismatch), evaluated EXACTLY like an on-chain approval. The PERMIT SPENDER is
//     the policy subject (Check.Dest), never the verifyingContract/token.
//   - an UNRECOGNIZED typed message → the §4.3 stage-5 typed-data gate
//     (typed_data.unknown deny-by-default once a policy is active + the per-domain
//     Allowed[] registry + chain mismatch).
//
// Both refuse BEFORE signer.SignHash. It calls Evaluate, NEVER Reserve (a permit is
// gasless: no wei to count, nothing to reserve, §4.4). It lives in service ahead of
// domain.Signer so the v1.1 daemon relocation covers it on the same two seams as
// authorize.
func (s *Service) authorizeSignature(ctx context.Context, _ domain.Principal, t *apitypes.TypedData, from common.Address, network string, activeChainID int64, acked bool) error {
	primary := t.PrimaryType
	// Build the domain map with NORMALIZED value types the policy recognizers consume:
	// apitypes.TypedDataDomain.Map() returns chainId as a *math.HexOrDecimal256, which
	// the recognizer's value coercion (and the chain-mismatch read) cannot decode — so
	// chainId would silently read as 0 and the chain-mismatch deny would never fire (a
	// load-bearing exfiltration guard). We hand chainId across as a decimal string and
	// verifyingContract as a 0x string, the forms messageBig/lowerAddr accept.
	domMap := normalizedDomainMap(t)
	msgMap := map[string]any(t.Message) // TypedDataMessage is map[string]any
	cls := policy.ClassifyTypedDataFor(activeChainID, primary, domMap, msgMap)

	if cls.IsSpend {
		// A recognized spend-equivalent → evaluate EXACTLY like an on-chain approval.
		// §4.2 "one Check per token/amount entry; service signs only if ALL pass": a
		// Permit2 batch authorizes several ERC-20s, each with its OWN amount and its own
		// allow_unlimited:false rule — emit one Check per token and refuse on the FIRST
		// that denies (the safe direction: a single failing entry blocks the signature).
		return s.evaluateSpendEquivalent(ctx, cls, from, network, acked)
	}

	// Unrecognized typed data → the stage-5 typed-data gate (deny-by-default).
	c := policy.Check{
		Account:        from,
		Network:        network,
		ToInput:        primary,
		TypedUnknown:   true,
		TypedPrimary:   primary,
		TypedVerifying: lowerHexAddr(domMap["verifyingContract"]),
		TypedChainID:   readDomainChainID(domMap),
	}
	// The chain-mismatch deny applies to unknown typed data too (the classic
	// exfiltration trick is not limited to recognized permits). Mark it the same
	// way the recognizer path does so the pure stage-5 gate refuses it.
	if activeChainID > 0 && c.TypedChainID > 0 && c.TypedChainID != activeChainID {
		c.Asset = "chain_mismatch:" + strconv.FormatInt(c.TypedChainID, 10)
	}

	dec, err := s.policy.Evaluate(ctx, c) // NO Reserve — gasless (§4.2, §4.4 "do not reserve")
	if err != nil {
		return err
	}
	if !dec.Allowed {
		return deniedDecisionError(dec)
	}
	return nil
}

// evaluateSpendEquivalent runs the §4.2 spend-equivalent gate for a recognized
// EIP-2612 / DAI / Permit2 message: one policy.Evaluate per underlying token entry
// (Permit2 batch forms carry >1), signing only if ALL pass. The PERMIT SPENDER is the
// policy subject (Check.Dest), and the policy subject TOKEN is the underlying ERC-20
// (cls.Tokens[i].Token), NEVER the verifyingContract — so for Permit2 the per-token
// allow_unlimited:false hard-deny binds the real asset, not the Permit2 contract (the
// medium-severity fix). The chain-mismatch marker rides on every entry's Check so it
// denies regardless of which entry is evaluated first.
func (s *Service) evaluateSpendEquivalent(ctx context.Context, cls policy.TypedDataClass, from common.Address, network string, acked bool) error {
	// Defensive: a recognizer that set IsSpend must populate at least one token entry
	// (EIP-2612/DAI fill it from verifyingContract; Permit2 from details/permitted.
	// token). If none, fall back to a single entry keyed on the verifying contract so
	// the gate still runs (never a silent allow).
	entries := cls.Tokens
	if len(entries) == 0 {
		entries = []policy.SpendToken{{Token: cls.Verifying, Unlimited: cls.Unlimited}}
	}
	for _, e := range entries {
		c := policy.Check{
			Account:   from,
			Network:   network,
			ToInput:   cls.Primary,
			KindEnum:  policy.KindPermit,
			Dest:      common.HexToAddress(cls.Spender), // the PERMIT SPENDER is the policy subject (§4.2)
			Unlimited: e.Unlimited,                      // THIS entry's amount sentinel
			Acked:     acked,
			Token:     e.Token, // the underlying ERC-20 (for the allow_unlimited rule)
			Asset:     e.Token,
		}
		if cls.Denied {
			// chain_mismatch carried by ClassifyTypedDataFor → the stage-5 marker the
			// pure engine reads (it does not see the active chainId itself). It REPLACES
			// the asset marker (the engine reads Asset for the chain_mismatch prefix; the
			// underlying token is still pinned on Check.Token for completeness).
			c.Asset = "chain_mismatch:" + strconv.FormatInt(cls.ChainID, 10)
		}
		dec, err := s.policy.Evaluate(ctx, c) // NO Reserve — gasless (§4.2, §4.4 "do not reserve")
		if err != nil {
			return err
		}
		if !dec.Allowed {
			return deniedDecisionError(dec) // first failing entry blocks the whole signature
		}
	}
	return nil
}

// checkMessagesKillSwitch refuses an EIP-191 signature when the active policy sets
// messages:"deny" (§4.2 row 1 — the single kill switch governing personal_sign). It
// is read from the unauthenticated policy view (no admin secret needed for a read);
// when no policy is active (opt-in), or messages is unset/"allow", signing proceeds.
// A halted seal (a present-but-unverifiable policy) is a FAIL-CLOSED refusal — a
// halted trust root must never be read as "messages allowed".
func (s *Service) checkMessagesKillSwitch() error {
	pol, st, err := s.policy.Show()
	if err != nil {
		return err // a halted/unverifiable seal fails closed (exit 8)
	}
	if !st.AnchorFound && !st.Present {
		return nil // opt-in: no anchor + no policy ⇒ messages allowed
	}
	if strings.EqualFold(strings.TrimSpace(pol.Messages), "deny") {
		return domain.New(domain.CodePolicyDeniedTypedData,
			"EIP-191 message signing is disabled by policy (messages:\"deny\")")
	}
	return nil
}

// normalizedDomainMap projects an EIP-712 document's domain into a map[string]any with
// the value TYPES the policy recognizers consume: chainId as a decimal string (from
// the *math.HexOrDecimal256 apitypes uses), verifyingContract as a 0x string, name/
// version/salt verbatim. This is the single place the apitypes domain shape is adapted
// to the policy seam, so the recognizers stay free of go-ethereum's apitypes types.
func normalizedDomainMap(t *apitypes.TypedData) map[string]any {
	m := map[string]any{}
	d := t.Domain
	if d.ChainId != nil {
		m["chainId"] = (*big.Int)(d.ChainId).String()
	}
	if d.Name != "" {
		m["name"] = d.Name
	}
	if d.Version != "" {
		m["version"] = d.Version
	}
	if d.VerifyingContract != "" {
		m["verifyingContract"] = d.VerifyingContract
	}
	if d.Salt != "" {
		m["salt"] = d.Salt
	}
	return m
}

// readDomainChainID coerces an EIP-712 domain map's chainId to int64 (0 when absent
// or unparseable), the same coercion the recognizer set uses for the recognized path.
func readDomainChainID(domMap map[string]any) int64 {
	switch v := domMap["chainId"].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return 0
		}
		base := 10
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			base, s = 16, s[2:]
		}
		n, err := strconv.ParseInt(s, base, 64)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// lowerHexAddr coerces a domain value to a lowercase 0x address string ("" when not a
// hex address). It accepts a 0x string or a common.Address.
func lowerHexAddr(v any) string {
	switch t := v.(type) {
	case string:
		if common.IsHexAddress(t) {
			return strings.ToLower(common.HexToAddress(t).Hex())
		}
		return ""
	case common.Address:
		return strings.ToLower(t.Hex())
	default:
		return ""
	}
}

// eip191Digest builds the EIP-191 personal_sign digest:
//
//	keccak256("\x19Ethereum Signed Message:\n" + len(payload) + payload)
//
// payload is the raw message bytes (default) OR the 32-byte digest bytes when the
// frontend decoded --no-hash. The PREFIX IS ALWAYS APPLIED — there is no path to sign
// raw unprefixed bytes (eth_sign is never offered, §4.2 row 2). geth's
// accounts.TextHash implements exactly this prefix.
func eip191Digest(payload []byte) common.Hash {
	return common.BytesToHash(accounts.TextHash(payload))
}

// eip712Digest computes the EIP-712 signing digest:
//
//	keccak256("\x19\x01" || domainSeparator || hashStruct(primaryType, message))
//
// apitypes.TypedDataAndHash does EXACTLY this (HashStruct("EIP712Domain", …) for the
// domain separator + HashStruct(primaryType, message) for the struct hash + the
// \x19\x01 sigil). A malformed/typeless document errors → sign.bad_typed (mapped by
// the caller).
func eip712Digest(td *apitypes.TypedData) (common.Hash, error) {
	hash, _, err := apitypes.TypedDataAndHash(*td) // ([]byte, string, error)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(hash), nil
}

// signDigest signs a 32-byte digest via the domain.Signer over the §3.6 keystore
// passphrase (the same Unlocker seam tx send uses). A wrong/missing passphrase
// surfaces keystore.bad_passphrase (exit 4) from the signer for free. The returned
// signature is the raw 65-byte [R||S||V] geth emits with V ∈ {0,1}; sigResult bumps
// V to {27,28} for wallet interop.
func (s *Service) signDigest(ctx context.Context, ref domain.AccountRef, digest common.Hash) ([]byte, error) {
	unlocker, zero, err := s.withUnlocker(false)
	if err != nil {
		return nil, err
	}
	defer zero()
	return s.signer.SignHash(ctx, ref, digest, unlocker)
}

// sigResult assembles the SigResult: the 0x signature (with V normalized to {27,28}
// for wallet interop), the checksummed signer, the digest, and the scheme.
func sigResult(sig []byte, from common.Address, digest common.Hash, scheme string) domain.SigResult {
	out := make([]byte, len(sig))
	copy(out, sig)
	if len(out) == 65 && out[64] < 27 {
		out[64] += 27
	}
	return domain.SigResult{
		Signature: "0x" + common.Bytes2Hex(out),
		Signer:    from.Hex(),
		Digest:    digest.Hex(),
		Scheme:    scheme,
	}
}

// activeChainID dials the request's endpoint and returns (chainId, resolved network
// name, err). It drives the §4.2 chain-mismatch deny on the typed path: a permit/typed
// message declaring a chainId different from the live network is denied. The client is
// owned + closed here (no client is held across the gate, §2.7 prefetch).
func (s *Service) activeChainID(ctx context.Context, cr ChainRequest) (int64, string, error) {
	network := s.networkName(cr.Network)
	cc, err := s.chains.ClientFor(ctx, cr)
	if err != nil {
		return 0, network, err
	}
	defer cc.Close()
	id, err := cc.ChainID(ctx)
	if err != nil {
		return 0, network, mapRPCErr(err)
	}
	if id == nil || !id.IsInt64() {
		return 0, network, nil // unknown/huge chainId ⇒ disable the mismatch check (fail-open on the read, the gate still denies-by-default for unknown typed data)
	}
	return id.Int64(), network, nil
}

// deniedDecisionError renders a denied policy.Decision as the canonical domain.Error
// (exit 3 via the policy.denied prefix), carrying the §4.9 per-code Data + violations
// payload + the retry_after hint. Shared by authorizeSignature and the typed verify
// path (the same projection tx.go's dry-run applies inline).
func deniedDecisionError(dec policy.Decision) error {
	code := dec.Code
	if code == "" {
		code = domain.CodePolicyDenied
	}
	de := domain.New(code, dec.Reason)
	if dec.Data != nil {
		de = domain.WithData(de, dec.Data)
	}
	if dec.RetryAfter != "" {
		de = domain.WithData(de, map[string]any{"retry_after": dec.RetryAfter})
	}
	return de
}

// resolveSigner resolves the signing ref (flag>env>default) to (AccountRef, address)
// WITHOUT unlocking. An empty account falls to the §7.7 default; an empty default is
// usage.no_account. The address is resolved through the domain.Signer seam (so a
// KMS/daemon backend answers the same way the local keystore does).
func (s *Service) resolveSigner(ctx context.Context, account string) (domain.AccountRef, common.Address, error) {
	acct := account
	if acct == "" {
		acct = s.activeDefault(ctx)
	}
	if acct == "" {
		return domain.AccountRef{}, common.Address{}, domain.New(domain.CodeUsage+".no_account",
			"no --account given and no default account set (run `daxie account use`)")
	}
	ref, err := domain.ParseAccountRef(acct)
	if err != nil {
		return domain.AccountRef{}, common.Address{}, err
	}
	addr, err := s.signer.Address(ctx, ref)
	if err != nil {
		return domain.AccountRef{}, common.Address{}, err
	}
	return ref, addr, nil
}
