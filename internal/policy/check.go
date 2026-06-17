package policy

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Check is the Evaluate/Reserve input — the fully-built tx the verdict sees
// (§5.1: recipient, native value, classified calldata, worst-case gas). The
// service kernel builds exactly one Check per signing op AFTER the gas engine has
// resolved the limit and fees (so MaxGasWei = gasLimit × maxFeePerGas is final)
// and hands it to Evaluate (dry-run) or Reserve (the durable pre-sign path).
//
// The M3 stub read only Account/Dest/SpendWei/MaxGasWei. M4 consumes the rest of
// the §4.2 model WITHOUT changing the fields service already sets — every M4
// field is additive and default-zero until the producing milestone (M5/M7/M9)
// fills it. No float anywhere (§2.5): every amount is a *big.Int in wei.
type Check struct {
	// ── M3 fields (FROZEN — service sets these today) ──
	Account   common.Address // the signing account (= From; the spend bucket key)
	Dest      common.Address // the resolved recipient/spender (= To; the allowlist subject)
	SpendWei  *big.Int       // native ETH value moved; nil == zero. NEVER a token amount.
	MaxGasWei *big.Int       // worst-case gasLimit × maxFeePerGas; nil == zero

	MaxFeePerGas *big.Int // gas-cap check (stage 8); nil == zero
	Kind         string   // journal.Kind string (M3 sets it; M4 maps to the Kind enum)
	Token        string   // token contract (lowercase 0x); "" for ETH
	IsRBFDelta   bool     // speedup/cancel: only the positive gas delta counts (§5.5)
	Acked        bool     // the --unlimited --yes / acknowledgeUnlimited ceremony bit

	// ── M4 additive (default-zero until M5/M7/M9 set them; the pipeline reads them) ──
	Network      string         // per-network bucket + per-network rule key (§4.1)
	KindEnum     Kind           // the classified Kind (set by service from Kind or ClassifyTypedData)
	ToSrc        ToSource       // SourceRawAddress|ENS|Contact|Self
	ToInput      string         // exactly what the user typed (for pin-drift messaging)
	ENSName      string         // non-empty when To came from ENS → stage-4 pin check
	ENSResolved  common.Address // the FRESH pre-lock resolution service hands in (engine only compares)
	Asset        string         // "eth" | lowercase token/NFT contract
	TokenAmt     *big.Int       // raw token base units (display only in v1)
	Unlimited    bool           // unbounded approval/permit (sentinel match)
	AccountNonce *uint64        // RBF supersession

	// ── M9 unknown-typed-data path (default-zero; ONLY SignTyped's authorizeSignature
	// sets these, for an EIP-712 message that matched NO §4.2 recognizer). They drive
	// the §4.3 stage-5 typed-data gate: deny-by-default once a policy is active, with
	// the per-domain TypedData.Allowed[] registry (matched on the triple) + the
	// chain-mismatch deny. A recognized spend-equivalent permit does NOT use these — it
	// rides the KindPermit path (KindEnum=KindPermit + the chain-mismatch Asset marker
	// the M4 stage-5 branch already reads). ──
	TypedUnknown   bool   // the message is typed but matched no recognizer
	TypedPrimary   string // the EIP-712 primaryType
	TypedVerifying string // domain.verifyingContract (lowercase 0x) the message declared
	TypedChainID   int64  // domain.chainId the message declared (0 if absent)

	// ── M10 unknown-calldata path (stage-5b; ONLY ContractSend's classify sets these
	// for a selector ClassifyCalldata returned ok=false). A RECOGNIZED spend-equivalent
	// does NOT use these — it rides KindApprove/KindTransfer through stages 3-8 exactly
	// like the typed path (the M10 crux: the generic and typed paths are indistinguishable
	// to Evaluate). These drive the §4.3 stage-5b deny-by-default unknown-calldata gate:
	// once a policy is active, an unrecognized selector to a non-allowlisted, non-opted-in
	// contract is refused (policy.denied.contract_call), with the per-(network,contract,
	// selector) ContractsAllowed[] registry as the only opt-in. --value still folds into
	// SpendWei (recognition-independent) so the ETH gates apply a fortiori. ──
	UnknownCalldata bool           // the calldata's selector matched no §4.2 recognizer
	ContractAddr    common.Address // the tx To (the contract) — the stage-5b allowlist subject
	Selector        string         // the leading 4-byte selector "0x…" (for the triple + Data)
}

// Kind is the §4.2 request kind. There is NO opaque KindContractCall: arbitrary
// calldata is classified into one of these or denied (the §4.3 stage-5b gate,
// M10). The string-to-enum mapping lives in kindOf so service's journal.Kind
// string maps in without service knowing the enum.
type Kind int

const (
	KindUnknown  Kind = iota // unset / not yet classified
	KindTransfer             // ETH / ERC-20 / ERC-721 / ERC-1155 send
	KindApprove              // approve / revoke / setApprovalForAll (spend-equivalent)
	KindPermit               // EIP-2612 / DAI / Permit2 (spend-equivalent, gasless — never Reserve)
)

// ToSource records how the destination/spender was supplied, so stage 4 knows
// whether a fresh-resolution pin check applies.
type ToSource int

const (
	SourceRawAddress ToSource = iota // a literal 0x… — no drift check
	SourceENS                        // an ENS name → fresh-resolution pin check
	SourceContact                    // a contact name → snapshot pin check
	SourceSelf                       // an own account (include_self path)
)

// effectiveKind returns the classified Kind, falling back to mapping the M3
// journal.Kind string when the enum was not set by an M4 producer. Defaults to
// KindTransfer (the broadcasting-value path) so the ETH limits always apply.
func (c Check) effectiveKind() Kind {
	if c.KindEnum != KindUnknown {
		return c.KindEnum
	}
	switch c.Kind {
	case "approve", "revoke":
		return KindApprove
	case "permit":
		return KindPermit
	default:
		// transfer, send, cancel, speedup, contract, "" — all broadcasting value paths.
		return KindTransfer
	}
}

// spendWei returns the native value as a non-nil big.Int (0 if unset).
func (c Check) spendWei() *big.Int {
	if c.SpendWei == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(c.SpendWei)
}

// maxGasWei returns the worst-case gas as a non-nil big.Int (0 if unset).
func (c Check) maxGasWei() *big.Int {
	if c.MaxGasWei == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(c.MaxGasWei)
}

// maxFeePerGas returns the gas-cap subject as a non-nil big.Int (0 if unset).
func (c Check) maxFeePerGas() *big.Int {
	if c.MaxFeePerGas == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(c.MaxFeePerGas)
}

// Decision is the policy verdict (§4.9). When denied, Code is the
// highest-precedence canonical policy.denied.* string and Reason is the human
// one-liner; Violations carries EVERY accumulated violation (stages 3-8) for
// details.violations[]; RetryAfter is an RFC3339 instant for day_limit; Data is
// the per-code details payload the frontends surface. The service kernel renders
// a denial as a domain.Error whose Code is Decision.Code (exit 3 via the
// policy.denied prefix already in domain).
type Decision struct {
	Allowed    bool
	Code       string         // canonical policy.denied.* ("" when allowed)
	Reason     string         // human one-liner ("" when allowed)
	Violations []Violation    // every accumulated violation for details.violations[]
	RetryAfter string         // RFC3339 instant for day_limit (§4.9); "" otherwise
	Data       map[string]any // the §4.9 per-code details payload
}

// Violation is one accumulated policy refusal (stages 3-8 accumulate; the highest
// precedence becomes Decision.Code, but all ride in Decision.Violations).
type Violation struct {
	Code   string         `json:"code"`
	Reason string         `json:"reason"`
	Data   map[string]any `json:"data,omitempty"`
}

// TypedDataClass is the §4.2 classification result for an EIP-712 typed message
// (sign typed). M4 fills IsSpend/Kind/Spender/Unlimited from the EIP-2612 / DAI /
// Permit2 recognizers; a chain mismatch sets Denied with the reason so the typed
// path can refuse without a second pass.
type TypedDataClass struct {
	IsSpend    bool   // true once a Permit/Permit2/DAI recognizer matched
	Kind       string // the spend-equivalent kind when IsSpend (e.g. "approve")
	Spender    string // the recognized spender (lowercase 0x) when IsSpend
	Unlimited  bool   // the recognized amount/deadline is an unlimited sentinel
	ChainID    int64  // the domain chainId the recognizer read
	Verifying  string // domain.verifyingContract (lowercase 0x) the recognizer matched
	Primary    string // the matched primaryType
	Denied     bool   // a chain mismatch (or shape on a hostile domain) ⇒ hard deny
	DenyReason string // "chain_mismatch" when Denied

	// Tokens is the underlying ERC-20(s) the spend-equivalent approves — one entry
	// per token/amount the message authorizes (§4.2 "one Check per token/amount
	// entry"). For EIP-2612/DAI the token IS domain.verifyingContract (the recognizer
	// fills a single entry from Verifying); for Permit2 it is the inner
	// details.token / permitted.token (NOT the Permit2 contract — so the per-token
	// `allow_unlimited:false` hard-deny is keyed on the real ERC-20). Batch Permit2
	// forms yield >1 entry; service emits one Check per entry and signs only if all
	// pass. Each entry carries its OWN Unlimited bit so a batch that mixes a bounded
	// and an unbounded amount gates the right token.
	Tokens []SpendToken
}

// SpendToken is one underlying ERC-20 entry of a recognized spend-equivalent: the
// token contract (lowercase 0x) and whether THAT entry's amount is an unlimited
// sentinel (§4.2). A single permit yields one entry; a Permit2 batch yields one per
// permitted item.
type SpendToken struct {
	Token     string // the underlying ERC-20 contract (lowercase 0x)
	Unlimited bool   // this entry's amount is an unlimited sentinel
}
