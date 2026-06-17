package policy

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	gethmath "github.com/ethereum/go-ethereum/common/math"
)

// recognizers.go is the §4.2 spend-equivalent EIP-712 recognizer set, pure and
// table-tested. The match is on (primaryType, type-field shape,
// domain.verifyingContract) — NEVER on the domain `name` string. A hostile
// domain whose name is "Permit" but whose field shape is wrong returns ok=false
// and falls to the deny-by-default typed-data gate (the name-string-must-not-match
// invariant the tests pin).
//
// THE CALLDATA TWIN (ClassifyCalldata / internal/abi) IS M10, NOT M4 — the plan's
// scope note. Only the typed-data recognizers ship here.

// permit2Contract is the canonical Permit2 deployment address (same on every
// chain). A recognizer shape is Permit2 only when domain.verifyingContract equals
// this address (§4.2).
const permit2Contract = "0x000000000022d473030f116ddee9f6b43ac78ba3"

// uint256Max, uint160Max and uint96Max are the §4.2 "unlimited" sentinels. A permit
// value at uint256 max (EIP-2612), a Permit2 amount at uint160 max, or a uint96-max
// allowance is unbounded → the unlimited-ack ceremony (§4.3 stage 6). The engine
// re-derives Unlimited from the encoded amount against THIS set (isUnlimitedAmount),
// so the ceremony does not depend on a caller-supplied flag it cannot trust.
var (
	uint256Max = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	uint160Max = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	uint96Max  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 96), big.NewInt(1))
)

// isUnlimitedAmount reports whether an approval/permit amount equals any §4.2
// unlimited sentinel (2^256-1, uint160 max, uint96 max). A nil amount is never
// unlimited. This is the policy-side twin of erc.IsUnlimitedAmount; the policy
// package may not import erc (provider→provider, §2.2), so the sentinel set is
// kept in lock-step with that package — both encode the SAME three values so the
// calldata builder and the ceremony agree on the exact match set (§4.2 line 1644).
func isUnlimitedAmount(amount *big.Int) bool {
	if amount == nil {
		return false
	}
	return amount.Cmp(uint256Max) == 0 ||
		amount.Cmp(uint160Max) == 0 ||
		amount.Cmp(uint96Max) == 0
}

// ClassifyTypedData is the §4.2 typed-data recognizer seam (the frozen service
// signature). It runs the pure recognizers over (primaryType, domain, message)
// and returns the populated TypedDataClass. The chainId the domain declares is
// carried in the result; the stage-5 typed-data gate (which knows the active
// network) makes the chain-mismatch denial via ClassifyTypedDataFor. A shape that
// matches no recognizer returns {IsSpend:false} (it falls to the typed-data gate).
func (e *Engine) ClassifyTypedData(primaryType string, domain map[string]any, message map[string]any) (TypedDataClass, error) {
	return classifyTypedData(primaryType, domain, message), nil
}

// ClassifyTypedDataFor is ClassifyTypedData with the active network's chainId, so
// it can apply the §4.2 chain-mismatch deny: a recognizer shape on a chainId
// different from the active network is a classic exfiltration trick (a permit for
// chain 1 signed "while on Sepolia"). expectedChainID <= 0 disables the check
// (the caller does not know the active chainId).
func ClassifyTypedDataFor(expectedChainID int64, primaryType string, domain, message map[string]any) TypedDataClass {
	c := classifyTypedData(primaryType, domain, message)
	if c.IsSpend && expectedChainID > 0 && c.ChainID > 0 && c.ChainID != expectedChainID {
		c.Denied = true
		c.DenyReason = "chain_mismatch"
	}
	return c
}

// classifyTypedData is the pure recognizer dispatcher. It tries EIP-2612, then
// DAI-style, then Permit2 (the v1 set). The first that matches wins; none ⇒
// {IsSpend:false}. A shape that partially matches a recognizer but fails its
// field-shape contract returns {IsSpend:false} — never a partial extraction (the
// fail-direction §4.2 mandates).
func classifyTypedData(primaryType string, domain, message map[string]any) TypedDataClass {
	chainID := readChainID(domain)
	verifying := lowerAddr(domain["verifyingContract"])

	if c, ok := matchEIP2612(primaryType, message); ok {
		c.ChainID = chainID
		c.Verifying = verifying
		c.Primary = primaryType
		// EIP-2612: the token IS domain.verifyingContract (§4.2). One token entry,
		// carrying this permit's Unlimited bit, so the per-token allow_unlimited rule
		// is keyed on the real ERC-20 (which here equals the verifying contract).
		c.Tokens = []SpendToken{{Token: verifying, Unlimited: c.Unlimited}}
		return c
	}
	if c, ok := matchDAIPermit(primaryType, message); ok {
		c.ChainID = chainID
		c.Verifying = verifying
		c.Primary = primaryType
		// DAI-style: the token IS domain.verifyingContract (§4.2).
		c.Tokens = []SpendToken{{Token: verifying, Unlimited: c.Unlimited}}
		return c
	}
	if c, ok := matchPermit2(primaryType, verifying, message); ok {
		c.ChainID = chainID
		c.Verifying = verifying
		c.Primary = primaryType
		// matchPermit2 fills c.Tokens from the INNER details.token / permitted.token
		// (never the Permit2 contract) so the per-token allow_unlimited:false hard-deny
		// binds the real ERC-20 (§4.2 medium-severity fix).
		return c
	}
	return TypedDataClass{IsSpend: false}
}

// matchEIP2612 recognizes the EIP-2612 Permit: primaryType=="Permit" with EXACTLY
// the fields {owner,spender,value,nonce,deadline}. token = domain.verifyingContract;
// To = spender; Unlimited if value == 2^256−1 or the deadline is the max sentinel.
func matchEIP2612(primaryType string, message map[string]any) (TypedDataClass, bool) {
	if primaryType != "Permit" {
		return TypedDataClass{}, false
	}
	if !hasExactKeys(message, "owner", "spender", "value", "nonce", "deadline") {
		return TypedDataClass{}, false
	}
	spender, ok := messageAddr(message, "spender")
	if !ok {
		return TypedDataClass{}, false
	}
	value, ok := messageBig(message, "value")
	if !ok {
		return TypedDataClass{}, false
	}
	deadline, _ := messageBig(message, "deadline")
	unlimited := value.Cmp(uint256Max) == 0 || (deadline != nil && deadline.Cmp(uint256Max) == 0)
	return TypedDataClass{IsSpend: true, Kind: "approve", Spender: spender, Unlimited: unlimited}, true
}

// matchDAIPermit recognizes the DAI-style Permit: primaryType=="Permit" with
// EXACTLY {holder,spender,nonce,expiry,allowed}. To = spender; allowed==true ⇒
// Unlimited (DAI's "allowed" toggles infinite allowance).
func matchDAIPermit(primaryType string, message map[string]any) (TypedDataClass, bool) {
	if primaryType != "Permit" {
		return TypedDataClass{}, false
	}
	if !hasExactKeys(message, "holder", "spender", "nonce", "expiry", "allowed") {
		return TypedDataClass{}, false
	}
	spender, ok := messageAddr(message, "spender")
	if !ok {
		return TypedDataClass{}, false
	}
	allowed, ok := messageBool(message, "allowed")
	if !ok {
		return TypedDataClass{}, false
	}
	return TypedDataClass{IsSpend: true, Kind: "approve", Spender: spender, Unlimited: allowed}, true
}

// matchPermit2 recognizes Permit2: domain.verifyingContract == the canonical
// Permit2 address AND primaryType ∈ {PermitSingle, PermitBatch, PermitTransferFrom,
// PermitBatchTransferFrom}. The extractor is a fixed switch on primaryType (four
// shapes, four extractors); any shape mismatch returns ok=false (§4.2).
//
// SPENDER. The two ALLOWANCE forms (PermitSingle/PermitBatch) sign an on-message
// `spender` (the address granted the allowance) — required. The two SIGNATURE-
// TRANSFER forms (PermitTransferFrom/PermitBatchTransferFrom) bind the spender as
// msg.sender at permitTransferFrom() call time; the canonical Uniswap message may or
// may not carry a top-level `spender` (the witnessed variant pins it, the plain one
// does not). So for those two flavors the spender is OPTIONAL: if present it becomes
// the allowlist subject; if absent the recognizer STILL classifies the message as a
// spend-equivalent (a signature transfer moves funds with no on-chain spender bound
// in the signature) and routes it through the unlimited-ack + chain-mismatch ceremony
// with an empty Spender — never the dead-code fall-through to the unknown-typed gate
// the old top-level-spender requirement caused (the high-severity fix).
//
// TOKEN. Each entry's underlying ERC-20 is read from details.token (allowance forms)
// or permitted.token (transfer forms) and carried in TypedDataClass.Tokens — NEVER
// the Permit2 contract — so the per-token allow_unlimited:false hard-deny binds the
// real asset (the medium-severity fix). Batch forms emit one entry per item, each
// with its own Unlimited bit; TypedDataClass.Unlimited stays the OR across entries
// (the legacy single-bit summary). Any shape mismatch in any entry returns ok=false.
func matchPermit2(primaryType, verifying string, message map[string]any) (TypedDataClass, bool) {
	if verifying != permit2Contract {
		return TypedDataClass{}, false
	}
	switch primaryType {
	case "PermitSingle":
		spender, ok := messageAddr(message, "spender")
		if !ok {
			return TypedDataClass{}, false
		}
		details, ok := message["details"].(map[string]any)
		if !ok {
			return TypedDataClass{}, false
		}
		st, ok := permit2Token(details, uint160Max)
		if !ok {
			return TypedDataClass{}, false
		}
		return TypedDataClass{IsSpend: true, Kind: "approve", Spender: spender, Unlimited: st.Unlimited, Tokens: []SpendToken{st}}, true
	case "PermitBatch":
		spender, ok := messageAddr(message, "spender")
		if !ok {
			return TypedDataClass{}, false
		}
		toks, unlimited, ok := permit2Tokens(message["details"], uint160Max)
		if !ok {
			return TypedDataClass{}, false
		}
		return TypedDataClass{IsSpend: true, Kind: "approve", Spender: spender, Unlimited: unlimited, Tokens: toks}, true
	case "PermitTransferFrom":
		// Signature-transfer: no signed on-chain spender required (it is bound as
		// msg.sender at call time). An optional top-level spender becomes the subject.
		spender, _ := messageAddr(message, "spender")
		permitted, ok := message["permitted"].(map[string]any)
		if !ok {
			return TypedDataClass{}, false
		}
		st, ok := permit2Token(permitted, uint256Max)
		if !ok {
			return TypedDataClass{}, false
		}
		return TypedDataClass{IsSpend: true, Kind: "approve", Spender: spender, Unlimited: st.Unlimited, Tokens: []SpendToken{st}}, true
	case "PermitBatchTransferFrom":
		spender, _ := messageAddr(message, "spender") // optional (see above)
		toks, unlimited, ok := permit2Tokens(message["permitted"], uint256Max)
		if !ok {
			return TypedDataClass{}, false
		}
		return TypedDataClass{IsSpend: true, Kind: "approve", Spender: spender, Unlimited: unlimited, Tokens: toks}, true
	default:
		return TypedDataClass{}, false
	}
}

// permit2Token extracts one Permit2 entry's underlying token + unlimited bit from a
// details/permitted object: token (required address) + amount (required, compared to
// the form's unlimited sentinel — uint160 max for allowance forms, uint256 max for
// transfer forms). A missing/unparseable token or amount returns ok=false (the §4.2
// fail-direction: no partial extraction).
func permit2Token(obj map[string]any, sentinel *big.Int) (SpendToken, bool) {
	token, ok := messageAddr(obj, "token")
	if !ok {
		return SpendToken{}, false
	}
	amt, ok := messageBig(obj, "amount")
	if !ok {
		return SpendToken{}, false
	}
	return SpendToken{Token: token, Unlimited: amt.Cmp(sentinel) == 0}, true
}

// permit2Tokens extracts every entry of a Permit2 batch (details[]/permitted[]) into
// a SpendToken slice and reports whether ANY entry is unlimited. A non-array, empty
// array, or any malformed entry returns ok=false.
func permit2Tokens(raw any, sentinel *big.Int) ([]SpendToken, bool, bool) {
	arr, ok := raw.([]any)
	if !ok || len(arr) == 0 {
		return nil, false, false
	}
	toks := make([]SpendToken, 0, len(arr))
	anyUnlimited := false
	for _, el := range arr {
		d, ok := el.(map[string]any)
		if !ok {
			return nil, false, false
		}
		st, ok := permit2Token(d, sentinel)
		if !ok {
			return nil, false, false
		}
		if st.Unlimited {
			anyUnlimited = true
		}
		toks = append(toks, st)
	}
	return toks, anyUnlimited, true
}

// ── typed-data value coercion (JSON numbers arrive as float64/json.Number/string;
// addresses as 0x strings; all coerced WITHOUT float arithmetic on amounts) ──

// hasExactKeys reports whether m's key set is EXACTLY want (no more, no fewer).
// The exact-shape match is what makes the name-string irrelevant: a hostile
// domain.name cannot conjure the right field set.
func hasExactKeys(m map[string]any, want ...string) bool {
	if len(m) != len(want) {
		return false
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

// readChainID coerces domain.chainId to int64 (0 when absent/unparseable). EIP-712
// chainId is a uint256 in the type system but always small in practice; we read it
// via messageBig and clamp to int64.
func readChainID(domain map[string]any) int64 {
	v, ok := messageBig(domain, "chainId")
	if !ok || v == nil {
		return 0
	}
	if !v.IsInt64() {
		return 0
	}
	return v.Int64()
}

// lowerAddr coerces a typed-data address value to a lowercase 0x string ("" when
// not an address). It accepts a common.Address, a 0x string, or a []byte.
func lowerAddr(v any) string {
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

// messageAddr reads a lowercase 0x address from message[key].
func messageAddr(m map[string]any, key string) (string, bool) {
	a := lowerAddr(m[key])
	return a, a != ""
}

// messageBool reads a bool from message[key] (accepts a JSON bool or "true"/"false").
func messageBool(m map[string]any, key string) (bool, bool) {
	switch t := m[key].(type) {
	case bool:
		return t, true
	case string:
		if t == "true" {
			return true, true
		}
		if t == "false" {
			return false, true
		}
	}
	return false, false
}

// messageBig reads an integer amount from message[key] WITHOUT float arithmetic.
// EIP-712 uint256 values cross JSON as decimal/hex strings (the only safe form for
// >2^53); a float64 is accepted only when it is an exact integer (small chainIds,
// deadlines), never for an amount that could lose precision. A 0x-hex string is
// parsed base-16; a plain string base-10.
func messageBig(m map[string]any, key string) (*big.Int, bool) {
	switch t := m[key].(type) {
	case string:
		return parseBigString(t)
	case float64:
		// Accept only exact integers (JSON numbers <= 2^53 round-trip exactly).
		if t != float64(int64(t)) {
			return nil, false
		}
		return big.NewInt(int64(t)), true
	case int:
		return big.NewInt(int64(t)), true
	case int64:
		return big.NewInt(t), true
	case *big.Int:
		if t == nil {
			return nil, false
		}
		return new(big.Int).Set(t), true
	case *gethmath.HexOrDecimal256:
		// apitypes.TypedData.Domain.Map() returns domain.chainId (and any numeric
		// uint256 the caller supplied as a JSON number) as a *math.HexOrDecimal256, a
		// defined type over big.Int. Without this case readChainID returns 0 for every
		// apitypes-parsed document, silently defeating the §4.2 chain-mismatch deny.
		if t == nil {
			return nil, false
		}
		b := big.Int(*t)
		return &b, true
	default:
		return nil, false
	}
}

// parseBigString parses a decimal or 0x-hex integer string into a *big.Int.
func parseBigString(s string) (*big.Int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, ok := new(big.Int).SetString(s[2:], 16)
		return v, ok
	}
	v, ok := new(big.Int).SetString(s, 10)
	return v, ok
}
