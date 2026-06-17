package policy

import "testing"

// recognizers_test.go pins the §4.2 EIP-712 spend-equivalent recognizers:
// EIP-2612 / DAI / Permit2 matched on (primaryType, field-shape,
// domain.verifyingContract), the unlimited sentinels, chain-mismatch deny, and —
// the load-bearing invariant — the domain NAME STRING must NOT trigger a match.

const (
	tokenContract = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" // USDC-ish
	spenderAddr   = "0x1111111111111111111111111111111111111111"
)

// EIP-2612 Permit: spender extracted; unlimited sentinel recognized.
func TestRecognizeEIP2612(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": tokenContract}
	msg := map[string]any{
		"owner":    "0x2222222222222222222222222222222222222222",
		"spender":  spenderAddr,
		"value":    uint256Max.String(),
		"nonce":    "0",
		"deadline": "0",
	}
	c := classifyTypedData("Permit", domain, msg)
	if !c.IsSpend || c.Kind != "approve" {
		t.Fatalf("EIP-2612 permit not recognized: %+v", c)
	}
	if c.Spender != spenderAddr {
		t.Fatalf("spender = %q, want %q", c.Spender, spenderAddr)
	}
	if !c.Unlimited {
		t.Fatal("value == 2^256-1 must be unlimited")
	}
}

// A bounded EIP-2612 value is NOT unlimited.
func TestRecognizeEIP2612Bounded(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": tokenContract}
	msg := map[string]any{
		"owner": "0x2222222222222222222222222222222222222222", "spender": spenderAddr,
		"value": "1000000", "nonce": "0", "deadline": "0",
	}
	c := classifyTypedData("Permit", domain, msg)
	if !c.IsSpend || c.Unlimited {
		t.Fatalf("a bounded permit must be recognized but not unlimited: %+v", c)
	}
}

// DAI-style Permit: allowed==true ⇒ unlimited.
func TestRecognizeDAIPermit(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": tokenContract}
	msg := map[string]any{
		"holder": "0x2222222222222222222222222222222222222222", "spender": spenderAddr,
		"nonce": "0", "expiry": "0", "allowed": true,
	}
	c := classifyTypedData("Permit", domain, msg)
	if !c.IsSpend || c.Kind != "approve" || c.Spender != spenderAddr {
		t.Fatalf("DAI permit not recognized: %+v", c)
	}
	if !c.Unlimited {
		t.Fatal("DAI allowed==true must be unlimited")
	}
}

// Permit2 PermitSingle on the canonical contract: amount uint160-max ⇒ unlimited.
func TestRecognizePermit2Single(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": permit2Contract}
	msg := map[string]any{
		"spender": spenderAddr,
		"details": map[string]any{
			"token":      tokenContract,
			"amount":     uint160Max.String(),
			"expiration": "0",
			"nonce":      "0",
		},
	}
	c := classifyTypedData("PermitSingle", domain, msg)
	if !c.IsSpend || c.Spender != spenderAddr {
		t.Fatalf("Permit2 PermitSingle not recognized: %+v", c)
	}
	if !c.Unlimited {
		t.Fatal("Permit2 amount == uint160 max must be unlimited")
	}
}

// Permit2 PermitSingle carries the UNDERLYING token (details.token) in Tokens — NOT
// the Permit2 contract — so the per-token allow_unlimited rule binds the real ERC-20.
func TestRecognizePermit2SingleUnderlyingToken(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": permit2Contract}
	msg := map[string]any{
		"spender": spenderAddr,
		"details": map[string]any{"token": tokenContract, "amount": "1000", "expiration": "0", "nonce": "0"},
	}
	c := classifyTypedData("PermitSingle", domain, msg)
	if !c.IsSpend || len(c.Tokens) != 1 {
		t.Fatalf("PermitSingle must carry exactly one token entry: %+v", c)
	}
	if c.Tokens[0].Token != tokenContract {
		t.Fatalf("Tokens[0].Token = %q, want the underlying ERC-20 %q (NOT the Permit2 contract %q)",
			c.Tokens[0].Token, tokenContract, permit2Contract)
	}
	if c.Verifying != permit2Contract {
		t.Fatalf("Verifying = %q, want the Permit2 contract %q (the chain/contract identity)", c.Verifying, permit2Contract)
	}
}

// Permit2 PermitTransferFrom — the canonical SIGNATURE-TRANSFER shape (permitted{token,
// amount}, nonce, deadline, NO top-level spender). It must classify as a spend-
// equivalent (the high-severity dead-code fix): no top-level `spender` is required,
// the token comes from permitted.token, and Unlimited from permitted.amount==2^256-1.
func TestRecognizePermit2TransferFromNoSpender(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": permit2Contract}
	msg := map[string]any{
		// NO top-level "spender" — the spender is bound as msg.sender on-chain.
		"permitted": map[string]any{"token": tokenContract, "amount": uint256Max.String()},
		"nonce":     "0",
		"deadline":  "9999999999",
	}
	c := classifyTypedData("PermitTransferFrom", domain, msg)
	if !c.IsSpend || c.Kind != "approve" {
		t.Fatalf("a real PermitTransferFrom (no top-level spender) must classify as spend-equivalent: %+v", c)
	}
	if c.Spender != "" {
		t.Fatalf("Spender = %q, want empty (no signed spender in the canonical PermitTransferFrom)", c.Spender)
	}
	if len(c.Tokens) != 1 || c.Tokens[0].Token != tokenContract {
		t.Fatalf("token must come from permitted.token: %+v", c.Tokens)
	}
	if !c.Unlimited || !c.Tokens[0].Unlimited {
		t.Fatal("permitted.amount == 2^256-1 must be unlimited")
	}
}

// A witnessed PermitTransferFrom that DOES carry a top-level spender uses it as the
// allowlist subject (the optional-spender branch).
func TestRecognizePermit2TransferFromWithSpender(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": permit2Contract}
	msg := map[string]any{
		"permitted": map[string]any{"token": tokenContract, "amount": "1000"},
		"spender":   spenderAddr,
		"nonce":     "0",
		"deadline":  "9999999999",
	}
	c := classifyTypedData("PermitTransferFrom", domain, msg)
	if !c.IsSpend || c.Spender != spenderAddr {
		t.Fatalf("a witnessed PermitTransferFrom must use the top-level spender: %+v", c)
	}
	if c.Unlimited {
		t.Fatal("a bounded amount must not be unlimited")
	}
}

// Permit2 PermitBatchTransferFrom — the batch signature-transfer shape (permitted[] of
// {token,amount}, no top-level spender). It must classify as a spend-equivalent with
// one Tokens entry per permitted item, each carrying its own Unlimited bit.
func TestRecognizePermit2BatchTransferFromNoSpender(t *testing.T) {
	tokenB := "0xb0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
	domain := map[string]any{"chainId": "1", "verifyingContract": permit2Contract}
	msg := map[string]any{
		"permitted": []any{
			map[string]any{"token": tokenContract, "amount": "1000"},       // bounded
			map[string]any{"token": tokenB, "amount": uint256Max.String()}, // unlimited
		},
		"nonce":    "0",
		"deadline": "9999999999",
	}
	c := classifyTypedData("PermitBatchTransferFrom", domain, msg)
	if !c.IsSpend || c.Kind != "approve" {
		t.Fatalf("a real PermitBatchTransferFrom (no top-level spender) must classify as spend-equivalent: %+v", c)
	}
	if c.Spender != "" {
		t.Fatalf("Spender = %q, want empty", c.Spender)
	}
	if len(c.Tokens) != 2 {
		t.Fatalf("Tokens = %d, want one per permitted entry (2)", len(c.Tokens))
	}
	if c.Tokens[0].Token != tokenContract || c.Tokens[0].Unlimited {
		t.Fatalf("entry 0 must be the bounded %s: %+v", tokenContract, c.Tokens[0])
	}
	if c.Tokens[1].Token != tokenB || !c.Tokens[1].Unlimited {
		t.Fatalf("entry 1 must be the unlimited %s: %+v", tokenB, c.Tokens[1])
	}
	if !c.Unlimited {
		t.Fatal("the summary Unlimited must be the OR across entries (one entry is unlimited)")
	}
}

// Permit2 PermitBatch (allowance form) carries one Tokens entry per details[] item,
// each with the underlying token (uint160-max sentinel).
func TestRecognizePermit2BatchUnderlyingTokens(t *testing.T) {
	tokenB := "0xb0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
	domain := map[string]any{"chainId": "1", "verifyingContract": permit2Contract}
	msg := map[string]any{
		"spender": spenderAddr,
		"details": []any{
			map[string]any{"token": tokenContract, "amount": uint160Max.String(), "expiration": "0", "nonce": "0"},
			map[string]any{"token": tokenB, "amount": "5", "expiration": "0", "nonce": "0"},
		},
	}
	c := classifyTypedData("PermitBatch", domain, msg)
	if !c.IsSpend || len(c.Tokens) != 2 {
		t.Fatalf("PermitBatch must carry one token entry per details item: %+v", c)
	}
	if c.Tokens[0].Token != tokenContract || !c.Tokens[0].Unlimited {
		t.Fatalf("entry 0 must be the unlimited underlying token: %+v", c.Tokens[0])
	}
	if c.Tokens[1].Token != tokenB || c.Tokens[1].Unlimited {
		t.Fatalf("entry 1 must be the bounded underlying token: %+v", c.Tokens[1])
	}
}

// A PermitTransferFrom missing the permitted.token (malformed) returns ok=false (the
// §4.2 fail-direction — no partial extraction), falling to the unknown-typed gate.
func TestRecognizePermit2TransferFromMissingTokenFails(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": permit2Contract}
	msg := map[string]any{
		"permitted": map[string]any{"amount": "1000"}, // no token
		"nonce":     "0",
		"deadline":  "0",
	}
	if c := classifyTypedData("PermitTransferFrom", domain, msg); c.IsSpend {
		t.Fatalf("a PermitTransferFrom with no permitted.token must NOT match: %+v", c)
	}
}

// Permit2 ONLY matches on the canonical verifyingContract — a Permit2 shape on a
// different contract is NOT recognized.
func TestRecognizePermit2WrongContract(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": tokenContract}
	msg := map[string]any{"spender": spenderAddr, "details": map[string]any{"amount": "1"}}
	c := classifyTypedData("PermitSingle", domain, msg)
	if c.IsSpend {
		t.Fatalf("a Permit2 shape on a non-Permit2 contract must NOT match: %+v", c)
	}
}

// Chain mismatch: a recognized permit on a chainId different from the active
// network is denied (chain_mismatch).
func TestRecognizeChainMismatch(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": tokenContract}
	msg := map[string]any{
		"owner": "0x2222222222222222222222222222222222222222", "spender": spenderAddr,
		"value": "1", "nonce": "0", "deadline": "0",
	}
	c := ClassifyTypedDataFor(11155111, "Permit", domain, msg) // signing "on Sepolia"
	if !c.Denied || c.DenyReason != "chain_mismatch" {
		t.Fatalf("a chain-1 permit signed on Sepolia must be chain_mismatch: %+v", c)
	}
	// Same chain ⇒ not denied.
	cOK := ClassifyTypedDataFor(1, "Permit", domain, msg)
	if cOK.Denied {
		t.Fatalf("a matching chainId must not be denied: %+v", cOK)
	}
}

// THE load-bearing invariant: a hostile domain.name="Permit" with the WRONG field
// shape must NOT trigger a recognizer (the match is on shape, never the name).
func TestRecognizeNameStringDoesNotMatch(t *testing.T) {
	domain := map[string]any{"chainId": "1", "verifyingContract": tokenContract, "name": "Permit"}
	// A bogus message that is NOT an EIP-2612/DAI shape.
	msg := map[string]any{"foo": "bar", "spender": spenderAddr}
	c := classifyTypedData("Order", domain, msg) // primaryType is not "Permit"
	if c.IsSpend {
		t.Fatalf("a hostile domain.name must not conjure a recognizer match: %+v", c)
	}

	// Even primaryType=="Permit" with a wrong field set must not match (partial
	// extraction is forbidden — fail-direction §4.2).
	wrong := map[string]any{"owner": "0x2222222222222222222222222222222222222222", "spender": spenderAddr}
	if c := classifyTypedData("Permit", domain, wrong); c.IsSpend {
		t.Fatalf("primaryType Permit with the wrong field set must not match: %+v", c)
	}
}

// The engine seam ClassifyTypedData returns the populated class (no error).
func TestEngineClassifyTypedDataSeam(t *testing.T) {
	e := newEngine(t)
	domain := map[string]any{"chainId": "1", "verifyingContract": tokenContract}
	msg := map[string]any{
		"owner": "0x2222222222222222222222222222222222222222", "spender": spenderAddr,
		"value": "1", "nonce": "0", "deadline": "0",
	}
	c, err := e.ClassifyTypedData("Permit", domain, msg)
	if err != nil {
		t.Fatalf("ClassifyTypedData: %v", err)
	}
	if !c.IsSpend || c.Spender != spenderAddr {
		t.Fatalf("seam did not classify: %+v", c)
	}
}
