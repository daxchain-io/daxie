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
