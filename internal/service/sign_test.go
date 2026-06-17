package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/policy"
	"github.com/daxchain-io/daxie/internal/secret"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// sign_test.go covers the M9 signing core: the EIP-191 prefix digest (against a
// hand-computed reference vector) + --no-hash; the EIP-712 digest (against geth's
// reference); authorizeSignature gating a recognized permit (allowlist / unlimited /
// chain-mismatch); the unknown-typed deny + allow; verify recovered==claimed +
// ecrecover correctness + a tampered signature rejected; and the messages kill switch.
//
// A recoverableSigner holds a REAL secp256k1 key so signHash → SigToPub round-trips
// (the fakeSigner returns a zero signature, which cannot be recovered). It is the
// minimum needed to prove the ecrecover path end-to-end without a keystore.

type recoverableSigner struct {
	priv *ecdsa.PrivateKey
	addr common.Address
}

func newRecoverableSigner(t *testing.T, scalar byte) *recoverableSigner {
	t.Helper()
	b := make([]byte, 32)
	b[31] = scalar // a small, fixed, valid scalar ⇒ a deterministic key/address
	priv, err := gethcrypto.ToECDSA(b)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}
	return &recoverableSigner{priv: priv, addr: gethcrypto.PubkeyToAddress(priv.PublicKey)}
}

func (r *recoverableSigner) Address(_ context.Context, _ domain.AccountRef) (common.Address, error) {
	return r.addr, nil
}
func (r *recoverableSigner) SignTx(_ context.Context, _ domain.AccountRef, tx *types.Transaction, _ *big.Int, _ domain.Unlocker) ([]byte, common.Hash, error) {
	raw, _ := tx.MarshalBinary()
	return raw, tx.Hash(), nil
}
func (r *recoverableSigner) SignHash(_ context.Context, _ domain.AccountRef, hash common.Hash, _ domain.Unlocker) ([]byte, error) {
	return gethcrypto.Sign(hash.Bytes(), r.priv) // 65-byte [R||S||V] with V ∈ {0,1}
}

var _ domain.Signer = (*recoverableSigner)(nil)

// newAdminSecret returns the admin passphrase sealPolicy/allowSpender use (so the
// typed admin mutations authenticate against the same bootstrapped anchor).
func newAdminSecret() *secret.Bytes { return secret.NewString("unit-admin-pass") }

// signService wires a service with a real recoverable signer (so verify round-trips).
func signService(t *testing.T) (*Service, *recoverableSigner) {
	t.Helper()
	rs := newRecoverableSigner(t, 0x07)
	svc, _, _ := sendService(t, rs.addr)
	svc.signer = rs
	return svc, rs
}

// ── EIP-191 ───────────────────────────────────────────────────────────────────

// TestEIP191DigestReferenceVector pins the EIP-191 digest against the hand-computed
// keccak256("\x19Ethereum Signed Message:\n" + len + payload). geth's accounts.TextHash
// is the impl; here we recompute the prefix independently so a future geth change that
// alters the prefix is caught.
func TestEIP191DigestReferenceVector(t *testing.T) {
	msg := []byte("hello daxie")
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg)))
	want := gethcrypto.Keccak256Hash(append(prefix, msg...))
	got := eip191Digest(msg)
	if got != want {
		t.Fatalf("EIP-191 digest = %s, want %s (the \\x19 prefix must be applied)", got.Hex(), want.Hex())
	}
}

// TestSignMessageNoHashStillPrefixed confirms --no-hash signs the 32-byte digest WITH
// the EIP-191 prefix applied over those 32 bytes — never the raw unprefixed digest
// (raw eth_sign is never offered, §4.2 row 2).
func TestSignMessageNoHashStillPrefixed(t *testing.T) {
	svc, rs := signService(t)
	digest32 := gethcrypto.Keccak256([]byte("pre-hashed payload")) // 32 bytes

	res, err := svc.SignMessage(context.Background(), domain.LocalCLI(), domain.SignMessageRequest{
		Account: rs.addr.Hex(),
		Message: digest32,
		NoHash:  true,
	})
	if err != nil {
		t.Fatalf("SignMessage --no-hash: %v", err)
	}
	// The signed digest must be the EIP-191 prefix over the 32 bytes, NOT the 32 bytes
	// themselves (the prefix-always-applied invariant).
	prefix := []byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(digest32)))
	wantDigest := gethcrypto.Keccak256Hash(append(prefix, digest32...))
	if res.Digest != wantDigest.Hex() {
		t.Fatalf("--no-hash digest = %s, want the EIP-191-prefixed digest %s", res.Digest, wantDigest.Hex())
	}
	if res.Digest == ("0x" + common.Bytes2Hex(digest32)) {
		t.Fatal("--no-hash signed the RAW unprefixed digest — the EIP-191 prefix was skipped")
	}
	if res.Scheme != "eip191" {
		t.Fatalf("scheme = %q, want eip191", res.Scheme)
	}
}

// TestSignMessageVStripped27 confirms the emitted signature carries V ∈ {27,28} for
// wallet interop (geth signs with {0,1}; sigResult bumps it).
func TestSignMessageVNormalizedForWallets(t *testing.T) {
	svc, rs := signService(t)
	res, err := svc.SignMessage(context.Background(), domain.LocalCLI(), domain.SignMessageRequest{
		Account: rs.addr.Hex(), Message: []byte("v test"),
	})
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	sig := common.FromHex(res.Signature)
	if len(sig) != 65 {
		t.Fatalf("signature len = %d, want 65", len(sig))
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Fatalf("V = %d, want 27 or 28 (wallet interop)", sig[64])
	}
}

// ── EIP-712 digest ──────────────────────────────────────────────────────────────

func eip2612PermitDoc(t *testing.T, token, owner, spender common.Address, value string, chainID int64) []byte {
	t.Helper()
	doc := map[string]any{
		"types": map[string]any{
			"EIP712Domain": []any{
				map[string]any{"name": "name", "type": "string"},
				map[string]any{"name": "version", "type": "string"},
				map[string]any{"name": "chainId", "type": "uint256"},
				map[string]any{"name": "verifyingContract", "type": "address"},
			},
			"Permit": []any{
				map[string]any{"name": "owner", "type": "address"},
				map[string]any{"name": "spender", "type": "address"},
				map[string]any{"name": "value", "type": "uint256"},
				map[string]any{"name": "nonce", "type": "uint256"},
				map[string]any{"name": "deadline", "type": "uint256"},
			},
		},
		"primaryType": "Permit",
		"domain": map[string]any{
			"name":              "TestToken",
			"version":           "1",
			"chainId":           chainID,
			"verifyingContract": token.Hex(),
		},
		"message": map[string]any{
			"owner":    owner.Hex(),
			"spender":  spender.Hex(),
			"value":    value,
			"nonce":    "0",
			"deadline": "9999999999",
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal permit doc: %v", err)
	}
	return b
}

// TestEIP712DigestMatchesGeth confirms eip712Digest equals apitypes.TypedDataAndHash
// (the EIP-712 reference) for a well-formed permit.
func TestEIP712DigestMatchesGeth(t *testing.T) {
	doc := eip2612PermitDoc(t, someAddr(0x42), someAddr(0x01), someAddr(0x0b), "1000", 1)
	var td apitypes.TypedData
	if err := json.Unmarshal(doc, &td); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, err := eip712Digest(&td)
	if err != nil {
		t.Fatalf("eip712Digest: %v", err)
	}
	want, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		t.Fatalf("TypedDataAndHash: %v", err)
	}
	if got != common.BytesToHash(want) {
		t.Fatalf("EIP-712 digest = %s, want %s", got.Hex(), common.BytesToHash(want).Hex())
	}
}

// ── authorizeSignature: the recognized-permit gate ──────────────────────────────

// signServiceWithPolicy seals a policy (limits + allowlist toggle) on the signing
// service so authorizeSignature runs the REAL engine.
func signServiceWithPolicy(t *testing.T, ch policy.Change) (*Service, *recoverableSigner) {
	t.Helper()
	svc, rs := signService(t)
	sealPolicy(t, svc, ch)
	return svc, rs
}

// TestSignTypedPermitAllowlistedSpenderSigns confirms a recognized EIP-2612 permit to
// an ALLOWLISTED spender on the active chain signs (the spend-equivalent gate passed).
func TestSignTypedPermitAllowlistedSpenderSigns(t *testing.T) {
	spender := someAddr(0x0b)
	token := someAddr(0x42)
	al := true
	maxTx := "1000000000000000000"
	svc, rs := signServiceWithPolicy(t, policy.Change{
		Default:   &policy.Limits{MaxTxWei: &maxTx, AllowlistEnabled: &al},
		WrittenBy: "test",
	})
	// Allowlist the spender via the engine (admin pass = "unit-admin-pass").
	allowSpender(t, svc, spender)

	doc := eip2612PermitDoc(t, token, rs.addr, spender, "1000", 1) // chainId 1 == fake active
	res, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet",
	})
	if err != nil {
		t.Fatalf("SignTyped (allowlisted permit) must sign: %v", err)
	}
	if res.Scheme != "eip712" || res.Signature == "" {
		t.Fatalf("expected a signed eip712 result, got %+v", res)
	}
}

// TestSignTypedPermitNonAllowlistedSpenderDenied is the load-bearing one: a permit to
// a NON-allowlisted spender is denied at SIGNATURE time (policy.denied.allowlist), and
// the key is NEVER touched (no signature returned).
func TestSignTypedPermitNonAllowlistedSpenderDenied(t *testing.T) {
	spender := someAddr(0x0b)
	token := someAddr(0x42)
	al := true
	maxTx := "1000000000000000000"
	svc, rs := signServiceWithPolicy(t, policy.Change{
		Default:   &policy.Limits{MaxTxWei: &maxTx, AllowlistEnabled: &al},
		WrittenBy: "test",
	})
	// NO allow entry for the spender.

	doc := eip2612PermitDoc(t, token, rs.addr, spender, "1000", 1)
	res, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet",
	})
	if err == nil {
		t.Fatal("a permit to a non-allowlisted spender MUST be denied at signature time")
	}
	if code := domain.AsError(err).Code; code != domain.CodePolicyDeniedAllowlist {
		t.Fatalf("code = %q, want %q", code, domain.CodePolicyDeniedAllowlist)
	}
	if res.Signature != "" {
		t.Fatal("the key was touched on a denied permit — the signature must be empty")
	}
}

// TestSignTypedPermitUnlimitedUnackedDenied confirms an UNLIMITED permit (value =
// 2^256-1) to an allowlisted spender is denied without the --unlimited --yes ack.
func TestSignTypedPermitUnlimitedUnackedDenied(t *testing.T) {
	spender := someAddr(0x0b)
	token := someAddr(0x42)
	al := true
	maxTx := "1000000000000000000"
	svc, rs := signServiceWithPolicy(t, policy.Change{
		Default:   &policy.Limits{MaxTxWei: &maxTx, AllowlistEnabled: &al},
		WrittenBy: "test",
	})
	allowSpender(t, svc, spender)

	maxUint := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	doc := eip2612PermitDoc(t, token, rs.addr, spender, maxUint.String(), 1)

	// Without Acked ⇒ unlimited_unacked.
	_, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet",
	})
	if err == nil {
		t.Fatal("an unlimited permit without the ack must be denied")
	}
	if code := domain.AsError(err).Code; code != domain.CodePolicyDeniedUnlimited {
		t.Fatalf("code = %q, want %q", code, domain.CodePolicyDeniedUnlimited)
	}

	// With Acked ⇒ signs.
	if _, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet", AckUnlimited: true,
	}); err != nil {
		t.Fatalf("an acknowledged unlimited permit must sign: %v", err)
	}
}

// TestSignTypedPermitWrongChainDenied confirms a permit declaring a DIFFERENT chainId
// than the active network is denied (chain_mismatch) — the classic exfiltration trick.
func TestSignTypedPermitWrongChainDenied(t *testing.T) {
	spender := someAddr(0x0b)
	token := someAddr(0x42)
	al := true
	maxTx := "1000000000000000000"
	svc, rs := signServiceWithPolicy(t, policy.Change{
		Default:   &policy.Limits{MaxTxWei: &maxTx, AllowlistEnabled: &al},
		WrittenBy: "test",
	})
	allowSpender(t, svc, spender)

	doc := eip2612PermitDoc(t, token, rs.addr, spender, "1000", 137) // chainId 137 ≠ active 1
	_, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet",
	})
	if err == nil {
		t.Fatal("a permit for a different chainId than the active network must be denied")
	}
	de := domain.AsError(err)
	if de.Code != domain.CodePolicyDeniedTypedData {
		t.Fatalf("code = %q, want %q", de.Code, domain.CodePolicyDeniedTypedData)
	}
	if reason, _ := de.Data["reason"].(string); reason != "chain_mismatch" {
		t.Fatalf("reason = %v, want chain_mismatch", de.Data["reason"])
	}
}

// permit2Addr is the canonical Permit2 deployment (the recognizer match key).
var permit2Addr = common.HexToAddress("0x000000000022D473030F116dDEE9F6B43aC78BA3")

// permit2SingleDoc builds a Permit2 PermitSingle EIP-712 document — the exact shape
// `daxie sign typed` consumes and matchPermit2 accepts: verifyingContract == Permit2,
// primaryType "PermitSingle", message {details{token,amount,expiration,nonce}, spender,
// sigDeadline}. The underlying ERC-20 (details.token) is what the per-token
// allow_unlimited rule must bind — NOT the Permit2 contract.
func permit2SingleDoc(t *testing.T, underlying, spender common.Address, amount string, chainID int64) []byte {
	t.Helper()
	doc := map[string]any{
		"types": map[string]any{
			"EIP712Domain": []any{
				map[string]any{"name": "name", "type": "string"},
				map[string]any{"name": "chainId", "type": "uint256"},
				map[string]any{"name": "verifyingContract", "type": "address"},
			},
			"PermitSingle": []any{
				map[string]any{"name": "details", "type": "PermitDetails"},
				map[string]any{"name": "spender", "type": "address"},
				map[string]any{"name": "sigDeadline", "type": "uint256"},
			},
			"PermitDetails": []any{
				map[string]any{"name": "token", "type": "address"},
				map[string]any{"name": "amount", "type": "uint160"},
				map[string]any{"name": "expiration", "type": "uint48"},
				map[string]any{"name": "nonce", "type": "uint48"},
			},
		},
		"primaryType": "PermitSingle",
		"domain": map[string]any{
			"name":              "Permit2",
			"chainId":           chainID,
			"verifyingContract": permit2Addr.Hex(),
		},
		"message": map[string]any{
			"details": map[string]any{
				"token":      underlying.Hex(),
				"amount":     amount,
				"expiration": "0",
				"nonce":      "0",
			},
			"spender":     spender.Hex(),
			"sigDeadline": "9999999999",
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal permit2 doc: %v", err)
	}
	return b
}

// permit2TransferFromDoc builds the canonical Permit2 PermitTransferFrom — the
// SIGNATURE-TRANSFER shape with NO top-level spender (the spender is bound as
// msg.sender on-chain). This is the high-severity dead-code case: the old recognizer
// required a top-level spender and so never fired for this shape.
func permit2TransferFromDoc(t *testing.T, underlying common.Address, amount string, chainID int64) []byte {
	t.Helper()
	doc := map[string]any{
		"types": map[string]any{
			"EIP712Domain": []any{
				map[string]any{"name": "name", "type": "string"},
				map[string]any{"name": "chainId", "type": "uint256"},
				map[string]any{"name": "verifyingContract", "type": "address"},
			},
			"PermitTransferFrom": []any{
				map[string]any{"name": "permitted", "type": "TokenPermissions"},
				map[string]any{"name": "nonce", "type": "uint256"},
				map[string]any{"name": "deadline", "type": "uint256"},
			},
			"TokenPermissions": []any{
				map[string]any{"name": "token", "type": "address"},
				map[string]any{"name": "amount", "type": "uint256"},
			},
		},
		"primaryType": "PermitTransferFrom",
		"domain": map[string]any{
			"name":              "Permit2",
			"chainId":           chainID,
			"verifyingContract": permit2Addr.Hex(),
		},
		"message": map[string]any{
			"permitted": map[string]any{"token": underlying.Hex(), "amount": amount},
			"nonce":     "0",
			"deadline":  "9999999999",
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal permit2 transferFrom doc: %v", err)
	}
	return b
}

// TestSignTypedPermit2HardDenyOnUnderlyingToken is the medium-severity fix: an
// allow_unlimited:false rule on the UNDERLYING ERC-20 must hard-deny an unlimited
// Permit2 approval of that token — even with the --unlimited --yes ack. Before the
// fix the rule keyed on the Permit2 contract (cls.Verifying) so it was inoperative.
func TestSignTypedPermit2HardDenyOnUnderlyingToken(t *testing.T) {
	spender := someAddr(0x0b)
	underlying := someAddr(0x42)
	al := true
	maxTx := "1000000000000000000"
	deny := false
	svc, rs := signServiceWithPolicy(t, policy.Change{
		Default: &policy.Limits{MaxTxWei: &maxTx, AllowlistEnabled: &al},
		// Hard-deny unlimited approvals of the UNDERLYING token on mainnet.
		Tokens:    []policy.TokenRule{{Network: "mainnet", Address: strings.ToLower(underlying.Hex()), AllowUnlimited: &deny}},
		WrittenBy: "test",
	})
	allowSpender(t, svc, spender)

	// uint160 max ⇒ the Permit2 unlimited sentinel.
	uint160Max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	doc := permit2SingleDoc(t, underlying, spender, uint160Max.String(), 1)

	// Even WITH the ack, the per-token hard-deny refuses.
	_, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet", AckUnlimited: true,
	})
	if err == nil {
		t.Fatal("an unlimited Permit2 approval of an allow_unlimited:false token must be hard-denied (even acked)")
	}
	if code := domain.AsError(err).Code; code != domain.CodePolicyDeniedUnlimited {
		t.Fatalf("code = %q, want %q", code, domain.CodePolicyDeniedUnlimited)
	}

	// The SAME rule on a DIFFERENT token does not block this one (proves the key is the
	// underlying token, not the Permit2 contract): a bounded amount of the hard-denied
	// token still signs.
	bounded := permit2SingleDoc(t, underlying, spender, "1000", 1)
	if _, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: bounded, Network: "mainnet",
	}); err != nil {
		t.Fatalf("a BOUNDED Permit2 approval of the same token must sign: %v", err)
	}
}

// TestSignTypedPermit2TransferFromGated is the high-severity fix at the service level:
// a canonical PermitTransferFrom (NO top-level spender) is classified as a spend-
// equivalent and GATED — an unlimited one without the ack is denied, and with the ack
// it signs. Before the fix it fell through to the deny-by-default unknown-typed gate.
func TestSignTypedPermit2TransferFromGated(t *testing.T) {
	underlying := someAddr(0x42)
	al := false // no allowlist: with no signed spender the Dest is the zero address.
	maxTx := "1000000000000000000"
	ok := true
	svc, rs := signServiceWithPolicy(t, policy.Change{
		// allowlist OFF + tokens_no_allowlist_ok so the spend-equivalent is not blocked
		// by the stage-3c fail-closed rule — we are isolating the unlimited-ack ceremony.
		Default:         &policy.Limits{MaxTxWei: &maxTx, AllowlistEnabled: &al},
		TokensNoAllowOK: &ok,
		WrittenBy:       "test",
	})

	uint256Max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	doc := permit2TransferFromDoc(t, underlying, uint256Max.String(), 1)

	// Unlimited without the ack ⇒ the unlimited-ack ceremony denies (NOT the
	// deny-by-default unknown-typed gate — proving the recognizer FIRED).
	_, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet",
	})
	if err == nil {
		t.Fatal("an unlimited PermitTransferFrom without the ack must be denied")
	}
	if code := domain.AsError(err).Code; code != domain.CodePolicyDeniedUnlimited {
		t.Fatalf("code = %q, want %q (the spend-equivalent ceremony, not typed_data.unknown)", code, domain.CodePolicyDeniedUnlimited)
	}

	// With the ack ⇒ signs (the spend-equivalent gate passed; it was never the unknown gate).
	if _, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet", AckUnlimited: true,
	}); err != nil {
		t.Fatalf("an acknowledged PermitTransferFrom must sign: %v", err)
	}
}

// ── authorizeSignature: the unknown-typed gate ──────────────────────────────────

func unknownOrderDoc(t *testing.T, verifying common.Address, chainID int64) []byte {
	t.Helper()
	doc := map[string]any{
		"types": map[string]any{
			"EIP712Domain": []any{
				map[string]any{"name": "name", "type": "string"},
				map[string]any{"name": "chainId", "type": "uint256"},
				map[string]any{"name": "verifyingContract", "type": "address"},
			},
			"OrderComponents": []any{
				map[string]any{"name": "offerer", "type": "address"},
				map[string]any{"name": "amount", "type": "uint256"},
			},
		},
		"primaryType": "OrderComponents",
		"domain": map[string]any{
			"name":              "Seaport",
			"chainId":           chainID,
			"verifyingContract": verifying.Hex(),
		},
		"message": map[string]any{
			"offerer": someAddr(0x01).Hex(),
			"amount":  "5",
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal order doc: %v", err)
	}
	return b
}

// TestSignTypedUnknownDeniedByDefault confirms an unrecognized typed message is denied
// (typed_data.unknown) once a policy is active, and signing again succeeds after the
// per-domain allow entry is sealed.
func TestSignTypedUnknownDeniedThenAllowed(t *testing.T) {
	verifying := someAddr(0x55)
	al := true
	maxTx := "1000000000000000000"
	svc, rs := signServiceWithPolicy(t, policy.Change{
		Default:   &policy.Limits{MaxTxWei: &maxTx, AllowlistEnabled: &al},
		WrittenBy: "test",
	})

	doc := unknownOrderDoc(t, verifying, 1)
	_, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet",
	})
	if err == nil {
		t.Fatal("unrecognized typed data must be deny-by-default once a policy is active")
	}
	de := domain.AsError(err)
	if de.Code != domain.CodePolicyDeniedTypedData {
		t.Fatalf("code = %q, want %q", de.Code, domain.CodePolicyDeniedTypedData)
	}
	if reason, _ := de.Data["reason"].(string); reason != "unknown" {
		t.Fatalf("reason = %v, want unknown", de.Data["reason"])
	}

	// Seal a per-domain allow entry for the triple (chain 1, verifying, OrderComponents).
	pass := newAdminSecret()
	defer pass.Zero()
	if _, err := svc.policy.TypedAllow(pass, policy.TypedAllowEntry{
		ChainID:           1,
		VerifyingContract: strings.ToLower(verifying.Hex()),
		PrimaryType:       "OrderComponents",
		WrittenBy:         "test",
	}); err != nil {
		t.Fatalf("TypedAllow: %v", err)
	}

	if _, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet",
	}); err != nil {
		t.Fatalf("after the per-domain allow, signing must succeed: %v", err)
	}
}

// ── verify (ecrecover) ──────────────────────────────────────────────────────────

// TestVerifyMessageRoundTrip confirms a signed EIP-191 message verifies against the
// claimed signer, and a tampered signature / wrong address are rejected.
func TestVerifyMessageRoundTrip(t *testing.T) {
	svc, rs := signService(t)
	msg := []byte("sign in with ethereum")
	sig, err := svc.SignMessage(context.Background(), domain.LocalCLI(), domain.SignMessageRequest{
		Account: rs.addr.Hex(), Message: msg,
	})
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	// Valid round-trip.
	res, err := svc.Verify(context.Background(), domain.LocalCLI(), domain.VerifyRequest{
		Message: msg, Signature: sig.Signature, Address: rs.addr.Hex(),
	})
	if err != nil {
		t.Fatalf("Verify (valid) returned error: %v", err)
	}
	if !res.Valid || !strings.EqualFold(res.Recovered, rs.addr.Hex()) {
		t.Fatalf("valid round-trip failed: %+v (want recovered %s)", res, rs.addr.Hex())
	}

	// Wrong claimed address ⇒ mismatch (exit 2), valid:false, recovered echoed.
	other := someAddr(0xaa)
	res2, err := svc.Verify(context.Background(), domain.LocalCLI(), domain.VerifyRequest{
		Message: msg, Signature: sig.Signature, Address: other.Hex(),
	})
	if err == nil {
		t.Fatal("a wrong claimed address must produce verify.mismatch")
	}
	if domain.AsError(err).Code != domain.CodeVerifyMismatch {
		t.Fatalf("code = %q, want %q", domain.AsError(err).Code, domain.CodeVerifyMismatch)
	}
	if domain.ExitOf(domain.AsError(err).Code) != domain.ExitUsage {
		t.Fatalf("verify.mismatch must be exit 2, got %d", domain.ExitOf(domain.AsError(err).Code))
	}
	if res2.Valid {
		t.Fatal("mismatch result must be valid:false")
	}
	if !strings.EqualFold(res2.Recovered, rs.addr.Hex()) {
		t.Fatalf("mismatch must echo the recovered address %s, got %s", rs.addr.Hex(), res2.Recovered)
	}

	// Tampered signature ⇒ recovers a different address ⇒ mismatch (never valid).
	bad := []byte(sig.Signature)
	bad[10] ^= 0xff // flip a hex nibble in R
	res3, _ := svc.Verify(context.Background(), domain.LocalCLI(), domain.VerifyRequest{
		Message: msg, Signature: string(bad), Address: rs.addr.Hex(),
	})
	if res3.Valid {
		t.Fatal("a tampered signature must NOT verify as valid")
	}
}

// TestVerifyTypedRoundTrip confirms an EIP-712 signature verifies via ecrecover.
func TestVerifyTypedRoundTrip(t *testing.T) {
	spender := someAddr(0x0b)
	token := someAddr(0x42)
	al := true
	maxTx := "1000000000000000000"
	svc, rs := signServiceWithPolicy(t, policy.Change{
		Default:   &policy.Limits{MaxTxWei: &maxTx, AllowlistEnabled: &al},
		WrittenBy: "test",
	})
	allowSpender(t, svc, spender)
	doc := eip2612PermitDoc(t, token, rs.addr, spender, "1000", 1)

	sig, err := svc.SignTyped(context.Background(), domain.LocalCLI(), domain.SignTypedRequest{
		Account: rs.addr.Hex(), Typed: doc, Network: "mainnet",
	})
	if err != nil {
		t.Fatalf("SignTyped: %v", err)
	}
	res, err := svc.Verify(context.Background(), domain.LocalCLI(), domain.VerifyRequest{
		Typed: doc, Signature: sig.Signature, Address: rs.addr.Hex(),
	})
	if err != nil {
		t.Fatalf("Verify typed: %v", err)
	}
	if !res.Valid || res.Scheme != "eip712" {
		t.Fatalf("typed verify failed: %+v", res)
	}
}

// TestVerifyBadSignatureRejected confirms a malformed 0x signature is verify.bad_signature.
func TestVerifyBadSignatureRejected(t *testing.T) {
	svc, rs := signService(t)
	for _, sig := range []string{"nothex", "0x1234", "abcd"} {
		_, err := svc.Verify(context.Background(), domain.LocalCLI(), domain.VerifyRequest{
			Message: []byte("x"), Signature: sig, Address: rs.addr.Hex(),
		})
		if err == nil || domain.AsError(err).Code != domain.CodeVerifyBadSig {
			t.Fatalf("signature %q: code = %v, want verify.bad_signature", sig, err)
		}
	}
}

// ── messages kill switch ────────────────────────────────────────────────────────

// TestSignMessageDeniedByKillSwitch confirms messages:"deny" refuses EIP-191 signing.
func TestSignMessageDeniedByKillSwitch(t *testing.T) {
	svc, rs := signService(t)
	deny := "deny"
	sealPolicy(t, svc, policy.Change{Messages: &deny, WrittenBy: "test"})

	_, err := svc.SignMessage(context.Background(), domain.LocalCLI(), domain.SignMessageRequest{
		Account: rs.addr.Hex(), Message: []byte("blocked"),
	})
	if err == nil {
		t.Fatal("messages:deny must refuse EIP-191 signing")
	}
	if domain.AsError(err).Code != domain.CodePolicyDeniedTypedData {
		t.Fatalf("code = %q, want a policy.denied.* code", domain.AsError(err).Code)
	}
}

// TestSignMessageNoPolicyAllowed confirms EIP-191 signing works with no policy (opt-in).
func TestSignMessageNoPolicyAllowed(t *testing.T) {
	svc, rs := signService(t)
	if _, err := svc.SignMessage(context.Background(), domain.LocalCLI(), domain.SignMessageRequest{
		Account: rs.addr.Hex(), Message: []byte("ok"),
	}); err != nil {
		t.Fatalf("with no policy, EIP-191 signing must be allowed: %v", err)
	}
}
