package policy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/policyseal"
	"github.com/daxchain-io/daxie/internal/secret"
)

// file_test.go pins the §4.5/§4.6 sealed-file contract: seal round-trip,
// tamper→fail, nonce<watermark→rollback, version-skew strict-decode refusal,
// tri-state null vs absent round-trip, and byte-stable body.

// sealedEngine bootstraps a real sealed policy.json under a temp dir using the
// admin path and returns the engine (now anchorFound) plus the anchor + the admin
// passphrase string. It is the shared fixture for the seal/admin tests.
func sealedEngine(t *testing.T, adminPass string) (*Engine, policyseal.Anchor) {
	t.Helper()
	dir := t.TempDir()
	e, err := Open(dir, fixedClock(), policyseal.Anchor{}, false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pass := secret.NewString(adminPass)
	defer pass.Zero()
	max := "1000000000000000000"
	al := true
	anchor, err := e.Set(pass, Change{
		Default:   &Limits{MaxTxWei: &max, AllowlistEnabled: &al},
		WrittenBy: "test/0.4.0",
	})
	if err != nil {
		t.Fatalf("bootstrap Set: %v", err)
	}
	return e, anchor
}

// TestSealRoundTrip confirms a freshly-set policy loads + verifies under its anchor.
func TestSealRoundTrip(t *testing.T) {
	e, anchor := sealedEngine(t, "correct horse battery staple")
	res, err := loadPolicy(e.dir, anchor, true)
	if err != nil {
		t.Fatalf("loadPolicy: %v", err)
	}
	if !res.present || !res.status.Verified {
		t.Fatalf("a freshly sealed policy must verify: %+v", res.status)
	}
	if res.policy.Nonce != 1 {
		t.Fatalf("first set nonce = %d, want 1", res.policy.Nonce)
	}
	if res.policy.Rules.Default.MaxTxWei == nil || *res.policy.Rules.Default.MaxTxWei != "1000000000000000000" {
		t.Fatalf("max_tx not round-tripped: %+v", res.policy.Rules.Default)
	}
}

// TestSealTamperFails confirms a flipped body byte fails verification (seal_violation).
func TestSealTamperFails(t *testing.T) {
	e, anchor := sealedEngine(t, "pass-1")
	path := e.policyPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Flip a byte inside the decoded body and re-encode WITHOUT re-signing.
	body, _ := base64.StdEncoding.DecodeString(env.BodyB64)
	body[len(body)/2] ^= 0xFF
	env.BodyB64 = base64.StdEncoding.EncodeToString(body)
	b, _ := marshalEnvelope(env)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	_, err = loadPolicy(e.dir, anchor, true)
	assertCode(t, err, "policy.seal_violation", domain.ExitTimeoutPending)
}

// TestNonceBelowWatermarkRollback confirms a body whose nonce is below the anchor
// watermark is refused as a rollback (replayed older sealed policy).
func TestNonceBelowWatermarkRollback(t *testing.T) {
	e, anchor := sealedEngine(t, "pass-2")
	// Raise the anchor watermark above the body nonce (simulating a later tighten
	// the operator made; the on-disk body is the older nonce 1).
	anchor.NonceWatermark = 99
	_, err := loadPolicy(e.dir, anchor, true)
	assertCode(t, err, "policy.rollback", domain.ExitTimeoutPending)

	var de *domain.Error
	if errors.As(err, &de) {
		if de.Data["watermark"] != uint64(99) {
			t.Fatalf("rollback payload watermark = %v, want 99", de.Data["watermark"])
		}
	}
}

// TestAnchorPresentPolicyMissing confirms "delete the policy to escape it" is a
// seal violation when an anchor pins a trust root.
func TestAnchorPresentPolicyMissing(t *testing.T) {
	e, anchor := sealedEngine(t, "pass-3")
	if err := os.Remove(e.policyPath()); err != nil {
		t.Fatalf("remove policy: %v", err)
	}
	_, err := loadPolicy(e.dir, anchor, true)
	assertCode(t, err, "policy.seal_violation", domain.ExitTimeoutPending)
}

// TestPolicyPresentAnchorMissing confirms a sealed file with NO anchor is refused
// (no unpinned verification mode, §4.6).
func TestPolicyPresentAnchorMissing(t *testing.T) {
	e, _ := sealedEngine(t, "pass-4")
	_, err := loadPolicy(e.dir, policyseal.Anchor{}, false /* anchorFound=false but file present */)
	// present && !anchorFound ⇒ seal_violation (anchor_missing).
	assertCode(t, err, "policy.seal_violation", domain.ExitTimeoutPending)
}

// TestOptInNoAnchorNoPolicy confirms the opt-in case: no anchor + no policy ⇒
// present=false, no error.
func TestOptInNoAnchorNoPolicy(t *testing.T) {
	dir := t.TempDir()
	res, err := loadPolicy(dir, policyseal.Anchor{}, false)
	if err != nil {
		t.Fatalf("opt-in load must not error: %v", err)
	}
	if res.present {
		t.Fatal("opt-in load must report present=false")
	}
}

// TestVersionSkewRefused confirms a body version newer than this binary is a
// fail-closed policy.version refusal (exit 8) — verified by sealing a hand-built
// body at a future version under a known key.
func TestVersionSkewRefused(t *testing.T) {
	dir := t.TempDir()
	pass := secret.NewString("vskew")
	defer pass.Zero()
	salt, _ := policyseal.NewSalt()
	params := policyseal.DefaultScryptParams()
	sk, pk, err := policyseal.DeriveSealKey(pass.Reveal(), salt, params)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	anchor := policyseal.Anchor{VerifyKey: policyseal.EncodeKey(pk), Salt: policyseal.EncodeSalt(salt), Scrypt: params, NonceWatermark: 0}

	// Hand-build a body at version bodyVersion+1, sealed correctly.
	future := defaultPolicy("future/9.9.9")
	future.Version = bodyVersion + 1
	future.Nonce = 1
	bodyBytes := writeBody(future)
	sig := policyseal.Sign(bodyBytes, sk)
	env := envelope{Version: envelopeVersion, BodyB64: base64.StdEncoding.EncodeToString(bodyBytes), Seal: sealBlock{Alg: sealAlg, Sig: base64.StdEncoding.EncodeToString(sig)}}
	b, _ := marshalEnvelope(env)
	if err := os.WriteFile(filepath.Join(dir, policyFileName), b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, lerr := loadPolicy(dir, anchor, true)
	assertCode(t, lerr, "policy.seal_violation", domain.ExitTimeoutPending)
	assertReason(t, lerr, "policy.version")
}

// TestTriStateRoundTrip confirms absent vs explicit-null vs value survive a
// write→read round-trip distinctly, and that the body bytes are byte-stable
// (two writes of the same policy produce identical bytes — the seal subject).
func TestTriStateRoundTrip(t *testing.T) {
	p := defaultPolicy("test")
	p.Nonce = 1
	val := "5"
	p.Rules.Default.MaxTxWei = &val            // value
	p.Rules.Default.MaxDayWei = nil            // absent
	p.Rules.Default.MaxGasPriceWei = nullStr() // explicit null
	p.Rules.Networks = []NetworkRule{{Network: "sepolia", Limits: Limits{MaxTxWei: nullStr()}}}

	body1 := writeBody(p)
	body2 := writeBody(p)
	if string(body1) != string(body2) {
		t.Fatal("writeBody is not byte-stable for the same policy")
	}

	// Decode and check tri-state distinctions survive.
	got, err := decodeBodyStrict(body1)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Rules.Default.MaxTxWei == nil || *got.Rules.Default.MaxTxWei != "5" {
		t.Fatalf("value field lost: %+v", got.Rules.Default.MaxTxWei)
	}
	if got.Rules.Default.MaxDayWei != nil {
		t.Fatalf("absent field must decode to nil, got %v", *got.Rules.Default.MaxDayWei)
	}
	if !isNull(got.Rules.Default.MaxGasPriceWei) {
		t.Fatalf("explicit-null field must decode to the null sentinel, got %v", got.Rules.Default.MaxGasPriceWei)
	}
	if len(got.Rules.Networks) != 1 || !isNull(got.Rules.Networks[0].MaxTxWei) {
		t.Fatalf("per-network explicit-null lost: %+v", got.Rules.Networks)
	}
}

// TestUnknownFieldRefused confirms the strict decode rejects an unknown body field
// (a restriction this binary might silently drop) — fail-closed policy.version.
func TestUnknownFieldRefused(t *testing.T) {
	dir := t.TempDir()
	pass := secret.NewString("unk")
	defer pass.Zero()
	salt, _ := policyseal.NewSalt()
	params := policyseal.DefaultScryptParams()
	sk, pk, _ := policyseal.DeriveSealKey(pass.Reveal(), salt, params)
	anchor := policyseal.Anchor{VerifyKey: policyseal.EncodeKey(pk), Salt: policyseal.EncodeSalt(salt), Scrypt: params}

	// A body with an extra unknown field, sealed correctly.
	bodyBytes := []byte(`{"version":1,"nonce":1,"updated_at":"","written_by":"x","messages":"allow","tokens_no_allowlist_ok":false,"rules":{"default":{},"networks":[]},"tokens":[],"allowlist":[],"denylist":[],"self_addresses":[],"typed_data":{"unknown":"deny","allowed":[]},"contracts_allowed":[],"surprise_restriction":true}`)
	sig := policyseal.Sign(bodyBytes, sk)
	env := envelope{Version: envelopeVersion, BodyB64: base64.StdEncoding.EncodeToString(bodyBytes), Seal: sealBlock{Alg: sealAlg, Sig: base64.StdEncoding.EncodeToString(sig)}}
	b, _ := marshalEnvelope(env)
	_ = os.WriteFile(filepath.Join(dir, policyFileName), b, 0o600)

	_, lerr := loadPolicy(dir, anchor, true)
	assertCode(t, lerr, "policy.seal_violation", domain.ExitTimeoutPending)
	assertReason(t, lerr, "policy.version")
}

// assertReason asserts the error's data["reason"] equals want.
func assertReason(t *testing.T, err error, want string) {
	t.Helper()
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("want *domain.Error, got %T", err)
	}
	if de.Data["reason"] != want {
		t.Fatalf("reason = %v, want %q", de.Data["reason"], want)
	}
}
