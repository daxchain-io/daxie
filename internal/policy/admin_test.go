package policy

import (
	"context"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/policyseal"
	"github.com/daxchain-io/daxie/internal/secret"
	"github.com/ethereum/go-ethereum/common"
)

// admin_test.go pins the §4.7 admin surface: Set bumps nonce + watermark, wrong
// pass ⇒ admin_auth, reset authenticates against the ANCHOR not the file, and the
// staged change-admin-passphrase rotation. Plus the engine-level reserve/commit/
// release/settle lifecycle against a REAL sealed policy.

// TestSetBumpsNonceAndWatermark confirms a second `policy set` verifies, bumps the
// body nonce, and advances the anchor watermark.
func TestSetBumpsNonceAndWatermark(t *testing.T) {
	e, anchor := sealedEngine(t, "admin-pass")
	if anchor.NonceWatermark != 1 {
		t.Fatalf("first set watermark = %d, want 1", anchor.NonceWatermark)
	}
	pass := secret.NewString("admin-pass")
	defer pass.Zero()
	max := "2000000000000000000"
	anchor2, err := e.Set(pass, Change{Default: &Limits{MaxTxWei: &max}, WrittenBy: "test"})
	if err != nil {
		t.Fatalf("second Set: %v", err)
	}
	if anchor2.NonceWatermark != 2 {
		t.Fatalf("second set watermark = %d, want 2", anchor2.NonceWatermark)
	}
	res, err := loadPolicy(e.dir, anchor2, true)
	if err != nil {
		t.Fatalf("load after second set: %v", err)
	}
	if res.policy.Nonce != 2 {
		t.Fatalf("body nonce = %d, want 2", res.policy.Nonce)
	}
	if *res.policy.Rules.Default.MaxTxWei != "2000000000000000000" {
		t.Fatalf("max_tx not updated: %v", res.policy.Rules.Default.MaxTxWei)
	}
}

// TestSetWrongPassIsAdminAuth confirms a mutation under the wrong admin passphrase
// is policy.admin_auth (the derived pk != the anchor's verify key).
func TestSetWrongPassIsAdminAuth(t *testing.T) {
	e, _ := sealedEngine(t, "right-pass")
	wrong := secret.NewString("WRONG-pass")
	defer wrong.Zero()
	max := "1"
	_, err := e.Set(wrong, Change{Default: &Limits{MaxTxWei: &max}})
	assertCode(t, err, "policy.admin_auth", domain.ExitTimeoutPending)
}

// TestResetAuthenticatesAgainstAnchor confirms reset --force authenticates against
// the ANCHOR (not the file): a TRASHED policy.json still resets under the correct
// pass, and a WRONG pass is refused even though the file is unreadable (the
// prompt-injection defense, §4.7 J12).
func TestResetAuthenticatesAgainstAnchor(t *testing.T) {
	e, _ := sealedEngine(t, "reset-pass")

	// Trash policy.json (simulating a prompt-compromised agent).
	if err := os.WriteFile(e.policyPath(), []byte("garbage not a sealed envelope"), 0o600); err != nil {
		t.Fatalf("trash: %v", err)
	}

	// A WRONG pass must be refused even though the file is trashed.
	wrong := secret.NewString("attacker-chosen-pass")
	if _, err := e.ResetForce(wrong, nil, "test"); err == nil {
		t.Fatal("reset under a wrong pass must be refused")
	} else {
		assertCode(t, err, "policy.admin_auth", domain.ExitTimeoutPending)
	}
	wrong.Zero()

	// The CORRECT pass reseals a fresh default body at watermark+1.
	right := secret.NewString("reset-pass")
	defer right.Zero()
	anchor, err := e.ResetForce(right, nil, "test")
	if err != nil {
		t.Fatalf("reset under the correct pass: %v", err)
	}
	res, lerr := loadPolicy(e.dir, anchor, true)
	if lerr != nil {
		t.Fatalf("load after reset: %v", lerr)
	}
	if res.policy.Nonce != anchor.NonceWatermark {
		t.Fatalf("reset nonce = %d, watermark = %d; want equal (watermark+1 of the old)", res.policy.Nonce, anchor.NonceWatermark)
	}
	if res.policy.Nonce < 2 {
		t.Fatalf("reset nonce = %d, want > the prior watermark (1)", res.policy.Nonce)
	}
}

// TestChangeAdminPassphraseRotation walks the staged rotation: --stage records
// verify_key_next; the OLD pass still verifies; --commit re-derives + reseals under
// the new key family; the NEW pass then authenticates and the OLD one does not.
func TestChangeAdminPassphraseRotation(t *testing.T) {
	e, _ := sealedEngine(t, "old-pass")
	ctx := context.Background()

	old := secret.NewString("old-pass")
	neu := secret.NewString("new-pass")
	defer old.Zero()
	defer neu.Zero()

	// --stage: authenticate old, derive new, record verify_key_next + staged_salt.
	staged, err := e.ChangeAdminPassphrase(old, neu, true, false)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if staged.VerifyKeyNext == "" || staged.StagedSalt == "" {
		t.Fatalf("stage did not record the next key/salt: %+v", staged)
	}
	// The old key still verifies the on-disk body (zero-outage).
	if _, _, verr := e.Verify(); verr != nil {
		t.Fatalf("the old key must still verify after --stage: %v", verr)
	}

	// --commit: re-derive from the staged salt, reseal under the new key family.
	committed, err := e.ChangeAdminPassphrase(old, neu, false, true)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if committed.VerifyKeyNext != "" || committed.StagedSalt != "" {
		t.Fatalf("commit must clear the staged rotation: %+v", committed)
	}

	// The NEW pass now authenticates a mutation; the OLD one does not.
	max := "3"
	if _, err := e.Set(neu, Change{Default: &Limits{MaxTxWei: &max}}); err != nil {
		t.Fatalf("set under the new pass must succeed: %v", err)
	}
	if _, err := e.Set(old, Change{Default: &Limits{MaxTxWei: &max}}); err == nil {
		t.Fatal("set under the OLD pass must fail after the rotation committed")
	} else {
		assertCode(t, err, "policy.admin_auth", domain.ExitTimeoutPending)
	}
	_ = ctx
}

// TestAllowDenyPinning confirms allow/deny add pinned entries and --remove drops
// them, and that a denylisted destination is refused at Evaluate.
func TestAllowDenyPinning(t *testing.T) {
	e, _ := sealedEngine(t, "pin-pass")
	ctx := context.Background()
	pass := secret.NewString("pin-pass")
	defer pass.Zero()

	// Allow `dest` so an in-limit send to it passes.
	if _, err := e.Allow(pass, AllowEntry{PinEntry: PinEntry{Source: "address", Address: lowerHex(dest)}}); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	okCheck := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(1), Network: "mainnet"}
	if dec, err := e.Evaluate(ctx, okCheck); err != nil || !dec.Allowed {
		t.Fatalf("allowlisted send must pass; dec=%+v err=%v", dec, err)
	}

	// Deny `dest` — now it is refused (denylist beats allowlist).
	if _, err := e.Deny(pass, DenyEntry{PinEntry: PinEntry{Source: "address", Address: lowerHex(dest)}}); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if dec, err := e.Evaluate(ctx, okCheck); err != nil || dec.Allowed || dec.Code != codeAllowlist {
		t.Fatalf("denylisted send must be refused; dec=%+v err=%v", dec, err)
	}

	// Remove the deny — passes again.
	if _, err := e.Deny(pass, DenyEntry{PinEntry: PinEntry{Source: "address", Address: lowerHex(dest)}, Remove: true}); err != nil {
		t.Fatalf("Deny --remove: %v", err)
	}
	if dec, err := e.Evaluate(ctx, okCheck); err != nil || !dec.Allowed {
		t.Fatalf("after removing the deny the send must pass; dec=%+v err=%v", dec, err)
	}
}

// TestPinVerifyCanary confirms the passphrase-free `pin --verify` canary: the
// correct key verifies, a wrong key does not.
func TestPinVerifyCanary(t *testing.T) {
	e, anchor := sealedEngine(t, "canary-pass")
	ok, err := e.PinVerify(anchor.VerifyKey)
	if err != nil || !ok {
		t.Fatalf("the pinned key must verify the on-disk policy; ok=%v err=%v", ok, err)
	}
	// A different key (freshly generated) must not verify.
	salt, _ := policyseal.NewSalt()
	_, pk, _ := policyseal.DeriveSealKey([]byte("some-other-pass"), salt, policyseal.DefaultScryptParams())
	bad, err := e.PinVerify(policyseal.EncodeKey(pk))
	if err != nil {
		t.Fatalf("PinVerify(bad): %v", err)
	}
	if bad {
		t.Fatal("a wrong key must NOT verify the on-disk policy (the canary)")
	}
}

// ── engine-level lifecycle against a REAL sealed policy ──────────────────────-

// sealedEngineWithLimits bootstraps a sealed policy with explicit limits + an
// allowlisted dest so Reserve/Evaluate can be exercised end-to-end.
func sealedEngineWithLimits(t *testing.T, maxTx, maxDay string) *Engine {
	return sealedEngineWithLimitsClock(t, maxTx, maxDay, fixedClock())
}

// sealedEngineWithLimitsClock is sealedEngineWithLimits with an injectable clock
// (the engine reads it on every call), so a test can advance the rolling-24h
// window and assert debits age out.
func sealedEngineWithLimitsClock(t *testing.T, maxTx, maxDay string, clock func() time.Time) *Engine {
	t.Helper()
	dir := t.TempDir()
	e, err := Open(dir, clock, policyseal.Anchor{}, false)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pass := secret.NewString("limits-pass")
	defer pass.Zero()
	al := false // allowlist off so the ETH path is governed by limits only
	_, err = e.Set(pass, Change{
		Default:         &Limits{MaxTxWei: &maxTx, MaxDayWei: &maxDay, AllowlistEnabled: &al},
		TokensNoAllowOK: boolp(true),
		WrittenBy:       "test",
	})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	return e
}

func boolp(b bool) *bool { return &b }

// TestReserveDeniedWritesNothing confirms a denied Reserve (over max_tx) returns
// exit 3 and writes NO reservation and NO counter debit (the denial precedes any
// durable write — the ordering service depends on).
func TestReserveDeniedWritesNothing(t *testing.T) {
	e := sealedEngineWithLimits(t, "1000000000000000000", "10000000000000000000") // 1 ETH tx
	ctx := context.Background()
	over := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(2_000_000_000_000_000_000), Network: "mainnet"}
	_, err := e.Reserve(ctx, over)
	assertCode(t, err, codeTxLimit, domain.ExitPolicyDenied)

	orphans, _ := e.Orphans(ctx)
	if len(orphans) != 0 {
		t.Fatalf("a denied Reserve must write no reservation; got %d", len(orphans))
	}
}

// TestReserveCommitDebitsWindow confirms a reserved-then-committed send counts
// toward the rolling-24h window, so a second send that would exceed max_day is
// denied day_limit.
func TestReserveCommitDebitsWindow(t *testing.T) {
	e := sealedEngineWithLimits(t, "10000000000000000000", "1000000000000000000") // 1 ETH/day
	ctx := context.Background()

	first := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(700_000_000_000_000_000), Network: "mainnet"}
	r, err := e.Reserve(ctx, first)
	if err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	if err := e.Commit(ctx, r.ID, common.HexToHash("0xabc")); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// A second 0.7 ETH send: 0.7 + 0.7 = 1.4 > 1.0 ⇒ day_limit.
	second := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(700_000_000_000_000_000), Network: "mainnet"}
	_, err = e.Reserve(ctx, second)
	assertCode(t, err, codeDayLimit, domain.ExitPolicyDenied)
}

// TestReserveReleaseFreesWindow confirms a released (pre-sign) reservation drops
// out of the window, so a follow-up send that would otherwise exceed the day limit
// now fits — over-count is safe, but a genuine pre-sign release frees headroom.
func TestReserveReleaseFreesWindow(t *testing.T) {
	e := sealedEngineWithLimits(t, "10000000000000000000", "1000000000000000000") // 1 ETH/day
	ctx := context.Background()

	first := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(700_000_000_000_000_000), Network: "mainnet"}
	r, err := e.Reserve(ctx, first)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	// Release before sign (a local pre-sign failure).
	if err := e.Release(ctx, r.ID); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// The window is free again: another 0.7 ETH send fits.
	second := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(700_000_000_000_000_000), Network: "mainnet"}
	if _, err := e.Reserve(ctx, second); err != nil {
		t.Fatalf("after release the window must be free; got %v", err)
	}
}

// TestOverCountIsSafeCommittedNeverReleases confirms the §4.4 invariant: once a
// reservation is committed (signed bytes broadcast), Release is a no-op — its
// window debit stands (over-count is the safe direction).
func TestOverCountIsSafeCommittedNeverReleases(t *testing.T) {
	e := sealedEngineWithLimits(t, "10000000000000000000", "1000000000000000000")
	ctx := context.Background()

	r, err := e.Reserve(ctx, Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(700_000_000_000_000_000), Network: "mainnet"})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := e.Commit(ctx, r.ID, common.HexToHash("0xdef")); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Attempt to release a COMMITTED reservation — must be a no-op.
	if err := e.Release(ctx, r.ID); err != nil {
		t.Fatalf("Release after Commit: %v", err)
	}
	// The window debit must still stand: a second 0.7 ETH send is denied.
	_, err = e.Reserve(ctx, Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(700_000_000_000_000_000), Network: "mainnet"})
	assertCode(t, err, codeDayLimit, domain.ExitPolicyDenied)
}

// TestSettleActualGasDownOnly confirms the §5.4 down-only gas adjustment: a
// confirmed (reverted=false) SettleActual shrinks the worst-case gas to the actual
// gas in the window, freeing headroom for a later send.
func TestSettleActualGasDownOnly(t *testing.T) {
	e := sealedEngineWithLimits(t, "10000000000000000000", "1000000000000000000")
	ctx := context.Background()

	r, err := e.Reserve(ctx, Check{
		Account: selfAcc, Dest: dest,
		SpendWei: big.NewInt(0), MaxGasWei: big.NewInt(900_000_000_000_000_000), // ~0.9 ETH worst-case gas
		Network: "mainnet",
	})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := e.Commit(ctx, r.ID, common.HexToHash("0x111")); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Settle gas down to 0.1 ETH actual (confirmed, not reverted).
	if err := e.SettleActual(ctx, r.ID, big.NewInt(100_000_000_000_000_000), false); err != nil {
		t.Fatalf("SettleActual: %v", err)
	}
	// The window now counts ~0.1 ETH gas, so a 0.8 ETH send fits (0.1 + 0.8 < 1.0).
	if _, err := e.Reserve(ctx, Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(800_000_000_000_000_000), Network: "mainnet"}); err != nil {
		t.Fatalf("after the down-only gas settle the window must have headroom; got %v", err)
	}
}

// TestSettleActualRevertReleasesValue confirms the §4.4 "on a revert, value
// released" rule: a SettleActual with reverted=true keeps the actual gas counted
// but ZEROES the native value in the rolling-24h window (the EVM never moved it),
// so a later send that the still-counted value would have denied now fits.
func TestSettleActualRevertReleasesValue(t *testing.T) {
	e := sealedEngineWithLimits(t, "10000000000000000000", "1000000000000000000") // 1 ETH/day
	ctx := context.Background()

	// A 0.7 ETH send with ~0.05 ETH worst-case gas.
	r, err := e.Reserve(ctx, Check{
		Account: selfAcc, Dest: dest,
		SpendWei: big.NewInt(700_000_000_000_000_000), MaxGasWei: big.NewInt(50_000_000_000_000_000),
		Network: "mainnet",
	})
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := e.Commit(ctx, r.ID, common.HexToHash("0x222")); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Before the revert: the window counts 0.7 value + ~0.05 gas = ~0.75, so a 0.5
	// ETH send is denied (0.75 + 0.5 > 1.0).
	_, err = e.Reserve(ctx, Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(500_000_000_000_000_000), Network: "mainnet"})
	assertCode(t, err, codeDayLimit, domain.ExitPolicyDenied)

	// The receipt reverted: settle with reverted=true. Gas settles to 0.02 actual;
	// the 0.7 value is RELEASED (never moved on-chain).
	if err := e.SettleActual(ctx, r.ID, big.NewInt(20_000_000_000_000_000), true); err != nil {
		t.Fatalf("SettleActual(reverted): %v", err)
	}

	// The window now counts only ~0.02 ETH gas (value released), so a 0.9 ETH send
	// fits (0.02 + 0.9 < 1.0).
	if _, err := e.Reserve(ctx, Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(900_000_000_000_000_000), Network: "mainnet"}); err != nil {
		t.Fatalf("after a reverted settle the value must be released; got %v", err)
	}
}

// TestRBFGasAccrualCrossLink confirms a speedup (IsRBFDelta + matching
// account_nonce) appends a candidate to the EXISTING entry (max-across-candidates,
// not a new entry), so the counted envelope is the max of the candidates.
func TestRBFGasAccrualCrossLink(t *testing.T) {
	e := sealedEngineWithLimits(t, "10000000000000000000", "1000000000000000000") // 1 ETH/day
	ctx := context.Background()
	nonce := uint64(42)

	// Original send: 0.3 ETH value, account_nonce 42.
	orig := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(300_000_000_000_000_000), Network: "mainnet", AccountNonce: &nonce}
	r1, err := e.Reserve(ctx, orig)
	if err != nil {
		t.Fatalf("orig Reserve: %v", err)
	}
	if err := e.Commit(ctx, r1.ID, common.HexToHash("0xa1")); err != nil {
		t.Fatalf("orig Commit: %v", err)
	}

	// Speedup: a higher gas candidate on the SAME nonce (RBF delta).
	speedup := Check{
		Account: selfAcc, Dest: dest, SpendWei: big.NewInt(300_000_000_000_000_000),
		MaxGasWei: big.NewInt(200_000_000_000_000_000), // 0.2 ETH gas
		Network:   "mainnet", AccountNonce: &nonce, IsRBFDelta: true,
	}
	if _, err := e.Reserve(ctx, speedup); err != nil {
		t.Fatalf("speedup Reserve: %v", err)
	}

	// The window must count the MAX across candidates (value 0.3 + gas 0.2 = 0.5),
	// NOT the sum of two separate 0.3-value entries. So a 0.4 ETH send fits
	// (0.5 + 0.4 < 1.0) but a 0.6 ETH send does not (0.5 + 0.6 > 1.0).
	if _, err := e.Reserve(ctx, Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(400_000_000_000_000_000), Network: "mainnet"}); err != nil {
		t.Fatalf("a 0.4 ETH send should fit (max-across-candidates, not summed); got %v", err)
	}
	_, err = e.Reserve(ctx, Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(600_000_000_000_000_000), Network: "mainnet"})
	assertCode(t, err, codeDayLimit, domain.ExitPolicyDenied)
}

// TestPermitDoesNotReserve confirms a KindPermit is allowed (when its gates pass)
// but reserves NOTHING — no reservation record, no counter debit (§4.4 permits do
// not reserve).
func TestPermitDoesNotReserve(t *testing.T) {
	e, _ := sealedEngine(t, "permit-pass")
	ctx := context.Background()
	pass := secret.NewString("permit-pass")
	defer pass.Zero()
	// Allow the spender + allow tokens without allowlist so the permit passes.
	if _, err := e.Allow(pass, AllowEntry{PinEntry: PinEntry{Source: "address", Address: lowerHex(dest)}}); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	permit := Check{Account: selfAcc, Dest: dest, KindEnum: KindPermit, Token: tokenContract, Network: "mainnet"}
	r, err := e.Reserve(ctx, permit)
	if err != nil {
		t.Fatalf("permit Reserve: %v", err)
	}
	if r.ID != "" {
		t.Fatalf("a permit must not produce a reservation id; got %q", r.ID)
	}
	orphans, _ := e.Orphans(ctx)
	if len(orphans) != 0 {
		t.Fatalf("a permit must reserve nothing; got %d orphans", len(orphans))
	}
}

// TestRollingWindowAgesOutViaInjectedClock drives the ACTUAL rolling-24h aging
// path end-to-end through the engine with an INJECTED, ADVANCEABLE clock (no
// sleeps): Reserve+Commit a debit at t0, confirm a same-size second send is denied
// while both are inside the window, then ADVANCE the clock past 24h and assert the
// aged-out first debit no longer counts (the same send now passes). This exercises
// sumWindow's ts.Before(now-24h) cutoff under a real clock advance — the property
// the lens requires.
func TestRollingWindowAgesOutViaInjectedClock(t *testing.T) {
	clock, p := mutableClock()
	e := sealedEngineWithLimitsClock(t, "10000000000000000000", "1000000000000000000", clock) // 1 ETH/day
	ctx := context.Background()

	// t0: a 0.7 ETH send reserved + committed (it enters the window).
	r, err := e.Reserve(ctx, Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(700_000_000_000_000_000), Network: "mainnet"})
	if err != nil {
		t.Fatalf("first Reserve: %v", err)
	}
	if err := e.Commit(ctx, r.ID, common.HexToHash("0xa0")); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Still inside the window: a second 0.7 ETH send is denied (0.7 + 0.7 > 1.0).
	_, err = e.Reserve(ctx, Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(700_000_000_000_000_000), Network: "mainnet"})
	assertCode(t, err, codeDayLimit, domain.ExitPolicyDenied)

	// Advance the injected clock just past 24h so the first debit ages out.
	*p = p.Add(24*time.Hour + time.Nanosecond)

	// The first debit is now older than now−24h ⇒ it no longer counts; the same
	// 0.7 ETH send fits.
	if _, err := e.Reserve(ctx, Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(700_000_000_000_000_000), Network: "mainnet"}); err != nil {
		t.Fatalf("after advancing past 24h the first debit must age out; got %v", err)
	}
}

// TestDailyLimitAggregatesAcrossAccounts is the §4.1 "Limit scope" security
// property: the rolling-24h daily limit is AGGREGATE across ALL keystore accounts
// on a network, not per account. The unit of compromise is the keystore
// passphrase, so a compromised agent controlling N accounts must NOT be able to
// spend N× max_day. Account A consumes most of the daily budget; a send on a
// DIFFERENT account B that would fit a per-account cap must still be denied because
// the aggregate would exceed max_day.
func TestDailyLimitAggregatesAcrossAccounts(t *testing.T) {
	e := sealedEngineWithLimits(t, "10000000000000000000", "1000000000000000000") // 1 ETH/day aggregate
	ctx := context.Background()

	acctA := selfAcc
	acctB := other
	// The engine must see BOTH accounts as on-network (the policy⊥keystore hook).
	e.SetAccountsHook(func(string) []common.Address { return []common.Address{acctA, acctB} })

	// Account A spends 0.8 ETH (committed → in the window).
	rA, err := e.Reserve(ctx, Check{Account: acctA, Dest: dest, SpendWei: big.NewInt(800_000_000_000_000_000), Network: "mainnet"})
	if err != nil {
		t.Fatalf("acctA Reserve: %v", err)
	}
	if err := e.Commit(ctx, rA.ID, common.HexToHash("0xa")); err != nil {
		t.Fatalf("acctA Commit: %v", err)
	}

	// Account B now tries 0.5 ETH. Per-account it would fit (B has spent nothing),
	// but the AGGREGATE is 0.8 + 0.5 = 1.3 > 1.0 ⇒ denied. This is the keystone
	// guardrail: N accounts cannot multiply the cap.
	_, err = e.Reserve(ctx, Check{Account: acctB, Dest: dest, SpendWei: big.NewInt(500_000_000_000_000_000), Network: "mainnet"})
	assertCode(t, err, codeDayLimit, domain.ExitPolicyDenied)

	// A small 0.1 ETH send on B fits (0.8 + 0.1 < 1.0) — the aggregate has headroom.
	if _, err := e.Reserve(ctx, Check{Account: acctB, Dest: dest, SpendWei: big.NewInt(100_000_000_000_000_000), Network: "mainnet"}); err != nil {
		t.Fatalf("a within-aggregate send on B must fit; got %v", err)
	}
}
