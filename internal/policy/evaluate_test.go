package policy

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// evaluate_test.go is the §6 pure-pipeline table suite: per-tx, rolling-24h (via
// an injected clock, no sleeps), gas-cap, allowlist on/off, denylist,
// fail-closed-no-allowlist, precedence, retry_after — all over the PURE Evaluate
// with no I/O.

var (
	dest    = common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	other   = common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	selfAcc = common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
)

func wei(s string) *string { return &s }

// policyWithLimits builds a default-block policy with the given limits + allowlist
// toggle for the table tests.
func policyWithLimits(maxTx, maxDay, maxGas string, allowlist bool) Policy {
	al := allowlist
	return Policy{
		Version:  bodyVersion,
		Messages: "allow",
		Rules: Rules{Default: Limits{
			MaxTxWei:         wei(maxTx),
			MaxDayWei:        wei(maxDay),
			MaxGasPriceWei:   wei(maxGas),
			AllowlistEnabled: &al,
		}},
		TypedData: TypedDataCfg{Unknown: "deny"},
	}
}

func now0() time.Time { return time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC) }

// 1. Per-tx over max_tx → tx_limit.
func TestEvaluatePerTxOverLimit(t *testing.T) {
	p := policyWithLimits("1000000000000000000", "0", "0", false) // 1 ETH per-tx; no day/gas cap
	p.Rules.Default.MaxDayWei = nil
	p.Rules.Default.MaxGasPriceWei = nil
	req := Check{
		Account:  selfAcc,
		Dest:     dest,
		SpendWei: big.NewInt(2_000_000_000_000_000_000), // 2 ETH > 1 ETH
		Network:  "mainnet",
	}
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Allowed {
		t.Fatal("a 2 ETH send must be denied under a 1 ETH per-tx limit")
	}
	if dec.Code != codeTxLimit {
		t.Fatalf("code = %q, want %q", dec.Code, codeTxLimit)
	}
	if dec.Data["limit"] != "1000000000000000000" {
		t.Fatalf("limit payload = %v", dec.Data["limit"])
	}
}

// 2. Within limits + allowlisted dest → allowed.
func TestEvaluateWithinLimitsAllowlisted(t *testing.T) {
	p := policyWithLimits("1000000000000000000", "10000000000000000000", "200000000000", true)
	p.Allowlist = []PinEntry{{Source: "address", Address: lowerHex(dest)}}
	req := Check{
		Account:      selfAcc,
		Dest:         dest,
		SpendWei:     big.NewInt(500_000_000_000_000_000), // 0.5 ETH
		MaxGasWei:    big.NewInt(100_000_000_000_000),
		MaxFeePerGas: big.NewInt(50_000_000_000),
		Network:      "mainnet",
	}
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if !dec.Allowed {
		t.Fatalf("an in-limit allowlisted send must be allowed; got %+v", dec)
	}
}

// 3. Non-allowlisted dest, allowlist on → allowlist (not_allowlisted).
func TestEvaluateNotAllowlisted(t *testing.T) {
	p := policyWithLimits("1000000000000000000", "10000000000000000000", "200000000000", true)
	p.Allowlist = []PinEntry{{Source: "address", Address: lowerHex(other)}}
	req := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(1), Network: "mainnet"}
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Allowed || dec.Code != codeAllowlist {
		t.Fatalf("want allowlist denial, got %+v", dec)
	}
	if dec.Data["reason"] != "not_allowlisted" {
		t.Fatalf("reason = %v, want not_allowlisted", dec.Data["reason"])
	}
}

// 4. Denylisted dest beats allowlist + include_self.
func TestEvaluateDenylistBeatsAll(t *testing.T) {
	p := policyWithLimits("1000000000000000000", "10000000000000000000", "200000000000", true)
	incl := true
	p.Rules.Default.IncludeSelf = &incl
	p.SelfAddresses = []string{lowerHex(dest)}                             // dest is an own account
	p.Allowlist = []PinEntry{{Source: "address", Address: lowerHex(dest)}} // and allowlisted
	p.Denylist = []PinEntry{{Source: "address", Address: lowerHex(dest)}}  // but denylisted
	req := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(1), Network: "mainnet"}
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Allowed || dec.Code != codeAllowlist {
		t.Fatalf("denylist must refuse even an allowlisted own account; got %+v", dec)
	}
	if dec.Data["reason"] != "denylisted" {
		t.Fatalf("reason = %v, want denylisted", dec.Data["reason"])
	}
}

// 4b. include_self passes an own account when not denied.
func TestEvaluateIncludeSelfPasses(t *testing.T) {
	p := policyWithLimits("1000000000000000000", "10000000000000000000", "200000000000", true)
	incl := true
	p.Rules.Default.IncludeSelf = &incl
	p.SelfAddresses = []string{lowerHex(dest)}
	req := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(1), Network: "mainnet"}
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if !dec.Allowed {
		t.Fatalf("include_self against the sealed snapshot must pass; got %+v", dec)
	}
}

// 5. Gas cap refusal → gas_cap, retryable, with attempted payload.
func TestEvaluateGasCap(t *testing.T) {
	p := policyWithLimits("10000000000000000000", "100000000000000000000", "100000000000", false) // cap 100 gwei
	req := Check{
		Account:      selfAcc,
		Dest:         dest,
		SpendWei:     big.NewInt(1),
		MaxFeePerGas: big.NewInt(150_000_000_000), // 150 gwei > 100 gwei cap
		Network:      "mainnet",
	}
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Allowed || dec.Code != codeGasCap {
		t.Fatalf("want gas_cap denial, got %+v", dec)
	}
	if dec.Data["cap"] != "100000000000" || dec.Data["attempted"] != "150000000000" {
		t.Fatalf("gas_cap payload = %+v", dec.Data)
	}
}

// 6. Day-limit on a PRECOMPUTED window sum: Evaluate is window-agnostic (§4.1) —
// it compares the spentWindowWei it is HANDED against max_day. This pins exactly
// that: a bigger pre-summed window trips day_limit (+retry_after), a smaller one
// passes. The actual time-based AGING of the window is exercised end-to-end under
// an injected, advanceable clock in TestRollingWindowAgesOutViaInjectedClock and
// at the exact boundary in TestSumWindowBoundaryExact (counter_test.go); this test
// makes no claim about clock injection.
func TestEvaluateDayLimitOnPrecomputedWindowSum(t *testing.T) {
	p := policyWithLimits("10000000000000000000", "1000000000000000000", "0", false) // 1 ETH/day
	p.Rules.Default.MaxGasPriceWei = nil
	req := Check{
		Account:  selfAcc,
		Dest:     dest,
		SpendWei: big.NewInt(400_000_000_000_000_000), // 0.4 ETH
		Network:  "mainnet",
	}
	// A pre-summed window of 0.8 ETH — 0.8 + 0.4 = 1.2 > 1.0 ⇒ day_limit.
	spent := big.NewInt(800_000_000_000_000_000)
	dec := Evaluate(p, req, spent, now0())
	if dec.Allowed || dec.Code != codeDayLimit {
		t.Fatalf("want day_limit denial, got %+v", dec)
	}
	if dec.RetryAfter == "" {
		t.Fatal("day_limit must carry a retry_after")
	}
	// A smaller pre-summed window of 0.4 ETH passes (0.4 + 0.4 < 1.0).
	decOK := Evaluate(p, req, big.NewInt(400_000_000_000_000_000), now0())
	if !decOK.Allowed {
		t.Fatalf("a smaller pre-summed window must pass; got %+v", decOK)
	}
}

// 7. Fail-closed no-allowlist: limits set, allowlist off, an approval Kind,
// tokens_no_allowlist_ok=false → no_allowlist; an ETH transfer is exempt.
func TestEvaluateFailClosedNoAllowlist(t *testing.T) {
	p := policyWithLimits("1000000000000000000", "10000000000000000000", "0", false)
	p.Rules.Default.MaxGasPriceWei = nil
	p.TokensNoAllowlistOK = false

	approval := Check{Account: selfAcc, Dest: dest, KindEnum: KindApprove, Token: lowerHex(other), Network: "mainnet"}
	dec := Evaluate(p, approval, big.NewInt(0), now0())
	if dec.Allowed || dec.Code != codeNoAllowlist {
		t.Fatalf("an approval with limits-but-no-allowlist must be refused; got %+v", dec)
	}

	// ETH transfer is exempt (the ETH limit caps it directly).
	ethSend := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(1), KindEnum: KindTransfer, Asset: "eth", Network: "mainnet"}
	decEth := Evaluate(p, ethSend, big.NewInt(0), now0())
	if !decEth.Allowed {
		t.Fatalf("an in-limit ETH transfer must be exempt from the no-allowlist rule; got %+v", decEth)
	}
}

// 7b. Admin override (tokens_no_allowlist_ok=true) lifts the fail-closed rule.
func TestEvaluateNoAllowlistAdminOverride(t *testing.T) {
	p := policyWithLimits("1000000000000000000", "10000000000000000000", "0", false)
	p.Rules.Default.MaxGasPriceWei = nil
	p.TokensNoAllowlistOK = true
	approval := Check{Account: selfAcc, Dest: dest, KindEnum: KindApprove, Token: lowerHex(other), Network: "mainnet"}
	dec := Evaluate(p, approval, big.NewInt(0), now0())
	if !dec.Allowed {
		t.Fatalf("the admin override must lift the no-allowlist rule; got %+v", dec)
	}
}

// 8. Precedence: a Check tripping allowlist + tx_limit + gas_cap reports allowlist
// (higher precedence) and details.violations carries all three.
func TestEvaluatePrecedence(t *testing.T) {
	p := policyWithLimits("1000000000000000000", "0", "100000000000", true) // 1 ETH tx; 100 gwei cap; allowlist on
	p.Rules.Default.MaxDayWei = nil
	// dest NOT allowlisted.
	req := Check{
		Account:      selfAcc,
		Dest:         dest,
		SpendWei:     big.NewInt(2_000_000_000_000_000_000), // > tx limit
		MaxFeePerGas: big.NewInt(150_000_000_000),           // > gas cap
		Network:      "mainnet",
	}
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if dec.Code != codeAllowlist {
		t.Fatalf("highest-precedence code = %q, want %q", dec.Code, codeAllowlist)
	}
	if len(dec.Violations) != 3 {
		t.Fatalf("want 3 accumulated violations, got %d: %+v", len(dec.Violations), dec.Violations)
	}
	seen := map[string]bool{}
	for _, v := range dec.Violations {
		seen[v.Code] = true
	}
	for _, want := range []string{codeAllowlist, codeTxLimit, codeGasCap} {
		if !seen[want] {
			t.Fatalf("violations missing %q: %+v", want, dec.Violations)
		}
	}
}

// 9. Unlimited approval ceremony: unacked → unlimited_unacked; acked → allowed;
// allow_unlimited:false → hard deny even when acked.
func TestEvaluateUnlimitedCeremony(t *testing.T) {
	base := func() Policy {
		p := policyWithLimits("1000000000000000000", "0", "0", false)
		p.Rules.Default.MaxDayWei = nil
		p.Rules.Default.MaxGasPriceWei = nil
		p.TokensNoAllowlistOK = true // isolate the unlimited gate from the no-allowlist rule
		return p
	}
	token := lowerHex(other)

	unacked := Check{Account: selfAcc, Dest: dest, KindEnum: KindApprove, Token: token, Unlimited: true, Network: "mainnet"}
	if dec := Evaluate(base(), unacked, big.NewInt(0), now0()); dec.Allowed || dec.Code != codeUnlimitedUnacked {
		t.Fatalf("an unacked unlimited approval must be denied; got %+v", dec)
	}

	acked := unacked
	acked.Acked = true
	if dec := Evaluate(base(), acked, big.NewInt(0), now0()); !dec.Allowed {
		t.Fatalf("an acked unlimited approval must be allowed; got %+v", dec)
	}

	hard := base()
	no := false
	hard.Tokens = []TokenRule{{Network: "mainnet", Address: token, AllowUnlimited: &no}}
	if dec := Evaluate(hard, acked, big.NewInt(0), now0()); dec.Allowed || dec.Code != codeUnlimitedUnacked {
		t.Fatalf("allow_unlimited:false must hard-deny even when acked; got %+v", dec)
	}
}

// 10. Per-network override: an explicit-null per-network max_tx means "no limit",
// so a send that would exceed the default passes on that network.
func TestEvaluatePerNetworkNullOverride(t *testing.T) {
	p := policyWithLimits("1000000000000000000", "0", "0", false) // default 1 ETH tx
	p.Rules.Default.MaxDayWei = nil
	p.Rules.Default.MaxGasPriceWei = nil
	p.Rules.Networks = []NetworkRule{{Network: "sepolia", Limits: Limits{MaxTxWei: nullStr()}}}
	req := Check{Account: selfAcc, Dest: dest, SpendWei: big.NewInt(5_000_000_000_000_000_000), Network: "sepolia"}
	dec := Evaluate(p, req, big.NewInt(0), now0())
	if !dec.Allowed {
		t.Fatalf("an explicit-null per-network limit means no limit; got %+v", dec)
	}
	// On mainnet the default 1 ETH limit still bites.
	req.Network = "mainnet"
	if dec := Evaluate(p, req, big.NewInt(0), now0()); dec.Allowed {
		t.Fatal("the default limit must still apply on mainnet")
	}
}

// 11. Pin drift: an ENS input whose fresh resolution differs from the pin →
// pin_drift (ens_drift); a matching resolution passes.
func TestEvaluatePinDrift(t *testing.T) {
	p := policyWithLimits("1000000000000000000", "0", "0", true)
	p.Rules.Default.MaxDayWei = nil
	p.Rules.Default.MaxGasPriceWei = nil
	p.Allowlist = []PinEntry{{Source: "ens", Name: "vitalik.eth", Address: lowerHex(dest)}}

	// Fresh resolution drifts to `other`.
	drift := Check{
		Account: selfAcc, Dest: dest, SpendWei: big.NewInt(1), Network: "mainnet",
		ToSrc: SourceENS, ENSName: "vitalik.eth", ToInput: "vitalik.eth", ENSResolved: other,
	}
	dec := Evaluate(p, drift, big.NewInt(0), now0())
	if dec.Code != codePinDrift || dec.Data["reason"] != "ens_drift" {
		t.Fatalf("want ens_drift, got %+v", dec)
	}

	// Matching resolution passes.
	ok := drift
	ok.ENSResolved = dest
	if dec := Evaluate(p, ok, big.NewInt(0), now0()); !dec.Allowed {
		t.Fatalf("a matching ENS resolution must pass; got %+v", dec)
	}
}
