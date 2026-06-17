package service

import (
	"context"
	"math/big"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/config"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ethunit"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// gas.go is the M3 gas engine (design §5.4). It resolves the per-tx gas decision
// (limit + fees) with the §5.4 precedence and computes the worst-case gas cost
// the policy reservation counts against. All value math is *big.Int (§2.5) —
// the operator config multipliers are float64 (config is allowed float, §5.4),
// but they are folded into big.Int math via exact rational scaling, never a
// float multiply of a wei value.
//
// The fee/percentile policy itself lives in ONE place — chain.SuggestFees folds
// eth_feeHistory(20,"latest",[25,50,90]) + the median/percentile math into the
// single method (§2.6) — so buildGas and Gas only consume its output and apply
// the max-fee formula + overrides on top. The gas-cap (policy.max-gas-price)
// check is NOT here: it is the policy.Reserve/Evaluate hook (the M4 body); M3
// buildGas only computes WorstCaseGasWei so the Check the kernel passes policy is
// complete.

// intrinsicEOAGas is the exact intrinsic cost of a plain value transfer with no
// calldata. eth_estimateGas returns exactly this for an EOA→EOA send, and it is
// used AS-IS (the §5.4 exception) — never multiplied by the limit-multiplier,
// because the intrinsic cost is exact and a 1.2× would just overpay headroom.
const intrinsicEOAGas uint64 = 21000

// Quote is the resolved gas decision for one tx (§5.4). No float (§2.5): every
// fee is a *big.Int. Source records which fallback-ladder rung the fee estimate
// came from so `gas`/`tx send --json` is honest about a degraded RPC.
type Quote struct {
	Legacy   bool
	GasLimit uint64

	MaxFeePerGas *big.Int // 1559: the cap
	PriorityFee  *big.Int // 1559: the tip
	GasPrice     *big.Int // legacy: the flat price

	BaseFee *big.Int // next block's base fee (for the `gas` display)
	Speed   domain.Speed
	Source  string // "fee-history" | "fallback" | "legacy"

	// WorstCaseGasWei = GasLimit × MaxFeePerGas (1559) or × GasPrice (legacy) —
	// the value policy.Reserve durably counts before signing (§5.1/§5.4).
	WorstCaseGasWei *big.Int
}

// result projects a Quote into the wire GasResult (decimal strings, no float).
func (q Quote) result() domain.GasResult {
	r := domain.GasResult{
		Legacy:   q.Legacy,
		GasLimit: q.GasLimit,
		Speed:    string(q.Speed),
		Source:   q.Source,
	}
	if q.Legacy {
		if q.GasPrice != nil {
			r.GasPrice = q.GasPrice.String()
		}
	} else {
		if q.MaxFeePerGas != nil {
			r.MaxFeePerGas = q.MaxFeePerGas.String()
		}
		if q.PriorityFee != nil {
			r.PriorityFee = q.PriorityFee.String()
		}
	}
	if q.BaseFee != nil {
		r.BaseFee = q.BaseFee.String()
	}
	if q.WorstCaseGasWei != nil {
		r.WorstCaseGasWei = q.WorstCaseGasWei.String()
	}
	return r
}

// gasParams is the effective gas strategy for a network: the network's
// [networks.<n>.gas] sparse override layered over the global [gas] (§5.4
// precedence config(networks.<n>.gas.* > gas.*)). It carries only the knobs the
// engine reads (the rest live in config). legacy folds the network's Legacy flag
// and the request's --legacy.
type gasParams struct {
	limitMultiplier   float64
	baseFeeMultiplier float64
	minPriorityFee    *big.Int // resolved from the "0.01gwei" string
	defaultSpeed      domain.Speed
	rbfBumpPercent    float64
	feeHistoryBlocks  int // gas.fee-history-blocks: the eth_feeHistory window (§5.4)
	legacy            bool
}

// gasParamsFor resolves the effective gas strategy for the given network name +
// the request's --legacy. The network's *GasDefaults override (when present)
// shadows the global field-by-field; an absent network inherits the global
// strategy wholesale.
func (s *Service) gasParamsFor(network string, reqLegacy bool) gasParams {
	g := s.cfg.Gas // global strategy (a value copy)
	legacy := reqLegacy
	if net, ok := s.cfg.Networks[network]; ok {
		legacy = legacy || net.Legacy
		if net.Gas != nil {
			g = overlayGas(g, *net.Gas)
		}
	}
	p := gasParams{
		limitMultiplier:   g.LimitMultiplier,
		baseFeeMultiplier: g.BaseFeeMultiplier,
		defaultSpeed:      parseSpeed(g.Speed, domain.SpeedNormal),
		rbfBumpPercent:    g.RBFBumpPercent,
		feeHistoryBlocks:  g.FeeHistoryBlocks,
		legacy:            legacy,
	}
	p.minPriorityFee = parseFeeFloor(g.MinPriorityFee)
	return p
}

// overlayGas layers a sparse network gas override over the global strategy. A
// zero field on the override means "inherit"; viper unmarshals an omitted key to
// the zero value, so a network that only sets base-fee-multiplier inherits the
// rest. (Operator config; float is allowed here, §5.4.)
func overlayGas(base, over config.GasDefaults) config.GasDefaults {
	out := base
	if over.LimitMultiplier != 0 {
		out.LimitMultiplier = over.LimitMultiplier
	}
	if over.BaseFeeMultiplier != 0 {
		out.BaseFeeMultiplier = over.BaseFeeMultiplier
	}
	if over.MinPriorityFee != "" {
		out.MinPriorityFee = over.MinPriorityFee
	}
	if over.Speed != "" {
		out.Speed = over.Speed
	}
	if over.RBFBumpPercent != 0 {
		out.RBFBumpPercent = over.RBFBumpPercent
	}
	if over.FeeHistoryBlocks != 0 {
		out.FeeHistoryBlocks = over.FeeHistoryBlocks
	}
	return out
}

// buildGas resolves the per-tx limit + fees with the §5.4 precedence
// (flag > env > config(networks.<n>.gas.* > gas.*) > estimated), folding the
// network legacy mode + the 21000 EOA exception. It also fills in.gas so the
// kernel can journal the fees and the policy Check carries WorstCaseGasWei. The
// caller has already populated in.to/in.value/in.data and dialed in.cc.
//
// Env precedence is handled UPSTREAM by the cli frontend (it resolves
// flag>env>config into the TxRequest gas fields, §5.4); buildGas sees the
// already-layered request values and treats a non-empty field as an explicit
// override over the estimate.
func (s *Service) buildGas(ctx context.Context, cc chain.Client, in *Intent, req domain.TxRequest) (Quote, error) {
	gp := s.gasParamsFor(in.network, req.Legacy)
	speed := parseSpeed(req.Speed, gp.defaultSpeed)

	// ── gas limit ──
	limit, err := s.resolveGasLimit(ctx, cc, in, req)
	if err != nil {
		return Quote{}, err
	}

	if gp.legacy {
		q, qerr := s.buildLegacyFees(ctx, cc, req, speed, limit)
		if qerr != nil {
			return Quote{}, qerr
		}
		in.gas = q
		return q, nil
	}

	q, qerr := s.build1559Fees(ctx, cc, req, gp, speed, limit)
	if qerr != nil {
		return Quote{}, qerr
	}
	in.gas = q
	return q, nil
}

// resolveGasLimit applies the §5.4 limit rule: an explicit --gas-limit is used
// verbatim; else eth_estimateGas × limit-multiplier (rounded up), EXCEPT exactly
// 21000 (plain EOA transfer) which is used as-is. A revert-on-estimate surfaces
// as tx.reverted (exit 7), insufficient-funds as funds.insufficient (exit 5).
func (s *Service) resolveGasLimit(ctx context.Context, cc chain.Client, in *Intent, req domain.TxRequest) (uint64, error) {
	if req.GasLimit != "" {
		n, perr := parseUint(req.GasLimit)
		if perr != nil {
			return 0, domain.Newf(domain.CodeUsage+".bad_gas_limit",
				"invalid --gas-limit %q: want a positive integer", req.GasLimit)
		}
		return n, nil
	}

	msg := ethereum.CallMsg{
		From:  in.from,
		To:    &in.to,
		Value: in.value,
		Data:  in.data,
	}
	est, eerr := cc.EstimateGas(ctx, msg)
	if eerr != nil {
		return 0, mapEstimateErr(eerr)
	}
	// The §5.4 exception: an exactly-21000 estimate (intrinsic EOA cost) is used
	// as-is — no headroom multiplier. A contract call is never 21000.
	if est == intrinsicEOAGas && len(in.data) == 0 {
		return intrinsicEOAGas, nil
	}
	return mulCeilUint(est, s.gasParamsFor(in.network, req.Legacy).limitMultiplier), nil
}

// build1559Fees resolves EIP-1559 fees with the §5.4 max-fee formula + the
// partial-override precedence. SuggestFees folds the feeHistory percentile math;
// this applies the formula and the overrides on top.
func (s *Service) build1559Fees(ctx context.Context, cc chain.Client, req domain.TxRequest, gp gasParams, speed domain.Speed, limit uint64) (Quote, error) {
	// A legacy-only flag on a 1559 network is a usage error (§5.4).
	if req.GasPrice != "" {
		return Quote{}, domain.New(domain.CodeUsage+".gas_price_non_legacy",
			"--gas-price is legacy-only; on an EIP-1559 network use --max-fee/--priority-fee")
	}

	fees, ferr := cc.SuggestFees(ctx, gp.feeHistoryBlocks)
	if ferr != nil {
		// Fallback ladder (§5.4): the adapter already degrades feeHistory →
		// (maxPriority+header) internally and surfaces the failure only when even
		// that path is unreachable, so a SuggestFees error here is terminal —
		// map it to rpc.unreachable and let the caller branch.
		return Quote{}, mapRPCErr(ferr)
	}
	baseFee := fees.BaseFee
	source := fees.Source
	if source == "" {
		source = "fee-history"
	}
	// Select the priority-fee tier for --speed (slow→25th, normal→50th, fast→90th).
	estTip := fees.Priority(speedColumn(speed))
	if estTip == nil {
		estTip = big.NewInt(0)
	} else {
		estTip = new(big.Int).Set(estTip)
	}
	// Priority-fee floor (gas.min-priority-fee).
	if gp.minPriorityFee != nil && estTip.Cmp(gp.minPriorityFee) < 0 {
		estTip = new(big.Int).Set(gp.minPriorityFee)
	}

	// Parse explicit overrides (decimal+unit, e.g. "30gwei").
	ovMaxFee, err := parseOptionalFee(req.MaxFee, "--max-fee")
	if err != nil {
		return Quote{}, err
	}
	ovTip, err := parseOptionalFee(req.PriorityFee, "--priority-fee")
	if err != nil {
		return Quote{}, err
	}

	var tip, maxFee *big.Int
	switch {
	case ovMaxFee != nil && ovTip != nil:
		// Both explicit — verbatim; tip must be ≤ maxFee (§5.4 → exit 2).
		tip, maxFee = ovTip, ovMaxFee
		if tip.Cmp(maxFee) > 0 {
			return Quote{}, domain.New(domain.CodeUsage+".tip_exceeds_max_fee",
				"--priority-fee exceeds --max-fee")
		}
	case ovTip != nil:
		// Tip alone → recompute maxFee from the formula with the explicit tip.
		tip = ovTip
		maxFee = maxFeeFormula(gp.baseFeeMultiplier, baseFee, tip)
	case ovMaxFee != nil:
		// MaxFee alone → tip = min(speed estimate, maxFee) (§5.4).
		maxFee = ovMaxFee
		tip = new(big.Int).Set(estTip)
		if tip.Cmp(maxFee) > 0 {
			tip = new(big.Int).Set(maxFee)
		}
	default:
		// No overrides → the formula.
		tip = estTip
		maxFee = maxFeeFormula(gp.baseFeeMultiplier, baseFee, tip)
	}

	q := Quote{
		Legacy:       false,
		GasLimit:     limit,
		MaxFeePerGas: maxFee,
		PriorityFee:  tip,
		BaseFee:      baseFee,
		Speed:        speed,
		Source:       source,
	}
	q.WorstCaseGasWei = worstCaseGas(limit, maxFee)
	return q, nil
}

// speedColumn maps a --speed preset to the SuggestFees percentile column index
// (slow→0/25th, normal→1/50th, fast→2/90th — the binding §5.4 triple).
func speedColumn(s domain.Speed) int {
	switch s {
	case domain.SpeedSlow:
		return 0
	case domain.SpeedFast:
		return 2
	default: // SpeedNormal and any unset value
		return 1
	}
}

// buildLegacyFees resolves a legacy (pre-1559) gas price: an explicit
// --gas-price verbatim, else eth_gasPrice × the speed multiplier (slow ×1.0,
// normal ×1.2, fast ×1.5, §5.4). --max-fee/--priority-fee on a legacy network →
// exit 2.
func (s *Service) buildLegacyFees(ctx context.Context, cc chain.Client, req domain.TxRequest, speed domain.Speed, limit uint64) (Quote, error) {
	if req.MaxFee != "" || req.PriorityFee != "" {
		return Quote{}, domain.New(domain.CodeUsage+".eip1559_on_legacy",
			"--max-fee/--priority-fee are 1559-only; on a legacy network use --gas-price")
	}

	var price *big.Int
	if req.GasPrice != "" {
		p, perr := parseFee(req.GasPrice, "--gas-price")
		if perr != nil {
			return Quote{}, perr
		}
		price = p
	} else {
		base, gerr := cc.SuggestGasPrice(ctx)
		if gerr != nil {
			return Quote{}, mapRPCErr(gerr)
		}
		price = mulSpeed(base, speed)
	}

	q := Quote{
		Legacy:          true,
		GasLimit:        limit,
		GasPrice:        price,
		Speed:           speed,
		Source:          "legacy",
		WorstCaseGasWei: worstCaseGas(limit, price),
	}
	return q, nil
}

// Gas is the read-only `daxie gas` use case (§5.4): it dials the endpoint, reads
// all three speed quotes, and returns them + the next base fee. On a legacy
// network it reads eth_gasPrice × the three multipliers instead.
func (s *Service) Gas(ctx context.Context, p domain.Principal, req domain.GasRequest, sink domain.EventSink) (domain.GasQuotesResult, error) {
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.GasQuotesResult{}, err
	}
	defer cc.Close()

	netName := s.networkName(req.Network)
	gp := s.gasParamsFor(netName, req.Legacy)

	out := domain.GasQuotesResult{Network: netName, Legacy: gp.legacy}

	if gp.legacy {
		base, gerr := cc.SuggestGasPrice(ctx)
		if gerr != nil {
			return domain.GasQuotesResult{}, mapRPCErr(gerr)
		}
		out.Slow = legacyQuote(base, domain.SpeedSlow).result()
		out.Normal = legacyQuote(base, domain.SpeedNormal).result()
		out.Fast = legacyQuote(base, domain.SpeedFast).result()
		emitEstimated(sink, "gas: legacy "+out.Normal.GasPrice+" wei (normal)")
		return out, nil
	}

	// ONE eth_feeHistory(blocks,[25,50,90]) call serves all three speeds (§5.4).
	fees, ferr := cc.SuggestFees(ctx, gp.feeHistoryBlocks)
	if ferr != nil {
		return domain.GasQuotesResult{}, mapRPCErr(ferr)
	}
	out.Slow = gasTierQuote(gp, fees, domain.SpeedSlow).result()
	out.Normal = gasTierQuote(gp, fees, domain.SpeedNormal).result()
	out.Fast = gasTierQuote(gp, fees, domain.SpeedFast).result()
	if fees.BaseFee != nil {
		out.BaseFee = fees.BaseFee.String()
	}
	emitEstimated(sink, "gas estimated (3 speeds, 1 feeHistory call)")
	return out, nil
}

// gasTierQuote builds one speed-row Quote for `daxie gas` from the SINGLE
// SuggestFees result (no limit — the gas view has no concrete tx, so GasLimit is
// 0 and WorstCaseGasWei nil). It selects the speed's priority-fee tier, applies
// the min-priority-fee floor, and the max-fee formula — identical math to the send
// path's build1559Fees, just sourced from one shared Fees result.
func gasTierQuote(gp gasParams, fees chain.Fees, speed domain.Speed) Quote {
	estTip := fees.Priority(speedColumn(speed))
	if estTip == nil {
		estTip = big.NewInt(0)
	} else {
		estTip = new(big.Int).Set(estTip)
	}
	if gp.minPriorityFee != nil && estTip.Cmp(gp.minPriorityFee) < 0 {
		estTip = new(big.Int).Set(gp.minPriorityFee)
	}
	source := fees.Source
	if source == "" {
		source = "fee-history"
	}
	return Quote{
		Legacy:       false,
		MaxFeePerGas: maxFeeFormula(gp.baseFeeMultiplier, fees.BaseFee, estTip),
		PriorityFee:  estTip,
		BaseFee:      fees.BaseFee,
		Speed:        speed,
		Source:       source,
	}
}

// legacyQuote is the `gas` legacy-speed row (no limit).
func legacyQuote(base *big.Int, speed domain.Speed) Quote {
	return Quote{Legacy: true, GasPrice: mulSpeed(base, speed), Speed: speed, Source: "legacy"}
}

// ── pure helpers (no clock, no I/O — determinism-safe) ───────────────────────

// maxFeeFormula = baseFeeMultiplier × nextBaseFee + tip (§5.4). The multiplier
// is operator config (float64); it is applied as an exact rational scale of the
// big.Int base fee, never a float multiply of wei. Default 2.0 → 2×base + tip,
// which survives ~6 full blocks of 12.5% base-fee growth; the surplus is never
// paid.
func maxFeeFormula(multiplier float64, baseFee, tip *big.Int) *big.Int {
	if baseFee == nil {
		baseFee = big.NewInt(0)
	}
	scaled := scaleBig(baseFee, multiplier)
	return new(big.Int).Add(scaled, tip)
}

// mulSpeed scales a legacy gas price by the §5.4 speed multiplier (slow ×1.0,
// normal ×1.2, fast ×1.5), as exact big.Int rational math (×N/10).
func mulSpeed(price *big.Int, speed domain.Speed) *big.Int {
	if price == nil {
		return big.NewInt(0)
	}
	var num int64
	switch speed {
	case domain.SpeedSlow:
		num = 10 // ×1.0
	case domain.SpeedFast:
		num = 15 // ×1.5
	default:
		num = 12 // ×1.2 (normal)
	}
	out := new(big.Int).Mul(price, big.NewInt(num))
	return out.Quo(out, big.NewInt(10))
}

// scaleBig multiplies a big.Int by a float64 config multiplier EXACTLY by
// converting the multiplier to a rational (no float arithmetic on the wei
// value). It rounds half-up on the final division so a 2.0× of an integer base
// fee is exact and a 1.2× rounds deterministically.
func scaleBig(v *big.Int, multiplier float64) *big.Int {
	if v == nil {
		return big.NewInt(0)
	}
	num, den := floatToRatio(multiplier)
	out := new(big.Int).Mul(v, num)
	// round half-up: (out + den/2) / den
	out.Add(out, new(big.Int).Quo(den, big.NewInt(2)))
	return out.Quo(out, den)
}

// mulCeilUint multiplies a gas limit by a float64 config multiplier and rounds
// UP (the §5.4 "rounded up" rule for the limit headroom). Exact via the
// rational; no float multiply of the integer.
func mulCeilUint(n uint64, multiplier float64) uint64 {
	num, den := floatToRatio(multiplier)
	v := new(big.Int).Mul(new(big.Int).SetUint64(n), num)
	// ceil(v/den) = (v + den - 1) / den
	v.Add(v, new(big.Int).Sub(den, big.NewInt(1)))
	v.Quo(v, den)
	return v.Uint64()
}

// floatToRatio converts a non-negative float64 config multiplier into an exact
// num/den big.Int ratio using a fixed 1e6 denominator (six decimal places of
// precision, ample for the §5.4 multipliers like 1.2/2.0/1.125). A non-positive
// or absurd multiplier falls back to 1/1 so a misconfigured key never zeros the
// gas.
func floatToRatio(m float64) (num, den *big.Int) {
	const scale = 1_000_000
	if m <= 0 {
		return big.NewInt(1), big.NewInt(1)
	}
	n := int64(m*scale + 0.5) // round to the 1e-6 grid (config float, not wei)
	if n <= 0 {
		return big.NewInt(1), big.NewInt(1)
	}
	return big.NewInt(n), big.NewInt(scale)
}

// worstCaseGas = limit × perGasPrice (the value policy reserves, §5.1/§5.4).
func worstCaseGas(limit uint64, perGas *big.Int) *big.Int {
	if perGas == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Mul(new(big.Int).SetUint64(limit), perGas)
}

// parseSpeed maps a --speed string to domain.Speed, falling back to def for ""
// or an unknown value (the gas engine never errors on speed — config default
// governs; an explicit bad value is harmless, it just selects normal).
func parseSpeed(s string, def domain.Speed) domain.Speed {
	switch s {
	case string(domain.SpeedSlow):
		return domain.SpeedSlow
	case string(domain.SpeedNormal):
		return domain.SpeedNormal
	case string(domain.SpeedFast):
		return domain.SpeedFast
	default:
		return def
	}
}

// parseFeeFloor resolves a config fee-floor string ("0.01gwei") to wei. A bad or
// empty value yields nil (no floor) rather than an error — config validation is
// config's job; the engine degrades to "no floor".
func parseFeeFloor(s string) *big.Int {
	if s == "" {
		return nil
	}
	v, err := parseFee(s, "min-priority-fee")
	if err != nil {
		return nil
	}
	return v
}

// parseOptionalFee parses a "30gwei"-style override, returning nil for an empty
// string (no override). A malformed value is a usage error.
func parseOptionalFee(s, label string) (*big.Int, error) {
	if s == "" {
		return nil, nil
	}
	return parseFee(s, label)
}

// parseFee parses a fee string with an optional unit suffix ("30gwei", "1.5gwei",
// "1000000000" = wei when bare) into exact wei. A bare number is interpreted as
// WEI (the canonical base unit) — fee flags conventionally carry a unit, but a
// bare integer is unambiguous wei.
func parseFee(s, label string) (*big.Int, error) {
	value, unit := ethunit.SplitAmountUnit(s)
	if value == "" {
		return nil, domain.Newf(domain.CodeUsage+".bad_fee", "invalid %s %q", label, s)
	}
	u := ethunit.Wei
	if unit != "" {
		parsed, err := ethunit.ParseUnit(unit)
		if err != nil {
			return nil, domain.Newf(domain.CodeUsage+".bad_fee",
				"invalid %s unit in %q (want eth|gwei|wei)", label, s)
		}
		u = parsed
	}
	wei, err := ethunit.ParseAmount(value, u)
	if err != nil {
		return nil, domain.Wrap(domain.CodeUsage+".bad_fee",
			"invalid "+label+" "+s, err)
	}
	return wei, nil
}

// parseUint parses a base-10 unsigned integer without strconv-importing churn
// (matches account.go's tiny-itoa convention on the parse side).
func parseUint(s string) (uint64, error) {
	if s == "" {
		return 0, errBadUint
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, errBadUint
		}
		n = n*10 + uint64(c-'0')
	}
	return n, nil
}

var errBadUint = domain.New(domain.CodeUsage+".bad_integer", "not a non-negative integer")

// mapEstimateErr maps an eth_estimateGas failure to the §5.4 codes: a revert
// surfaces tx.reverted (exit 7), insufficient funds funds.insufficient (exit 5),
// else the transport mapping.
func mapEstimateErr(err error) error {
	de := domain.AsError(err)
	if de.Code == domain.CodeRPCUnreachable || de.Code == domain.CodeRPCChainIDMismatch {
		return err // already a typed chain error
	}
	msg := lowerErr(err)
	switch {
	case containsAny(msg, "execution reverted", "revert"):
		return domain.Wrap(domain.CodeTxReverted, "gas estimation reverted: "+err.Error(), err)
	case containsAny(msg, "insufficient funds"):
		return domain.Wrap(domain.CodeFundsInsufficient, "insufficient funds for gas estimation", err)
	default:
		return mapRPCErr(err)
	}
}

// mapRPCErr maps a transport/RPC failure to rpc.unreachable (exit 6, retryable).
// An already-typed domain error (the chain adapter raises rpc.unreachable /
// rpc.chain_id_mismatch, and our own callers may pass a typed error) is returned
// unchanged; only a raw/untyped error (which AsError synthesizes as "internal") is
// re-cast as a transport failure.
func mapRPCErr(err error) error {
	if err == nil {
		return nil
	}
	if de := domain.AsError(err); de.Code != domain.CodeInternal {
		return err // already typed — pass through
	}
	return domain.Wrap(domain.CodeRPCUnreachable, err.Error(), err)
}

// emitEstimated fires an EvEstimated progress event (gas/fees estimated, §5.9),
// to stderr. Nil sink = no-op.
func emitEstimated(sink domain.EventSink, detail string) {
	domain.Emit(sink, domain.Event{Kind: domain.EvEstimated, Detail: detail, Stream: "stderr"})
}

// addrPtr returns &a (the CallMsg.To wants a *common.Address).
func addrPtr(a common.Address) *common.Address { return &a }
