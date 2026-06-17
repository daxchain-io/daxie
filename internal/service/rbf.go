package service

import (
	"context"
	"errors"
	"math/big"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/ethereum/go-ethereum/common"
)

// rbf.go is the M3 replace-by-fee surface (§5.5): Speedup rebuilds the identical
// pending tx with bumped fees; Cancel replaces it with a 0-value self-send. Both
// are ordinary pipeline sends with a PINNED nonce and a Replaces cross-link,
// reusing the §2.7 authorize/settle/abort kernel (runSend) wholesale.
//
// Bump rule (§5.5):
//
//	newTip    = max(quote(fast).PriorityFee, ceil(oldTip    × 1.125))
//	newMaxFee = max(quote(fast).MaxFee,      ceil(oldMaxFee × 1.125))
//
// 12.5% clears geth's 10% pricebump with margin; re-quoting at `fast` handles a
// moved market. Explicit --max-fee/--priority-fee override the quote but are
// validated against the +12.5% floor → tx.replacement_underpriced (exit 9) if
// below. The corner case "the mandatory bump exceeds policy.max-gas-price" is the
// policy verdict's (gas_cap_below_bump_floor, exit 3) — wired via the Check.

// Speedup rebuilds the identical pending tx with bumped fees (§5.5). It requires
// a Daxie-originated journal record (foreign hash → ref.not_found) that has not
// yet mined (already mined → tx.already_mined). Value is NOT re-counted (only the
// positive gas delta — enforced by policy in M4); the cross-link is set on a
// successful broadcast.
func (s *Service) Speedup(ctx context.Context, p domain.Principal, req domain.SpeedupRequest, sink domain.EventSink) (domain.TxResult, error) {
	greq := rbfGasReq{maxFee: req.MaxFee, priorityFee: req.PriorityFee, gasPrice: req.GasPrice, speed: req.Speed}
	return s.replace(ctx, p, replaceArgs{
		hash:    req.Hash,
		kind:    journal.KindSpeedup,
		network: req.Network,
		rpc:     req.RPC,
		gas:     greq,
		wait:    req.Wait,
	}, sink)
}

// Cancel replaces a pending tx with a 0-value self-send (to=from, gas 21000) at
// bumped fees, journal kind "cancel" (§5.5). The allowlist is satisfied trivially
// (self); policy counts only the gas delta (recorded-never-denied at formula fees,
// enforced on overrides above formula — the M4 body; the stub allows).
func (s *Service) Cancel(ctx context.Context, p domain.Principal, req domain.CancelRequest, sink domain.EventSink) (domain.TxResult, error) {
	greq := rbfGasReq{maxFee: req.MaxFee, priorityFee: req.PriorityFee, gasPrice: req.GasPrice, speed: req.Speed}
	return s.replace(ctx, p, replaceArgs{
		hash:     req.Hash,
		kind:     journal.KindCancel,
		network:  req.Network,
		rpc:      req.RPC,
		gas:      greq,
		wait:     req.Wait,
		isCancel: true,
	}, sink)
}

// rbfGasReq is the gas-override subset of an RBF request.
type rbfGasReq struct {
	maxFee      string
	priorityFee string
	gasPrice    string
	speed       string
}

// replaceArgs is the shared input for Speedup/Cancel.
type replaceArgs struct {
	hash     string
	kind     journal.Kind
	network  string
	rpc      string
	gas      rbfGasReq
	wait     domain.WaitOpts
	isCancel bool
}

// replace is the shared RBF body: reconstruct the intent from the original
// journal record, compute the bumped fees, build a pinned-nonce Intent linked to
// the original, and run it through the kernel. On a successful broadcast the
// original record is cross-linked (replaced_by → the new hash); whichever mines
// flips the other to replaced (the §5.3 machine).
func (s *Service) replace(ctx context.Context, p domain.Principal, args replaceArgs, sink domain.EventSink) (domain.TxResult, error) {
	hash, err := parseHash(args.hash)
	if err != nil {
		return domain.TxResult{}, err
	}

	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: args.network, RPC: args.rpc})
	if err != nil {
		return domain.TxResult{}, err
	}
	defer cc.Close()

	chainID, err := cc.ChainID(ctx)
	if err != nil {
		return domain.TxResult{}, mapRPCErr(err)
	}

	// ── require a Daxie-originated record (foreign hash → ref.not_found) ──
	orig, jerr := s.journal.ByHash(ctx, chainID.Uint64(), hash)
	if jerr != nil {
		if errors.Is(jerr, journal.ErrNotFound) {
			return domain.TxResult{}, domain.Newf(domain.CodeRefNotFound,
				"no Daxie-originated transaction %s found in the journal (speedup/cancel only work on txs daxie sent)", args.hash)
		}
		return domain.TxResult{}, jerr
	}

	// ── precondition: not already mined (receipt present → tx.already_mined) ──
	if rcpt, rerr := cc.Receipt(ctx, hash); rerr == nil && rcpt != nil {
		return domain.TxResult{}, domain.New(domain.CodeTxAlreadyMined,
			"transaction already mined; nothing to replace")
	} else if rerr != nil && !errors.Is(rerr, chain.ErrTxNotFound) {
		return domain.TxResult{}, mapRPCErr(rerr)
	}
	// Terminal records cannot be replaced.
	if orig.Status.IsTerminal() {
		return domain.TxResult{}, domain.Newf(domain.CodeTxAlreadyMined,
			"transaction is %s; nothing to replace", orig.Status)
	}

	// ── build the replacement Intent from the original record ──
	in, err := s.replacementIntent(ctx, cc, chainID, orig, args, p)
	if err != nil {
		return domain.TxResult{}, err
	}
	// Resolve the signing passphrase (held for the minimum window; zeroed on
	// defer). A dry-run RBF is not a thing — a replacement always signs.
	unlocker, zero, uerr := s.withUnlocker(false)
	if uerr != nil {
		return domain.TxResult{}, uerr
	}
	defer zero()
	in.unlocker = unlocker

	emitResolved(sink, in.to.Hex(), "replacing "+args.hash+" (nonce "+utoa64(*in.nonce)+")")
	emitEstimated(sink, "rbf bumped: "+feeDetail(in.gas))

	// ── run the replacement through the kernel (pinned nonce + replaces link) ──
	res, rerr := s.runReplaceSend(ctx, p, &in, orig, args.wait, sink)
	if rerr != nil {
		return res, rerr
	}
	res.Replaced = args.hash
	return res, nil
}

// runReplaceSend wraps runSend so that on a successful broadcast it cross-links
// the original record (replaced_by → the new hash). The new record already
// carries replaces=orig.hash (set on the Intent). The original is NOT marked
// `replaced` yet — that happens when one of the pair actually mines (§5.3); here
// we only record the link so `tx list` shows the relationship.
func (s *Service) runReplaceSend(ctx context.Context, p domain.Principal, in *Intent, orig *journal.Record, wait domain.WaitOpts, sink domain.EventSink) (domain.TxResult, error) {
	res, err := s.runSend(ctx, p, in, domain.WaitOpts{}, sink) // do the send WITHOUT the wait first
	if err != nil {
		return res, err
	}
	// Cross-link the original record to the new hash.
	newHash := res.Hash
	_ = s.journal.SetState(ctx, orig.ChainID, orig.ID, journal.StateMutation{
		Status:     orig.Status, // unchanged (still pending) — only the link is added
		ReplacedBy: &newHash,
	})
	// Now run the optional wait on the NEW hash (§5.5 accepts --wait with §5.3
	// semantics).
	if wait.Enabled {
		nh := common.HexToHash(newHash)
		return s.waitOnHash(ctx, p, in.cc, in.network, nh, res.JournalID, in.chainID, wait, sink)
	}
	return res, nil
}

// replacementIntent reconstructs the send Intent from the original record + the
// RBF gas overrides. It pins the original nonce, links replaces, and applies the
// §5.5 bump rule to the fees (re-quoting at `fast` and bumping the old fees by
// 12.5%, taking the max). Cancel overrides To=from, value=0, gas=21000.
func (s *Service) replacementIntent(ctx context.Context, cc chain.Client, chainID *big.Int, orig *journal.Record, args replaceArgs, p domain.Principal) (Intent, error) {
	from := common.HexToAddress(orig.From)
	to := common.HexToAddress(orig.To)
	value := bigOrZero(orig.ValueWei)

	// Resolve the signing ref from the original `from` address. A replacement signs
	// from the same account; we look up its keystore ref so Signer.SignTx can sign.
	ref, err := s.refForAddress(from)
	if err != nil {
		return Intent{}, err
	}

	source := "cli"
	if p.Label == "mcp" {
		source = "mcp"
	}

	nonce := orig.Nonce
	replaces := orig.TxHash
	kind := args.kind

	in := Intent{
		chainID:  chainID,
		network:  s.networkName(args.network),
		rpc:      args.rpc,
		cc:       cc,
		from:     from,
		ref:      ref,
		dest:     domain.Dest{Address: to},
		to:       to,
		value:    value,
		data:     nil,
		kind:     kind,
		asset:    journal.Asset{Kind: "eth", Amount: strPtr(value.String())},
		nonce:    &nonce,
		replaces: &replaces,
		source:   source,
	}

	if args.isCancel {
		// 0-value self-send at 21000 gas (§5.5).
		in.to = from
		in.dest = domain.Dest{Address: from}
		in.value = big.NewInt(0)
		in.asset = journal.Asset{Kind: "eth", Amount: strPtr("0")}
	}

	// ── bumped fees ──
	q, err := s.bumpedQuote(ctx, cc, orig, args, in.network, in.to, in.value, in.data)
	if err != nil {
		return Intent{}, err
	}
	in.gas = q
	return in, nil
}

// bumpedQuote applies the §5.5 bump rule: re-quote at `fast` (or the requested
// speed), bump the original fees by +12.5%, take the per-field max, and validate
// explicit overrides against the floor. The gas limit is rebuilt (21000 for
// cancel; the original's limit for speedup unless overridden).
func (s *Service) bumpedQuote(ctx context.Context, cc chain.Client, orig *journal.Record, args replaceArgs, network string, to common.Address, value *big.Int, data []byte) (Quote, error) {
	gp := s.gasParamsFor(network, orig.Fees.Type == "legacy")

	// gas limit: cancel is exactly 21000; speedup reuses the original's limit.
	limit := orig.Fees.GasLimit
	if args.isCancel {
		limit = intrinsicEOAGas
	}

	if gp.legacy {
		return s.bumpedLegacy(ctx, cc, orig, args, gp, limit)
	}

	// Re-quote at the requested speed (default fast for RBF — a moved market).
	// ONE feeHistory call; pick the speed's tier (§5.4).
	speed := parseSpeed(args.gas.speed, domain.SpeedFast)
	fees, ferr := cc.SuggestFees(ctx, gp.feeHistoryBlocks)
	if ferr != nil {
		return Quote{}, mapRPCErr(ferr)
	}
	qTip := fees.Priority(speedColumn(speed))
	if qTip == nil {
		qTip = big.NewInt(0)
	} else {
		qTip = new(big.Int).Set(qTip)
	}
	if gp.minPriorityFee != nil && qTip.Cmp(gp.minPriorityFee) < 0 {
		qTip = new(big.Int).Set(gp.minPriorityFee)
	}
	baseFee := fees.BaseFee
	quoteMaxFee := maxFeeFormula(gp.baseFeeMultiplier, baseFee, qTip)

	// the +12.5% floor over the ORIGINAL fees.
	oldTip := feeOrZero(orig.Fees.MaxPriorityPerGas)
	oldMaxFee := feeOrZero(orig.Fees.MaxFeePerGas)
	floorTip := bumpPercent(oldTip, gp.rbfBumpPercent)
	floorMaxFee := bumpPercent(oldMaxFee, gp.rbfBumpPercent)

	newTip := maxBig(qTip, floorTip)
	newMaxFee := maxBig(quoteMaxFee, floorMaxFee)

	// Explicit overrides: validated against the +12.5% floor (§5.5 → exit 9).
	if args.gas.priorityFee != "" {
		ov, perr := parseFee(args.gas.priorityFee, "--priority-fee")
		if perr != nil {
			return Quote{}, perr
		}
		if ov.Cmp(floorTip) < 0 {
			return Quote{}, domain.WithData(
				domain.New(domain.CodeTxReplacementUnderpriced,
					"--priority-fee is below the +12.5% replacement floor"),
				map[string]any{"floor_priority_fee": floorTip.String()})
		}
		newTip = ov
	}
	if args.gas.maxFee != "" {
		ov, perr := parseFee(args.gas.maxFee, "--max-fee")
		if perr != nil {
			return Quote{}, perr
		}
		if ov.Cmp(floorMaxFee) < 0 {
			return Quote{}, domain.WithData(
				domain.New(domain.CodeTxReplacementUnderpriced,
					"--max-fee is below the +12.5% replacement floor"),
				map[string]any{"floor_max_fee": floorMaxFee.String()})
		}
		newMaxFee = ov
	}
	if newTip.Cmp(newMaxFee) > 0 {
		newTip = new(big.Int).Set(newMaxFee)
	}

	q := Quote{
		Legacy:          false,
		GasLimit:        limit,
		MaxFeePerGas:    newMaxFee,
		PriorityFee:     newTip,
		BaseFee:         baseFee,
		Speed:           speed,
		Source:          "fee-history",
		WorstCaseGasWei: worstCaseGas(limit, newMaxFee),
	}
	return q, nil
}

// bumpedLegacy applies the bump rule to a legacy gas price: max(quote(fast)×mult,
// ceil(oldPrice × 1.125)).
func (s *Service) bumpedLegacy(ctx context.Context, cc chain.Client, orig *journal.Record, args replaceArgs, gp gasParams, limit uint64) (Quote, error) {
	speed := parseSpeed(args.gas.speed, domain.SpeedFast)
	base, gerr := cc.SuggestGasPrice(ctx)
	if gerr != nil {
		return Quote{}, mapRPCErr(gerr)
	}
	quote := mulSpeed(base, speed)
	oldPrice := feeOrZero(orig.Fees.GasPrice)
	floor := bumpPercent(oldPrice, gp.rbfBumpPercent)
	price := maxBig(quote, floor)

	if args.gas.gasPrice != "" {
		ov, perr := parseFee(args.gas.gasPrice, "--gas-price")
		if perr != nil {
			return Quote{}, perr
		}
		if ov.Cmp(floor) < 0 {
			return Quote{}, domain.WithData(
				domain.New(domain.CodeTxReplacementUnderpriced,
					"--gas-price is below the +12.5% replacement floor"),
				map[string]any{"floor_gas_price": floor.String()})
		}
		price = ov
	}

	return Quote{
		Legacy:          true,
		GasLimit:        limit,
		GasPrice:        price,
		Speed:           speed,
		Source:          "legacy",
		WorstCaseGasWei: worstCaseGas(limit, price),
	}, nil
}

// refForAddress resolves a keystore signing ref for an address. RBF signs from the
// SAME account that sent the original tx; we need its ref so Signer.SignTx can
// unlock it. The keystore is scanned for an account holding addr (the normal case
// — the original send used a keystore account). A non-keystore signer (a future
// KMS/daemon backend, or a test signer) ignores the ref entirely; for those the
// raw-address ref is a harmless carrier — the keystore signer would reject it,
// but the keystore-match branch above always wins for the keystore signer, so this
// fallback is only reached by a backend that does not consult the ref.
func (s *Service) refForAddress(addr common.Address) (domain.AccountRef, error) {
	infos, err := s.keys.ListAccounts(context.Background(), "")
	if err == nil {
		for _, a := range infos {
			if a.Address == addr {
				if ref, perr := domain.ParseAccountRef(a.Ref); perr == nil {
					return ref, nil
				}
			}
		}
	}
	// Not in the keystore: carry the raw address. A keystore signer will reject it
	// (read-only), surfacing ref.not_found at sign time; a ref-ignoring signer
	// (KMS/daemon/test) signs regardless.
	return domain.AccountRef{Raw: addr.Hex(), Kind: domain.RefAddress, Addr: addr}, nil
}

// ── pure bump helpers ────────────────────────────────────────────────────────

// bumpPercent = ceil(v × (1 + pct/100)). pct is operator config (12.5 default);
// the math is exact via the rational, rounding UP so the floor always clears
// geth's pricebump.
func bumpPercent(v *big.Int, pct float64) *big.Int {
	if v == nil || v.Sign() == 0 {
		return big.NewInt(0)
	}
	// multiplier = 1 + pct/100.
	mult := 1.0 + pct/100.0
	num, den := floatToRatio(mult)
	out := new(big.Int).Mul(v, num)
	// ceil
	out.Add(out, new(big.Int).Sub(den, big.NewInt(1)))
	return out.Quo(out, den)
}

// maxBig returns the larger of a and b (treating nil as 0).
func maxBig(a, b *big.Int) *big.Int {
	if a == nil {
		a = big.NewInt(0)
	}
	if b == nil {
		b = big.NewInt(0)
	}
	if a.Cmp(b) >= 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}

// feeOrZero parses a *string decimal fee (a journal Fees field) into a *big.Int.
func feeOrZero(s *string) *big.Int {
	if s == nil {
		return big.NewInt(0)
	}
	return bigOrZero(*s)
}
