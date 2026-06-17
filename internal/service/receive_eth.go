package service

import (
	"context"
	"math/big"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// receive_eth.go holds the §5.8 ETH-arrival math, kept separate from the
// detection loop in receive.go so the balance-delta correctness — the
// review-hunted part — is reviewable and unit-testable in isolation. There are no
// logs for a plain ETH value transfer, so ETH detection is two halves:
//
//	(1) block scan (PRIMARY, ATTRIBUTABLE, attribution:"tx"): every tx in the
//	    block with to==addr && value>0 is a bound inbound transfer.
//	(2) balance delta (SAFETY NET, UNATTRIBUTABLE, attribution:"balance-delta"):
//	    the residue Δ−directIn+ownOut+ownFees catches internal CALL transfers
//	    invisible to block-scan (the common exchange-withdrawal funding path).
//
// CORRECTNESS NON-NEGOTIABLE (§5.8, review will hunt): ownFees uses the ACTUAL
// receipt.GasUsed×EffectiveGasPrice (receipts fetched), NEVER the journal's
// worst-case gas. Worst-case > actual would inflate ownFees, inflating
// `unattributed` positive into a PHANTOM inbound balance-delta detection.

// ethScan is the per-block ETH block-scan result (half 1). directIn is the
// attributed inbound for the block (Σ of inbound tx values); inbound carries the
// individual attributable detections (one per inbound tx). ownOut/ownFees are the
// own-outbound terms accumulated across the scanned window for the balance-delta
// math (half 2).
type ethScan struct {
	directIn *big.Int      // Σ value of inbound txs (attribution:"tx")
	inbound  []ethInbound  // the attributable inbound detections in this block
	ownOut   *big.Int      // Σ value of OUR OWN outbound txs (from==addr)
	ownTxs   []common.Hash // OUR own outbound tx hashes (receipts fetched for actual fees)
	block    *types.Block  // the scanned block (for its hash)
}

// ethInbound is one attributable ETH inbound transfer from the block scan.
type ethInbound struct {
	txHash common.Hash
	from   common.Address
	value  *big.Int
}

// scanETHBlock performs half (1): block scan. It reads the full block (fullTx=true)
// and classifies every transaction relative to addr:
//
//   - to == addr && value > 0 ⇒ an ATTRIBUTABLE inbound (attribution:"tx").
//   - from == addr            ⇒ OUR OWN outbound (its value + ACTUAL fee subtract
//     from the balance delta in half 2). The sender is recovered with the
//     chain-id signer (types.Sender).
//
// A nil block (a not-yet-available height) returns a zero scan with a nil block.
func (s *Service) scanETHBlock(ctx context.Context, cc chain.Client, addr common.Address, n uint64, chainID *big.Int) (ethScan, error) {
	blk, err := cc.BlockByNumber(ctx, new(big.Int).SetUint64(n), true)
	if err != nil {
		return ethScan{}, mapRPCErr(err)
	}
	out := ethScan{directIn: big.NewInt(0), ownOut: big.NewInt(0), block: blk}
	if blk == nil {
		return out, nil
	}
	signer := types.LatestSignerForChainID(chainID)
	for _, tx := range blk.Transactions() {
		// Inbound: a value transfer whose recipient is the listening address.
		if to := tx.To(); to != nil && *to == addr && tx.Value().Sign() > 0 {
			out.inbound = append(out.inbound, ethInbound{
				txHash: tx.Hash(),
				from:   senderOrZero(signer, tx),
				value:  new(big.Int).Set(tx.Value()),
			})
			out.directIn.Add(out.directIn, tx.Value())
		}
		// Own outbound: a tx WE sent. Its value left the account, and its ACTUAL
		// fee (receipt) left too — both must be added back so the balance delta is
		// not mistaken for an inbound (the own-outbound-fee correction).
		if from := senderOrZero(signer, tx); from == addr {
			out.ownOut.Add(out.ownOut, tx.Value())
			out.ownTxs = append(out.ownTxs, tx.Hash())
		}
	}
	return out, nil
}

// senderOrZero recovers a tx sender with the given signer, returning the zero
// address on a recovery failure (a malformed signature). It never panics — a
// hostile/garbled tx in a block must not sink the scan; an unrecoverable sender
// simply cannot match addr (so it is neither inbound-attributed nor own-outbound).
func senderOrZero(signer types.Signer, tx *types.Transaction) common.Address {
	a, err := types.Sender(signer, tx)
	if err != nil {
		return common.Address{}
	}
	return a
}

// ownFeesActual sums the ACTUAL fee paid by our own outbound txs:
// Σ receipt.GasUsed × receipt.EffectiveGasPrice (the §5.8 non-negotiable). For a
// legacy/pre-1559 receipt missing EffectiveGasPrice it falls back to the tx's
// GasPrice (fetched from the block). A receipt that cannot be read (transport
// failure) propagates as rpc.unreachable so the balance-delta math is never
// computed against a partial fee total (which would under-correct and create a
// phantom inbound).
//
// It NEVER uses the journal's worst-case gas — that is the whole point: worst-case
// > actual would inflate ownFees → inflate `unattributed` positive → a phantom
// balance-delta detection. The fee is the realized cost only.
func (s *Service) ownFeesActual(ctx context.Context, cc chain.Client, blk *types.Block, ownTxs []common.Hash) (*big.Int, error) {
	total := big.NewInt(0)
	for _, h := range ownTxs {
		rcpt, err := cc.Receipt(ctx, h)
		if err != nil {
			return nil, mapRPCErr(err)
		}
		gasUsed := new(big.Int).SetUint64(rcpt.GasUsed)
		price := rcpt.EffectiveGasPrice
		if price == nil || price.Sign() == 0 {
			// Legacy / missing effectiveGasPrice: fall back to the tx's own gas
			// price from the block (§5.8). A tx not in this block (a cross-block own
			// tx — should not happen here, ownTxs come from blk) contributes nothing.
			if blk != nil {
				if tx := blk.Transaction(h); tx != nil {
					price = tx.GasPrice()
				}
			}
		}
		if price != nil {
			total.Add(total, new(big.Int).Mul(gasUsed, price))
		}
	}
	return total, nil
}

// balanceDelta computes half (2): the unattributed ETH residue against the
// CARRY-FORWARD baseline (§5.8). The baseline is a running value captured ONCE at
// listen start and advanced at the head every poll — it is NEVER re-queried at a
// fixed historical block (pruning public RPCs return "missing trie node" past
// ~128 blocks, and an invoice wait is unbounded by default). The math, per the
// poll window of scanned blocks:
//
//		Δ            = balance(addr, head_now) − baseline      // since the last poll
//		directIn     = Σ over scanned blocks of attributed inbound (half 1)
//		ownOut       = Σ over scanned blocks of our own outbound value
//		ownFees      = Σ over scanned blocks of ACTUAL gasUsed×effectiveGasPrice
//		unattributed = Δ − directIn + ownOut + ownFees
//
//	  - unattributed > 0 ⇒ a balance-delta detection of that value (catches internal
//	    CALL transfers). The new baseline is balance(addr, head_now) (carry forward).
//	  - unattributed < 0 ⇒ CLAMP to zero and WARN (ETH left via a path the scan can't
//	    see); do NOT create a phantom negative detection. The baseline still advances.
//
// It returns the unattributed amount (clamped ≥ 0), a clamped flag (the warn
// signal), and the new baseline (= headBalance, always carried forward).
func balanceDelta(baseline, headBalance, directIn, ownOut, ownFees *big.Int) (unattributed *big.Int, clamped bool, newBaseline *big.Int) {
	delta := new(big.Int).Sub(headBalance, baseline)
	// unattributed = Δ − directIn + ownOut + ownFees
	u := new(big.Int).Set(delta)
	u.Sub(u, directIn)
	u.Add(u, ownOut)
	u.Add(u, ownFees)

	// Always carry the baseline forward to the head balance (statelessness rule):
	// the next poll measures Δ from here, never re-querying a fixed block.
	newBaseline = new(big.Int).Set(headBalance)

	if u.Sign() < 0 {
		// Negative residue: ETH left through a path the scan can't see. Clamp and
		// warn; never emit a phantom negative inbound.
		return big.NewInt(0), true, newBaseline
	}
	return u, false, newBaseline
}

// scanRangeETH detects ETH inbound over [from,to] (§5.8): half (1) block-scan
// per block (attributable tx detections) accumulated with half (2) the
// balance-delta safety net computed ONCE against the carry-forward baseline at the
// head. The own-outbound value + ACTUAL fees of every own tx in the window are
// summed so the unattributed residue is the real internal-transfer inflow, not a
// phantom from worst-case gas.
func (s *Service) scanRangeETH(ctx context.Context, cc chain.Client, sink domain.EventSink, st *receiveState, from, to uint64) error {
	chainID := new(big.Int).SetUint64(st.chainID)

	directIn := big.NewInt(0)
	ownOut := big.NewInt(0)
	ownFees := big.NewInt(0)

	for n := from; n <= to; n++ {
		scan, err := s.scanETHBlock(ctx, cc, st.addr, n, chainID)
		if err != nil {
			return err
		}
		// half (1): attributable inbound txs become detections immediately.
		for _, in := range scan.inbound {
			s.recordDetection(sink, st, pending{
				txHash:      in.txHash,
				from:        in.from,
				value:       in.value,
				block:       n,
				blockHash:   blockHashOf(scan.block),
				attribution: domain.AttribTx,
			})
		}
		directIn.Add(directIn, scan.directIn)
		ownOut.Add(ownOut, scan.ownOut)
		// half (2) term: ACTUAL own-outbound fees (receipts), NEVER worst-case gas.
		if len(scan.ownTxs) > 0 {
			fees, ferr := s.ownFeesActual(ctx, cc, scan.block, scan.ownTxs)
			if ferr != nil {
				return ferr
			}
			ownFees.Add(ownFees, fees)
		}
		if n == to {
			break // guard uint64 overflow at the max boundary
		}
	}

	// half (2): the balance delta against the carry-forward baseline, computed once
	// per scan window at the EXACT block just scanned (`to`), NOT at "latest" (nil).
	//
	// TOCTOU fix (§5.8): `to` is the head captured at the TOP of this poll, and the
	// directIn/ownOut/ownFees terms above are summed over [from,to] only. If we read
	// "latest" here and the chain advanced to to+1 between the BlockNumber() call and
	// this Balance call, Δ would include an inbound mined in to+1 that is NOT in
	// directIn — firing a PHANTOM balance-delta detection that (a) never reorgs out
	// (balance-delta reverify is always true) and (b) is then re-detected next poll as
	// an attribution:"tx" detection, double-counting toward the cumulative target.
	// Reading at `to` aligns the balance read with the [from,to] scan window exactly.
	//
	// This still honors the carry-forward invariant: `to` is a FRESH RECENT head each
	// poll (within ~128 blocks of the tip on the shipped pruning full nodes — unpruned
	// state), NEVER the fixed listen-start block whose state gets pruned out from under
	// an unbounded invoice wait.
	headBal, err := cc.Balance(ctx, st.addr, new(big.Int).SetUint64(to))
	if err != nil {
		return mapRPCErr(err)
	}
	unattributed, clamped, newBaseline := balanceDelta(st.ethBaseline, headBal, directIn, ownOut, ownFees)
	st.ethBaseline = newBaseline
	if clamped {
		emitBalanceDeltaWarn(sink, s.nowTS(), st.cumConfirmed.String(), st.remaining().String(), to)
		return nil
	}
	if unattributed.Sign() > 0 {
		// An unattributed positive residue: an internal CALL transfer invisible to
		// block-scan. Attribute it to the head block (the latest scanned) — it has no
		// single tx, so it is a balance-delta detection that confirms immediately
		// once the head advances past confTarget.
		s.recordDetection(sink, st, pending{
			value:       unattributed,
			block:       to,
			attribution: domain.AttribBalanceDelta,
		})
	}
	return nil
}

// blockHashOf returns a block's hash, or the zero hash for a nil block.
func blockHashOf(blk *types.Block) common.Hash {
	if blk == nil {
		return common.Hash{}
	}
	return blk.Hash()
}

// emitBalanceDeltaWarn fires a low-noise warning event when the unattributed
// residue clamped negative (§5.8): a heartbeat-shaped note carrying the cause, so
// an operator/agent sees that an outbound path was invisible to the scan without a
// terminal effect on the listen.
func emitBalanceDeltaWarn(emit domain.EventSink, ts string, cumConfirmed, remaining string, lastScanned uint64) {
	domain.Emit(emit, domain.Event{
		Kind:                domain.EvHeartbeat,
		V:                   1,
		Note:                "unattributed ETH outflow detected (balance delta clamped to zero)",
		CumulativeConfirmed: cumConfirmed,
		Remaining:           remaining,
		LastScanned:         lastScanned,
		TS:                  ts,
		Stream:              "stdout",
	})
}
