package service

// receive.go is the M8 `daxie receive` inbound-detection engine (design §5.8/§5.9):
// the use case BLOCKS until the listening address receives the expected asset and
// it reaches the confirmation target, streaming NDJSON events through the EventSink
// (Stream="stdout"). The detection core is transport-agnostic; v1 ships POLLING
// only (receive.poll-interval, default 4s) — the v1.1 WebSocket upgrade changes
// only the head source (chain.SubscribeNewHead returns ErrNotSupported on HTTP, the
// fallback signal).
//
// Determinism (§2.3): this file reads wall time ONLY through s.Now() and blocks
// ONLY through s.sleep(ctx,d) — never time.Now/After/Sleep directly (the guard
// bans them). No os/net/crypto-rand.
//
// The ETH block-scan + balance-delta math lives in receive_eth.go; the token/NFT
// log classification + the loop/confirmation/reorg/completion machinery lives here.

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ethunit"
	"github.com/daxchain-io/daxie/internal/registry"
	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// Topic-0 signatures the engine filters on (§5.8). Computed once from the
// canonical event signatures so they cannot drift; ERC-20 and ERC-721 share the
// Transfer signature (topic count disambiguates), ERC-1155 has its own.
var (
	transferTopic0       = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
	transferSingleTopic0 = crypto.Keccak256Hash([]byte("TransferSingle(address,address,address,uint256,uint256)"))
	transferBatchTopic0  = crypto.Keccak256Hash([]byte("TransferBatch(address,address,address,uint256[],uint256[])"))
)

// listenAsset is the resolved asset the listen is for. Native ETH has kind "eth"
// and a nil contract; a token/NFT carries its contract + kind + (NFT) tokenID.
type listenAsset struct {
	kind     string // "eth" | "erc20" | "erc721" | "erc1155"
	contract common.Address
	alias    string
	decimals uint8  // erc20 display
	tokenID  string // nft (decimal string); "" for collection-wide / eth
}

func (a listenAsset) isETH() bool { return a.kind == "eth" || a.kind == "" }

// pending is one DETECTED-but-not-yet-confirmed inbound transfer the loop tracks.
// The key (block, txHash, logIndex|attribution) dedups re-scans. evidence carries
// what re-verification needs at the confirmation point.
type pending struct {
	txHash      common.Hash
	logIndex    *int
	from        common.Address
	value       *big.Int
	tokenID     string
	block       uint64
	blockHash   common.Hash
	attribution string
}

// key uniquely identifies a detection for dedup across re-scans.
func (p pending) key() string {
	li := -1
	if p.logIndex != nil {
		li = *p.logIndex
	}
	return fmt.Sprintf("%d|%s|%d|%s", p.block, p.txHash.Hex(), li, p.attribution)
}

// Receive is the §5.8 inbound-detection use case. It resolves the listening
// address (an existing account, or a fresh --new index), dials the endpoint,
// resolves the asset, emits EvListening (the address-up-front guarantee) BEFORE
// blocking, then polls heads detecting + confirming inbound transfers until the
// completion mode is satisfied (EvComplete, exit 0) or the timeout fires
// (EvTimeout, exit 8, resumable). The terminal outcome is carried in BOTH the
// returned ReceiveResult and the final event. A timeout is NOT a Go error (the CLI
// exits via result.Exit); only true failures (bad ref, rpc.unreachable,
// keystore.read_only on --new) return a non-nil domain.Error.
func (s *Service) Receive(ctx context.Context, p domain.Principal, req domain.ReceiveRequest, sink domain.EventSink) (domain.ReceiveResult, error) {
	// ── 1. validate + resolve the completion mode (the usage rejections live here) ──
	mode, err := domain.ResolveReceiveMode(req)
	if err != nil {
		return domain.ReceiveResult{}, err
	}

	// ── 2. dial the endpoint (chain-id guard; rpc.unreachable ⇒ exit 6) ──
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.ReceiveResult{}, err
	}
	defer cc.Close()
	network := s.networkName(req.Network)

	chainIDbig, err := cc.ChainID(ctx)
	if err != nil {
		return domain.ReceiveResult{}, mapRPCErr(err)
	}
	chainID := chainIDbig.Uint64()

	// ── 3. resolve the LISTENING ADDRESS ──
	addr, accountRef, err := s.resolveListenAddress(ctx, cc, req)
	if err != nil {
		return domain.ReceiveResult{}, err
	}

	// ── 4. resolve the ASSET via the same M5/M6 chokepoints ──
	asset, err := s.resolveListenAsset(ctx, cc, network, req)
	if err != nil {
		return domain.ReceiveResult{}, err
	}

	// ── 5. resolve the completion target amount (base units) ──
	targetAmount, err := s.receiveTargetAmount(req, mode, asset)
	if err != nil {
		return domain.ReceiveResult{}, err
	}

	// ── 6. confirmation target (§5.2 resolution, REUSED) ──
	confTarget := s.confirmTarget(req.Network, req.Confirmations)

	// ── 7. starting block: resume (--from-block) else head − lookback (clamp ≥ 0) ──
	head, err := cc.BlockNumber(ctx)
	if err != nil {
		return domain.ReceiveResult{}, mapRPCErr(err)
	}
	var fromBlock uint64
	if req.FromBlock != nil {
		fromBlock = *req.FromBlock
	} else {
		lb := uint64(0)
		if s.cfg.Receive.LookbackBlocks > 0 {
			lb = uint64(s.cfg.Receive.LookbackBlocks)
		}
		if head > lb {
			fromBlock = head - lb
		} else {
			fromBlock = 0
		}
	}

	st := &receiveState{
		addr:         addr,
		accountRef:   accountRef,
		network:      network,
		chainID:      chainID,
		asset:        asset,
		mode:         mode,
		targetAmount: targetAmount,
		confTarget:   confTarget,
		cumDetected:  big.NewInt(0),
		cumConfirmed: big.NewInt(0),
		pending:      map[string]*pending{},
		confirmed:    map[string]*pending{},
	}
	// lastScanned is "the highest block already scanned"; the next loop scans
	// fromBlock..head, so seed it to fromBlock-1 (or 0 when fromBlock==0).
	if fromBlock > 0 {
		st.lastScanned = fromBlock - 1
	}

	// ── ETH carry-forward baseline: captured ONCE here at the head, advanced at the
	// head every poll — NEVER re-queried at a fixed historical block (§5.8). ──
	if asset.isETH() {
		bal, berr := cc.Balance(ctx, addr, nil) // nil = latest (the head)
		if berr != nil {
			return domain.ReceiveResult{}, mapRPCErr(berr)
		}
		st.ethBaseline = bal
	}

	// ── 8. EMIT EvListening (address up front) BEFORE blocking ──
	s.emitListening(sink, st, fromBlock)

	// ── 9. deadline: none unless a timeout was given (unbounded invoice wait) ──
	var deadline *time.Time
	if req.Timeout.D > 0 {
		d := s.Now().Add(req.Timeout.D)
		deadline = &d
	}
	st.lastActivity = s.Now().Unix()

	return s.receiveLoop(ctx, cc, sink, st, deadline)
}

// receiveState carries the running detection state across the poll loop.
type receiveState struct {
	addr         common.Address
	accountRef   string // the listening account ref for the resume string ("" for raw 0x)
	network      string
	chainID      uint64
	asset        listenAsset
	mode         domain.ReceiveMode
	targetAmount *big.Int // nil for ModeAny

	confTarget   uint64
	lastScanned  uint64
	cumDetected  *big.Int
	cumConfirmed *big.Int

	pending   map[string]*pending // detected, awaiting confirmations
	confirmed map[string]*pending // confirmed (re-verified); reorg can move them back out

	// ETH carry-forward baseline (asset.isETH only).
	ethBaseline *big.Int

	lastActivity int64 // unix seconds of the last emitted event (heartbeat gating)
}

// receiveLoop is the §5.8 detection loop: scan new blocks → detect → confirm/reorg
// → check completion → heartbeat → timeout. It blocks via s.sleep(ctx, pollInterval).
func (s *Service) receiveLoop(ctx context.Context, cc chain.Client, sink domain.EventSink, st *receiveState, deadline *time.Time) (domain.ReceiveResult, error) {
	poll := s.cfg.Receive.PollInterval
	for {
		head, err := cc.BlockNumber(ctx)
		if err != nil {
			return domain.ReceiveResult{}, mapRPCErr(err)
		}

		// ── scan every new block (lastScanned+1 .. head) ──
		if head > st.lastScanned {
			if derr := s.scanRange(ctx, cc, sink, st, st.lastScanned+1, head); derr != nil {
				return domain.ReceiveResult{}, derr
			}
			st.lastScanned = head
		}

		// ── confirmation / reorg re-verify over the pending + confirmed sets ──
		if cerr := s.advanceConfirmations(ctx, cc, sink, st, head); cerr != nil {
			return domain.ReceiveResult{}, cerr
		}

		// ── completion? ──
		if s.completed(st) {
			return s.completeResult(sink, st), nil
		}

		// ── heartbeat in quiet periods ──
		s.maybeHeartbeat(sink, st)

		// ── timeout? ──
		if deadline != nil && !s.Now().Before(*deadline) {
			return s.timeoutResult(sink, st), nil
		}

		// ── sleep one poll interval (ctx-aware, the determinism seam) ──
		if serr := s.sleep(ctx, poll); serr != nil {
			// ctx cancelled (SIGTERM during a listen): surface as a resumable timeout
			// rather than an error, mirroring `tx wait`'s SIGTERM behavior (§5.3).
			return s.timeoutResult(sink, st), nil
		}
	}
}

// scanRange scans blocks [from,to] for inbound detections of the listening asset,
// emitting EvDetected for each match and adding it to the pending set. Token/NFT
// use eth_getLogs (chunked by receive.max-log-range); ETH uses the block-scan +
// balance-delta safety net.
func (s *Service) scanRange(ctx context.Context, cc chain.Client, sink domain.EventSink, st *receiveState, from, to uint64) error {
	if st.asset.isETH() {
		return s.scanRangeETH(ctx, cc, sink, st, from, to)
	}
	return s.scanRangeLogs(ctx, cc, sink, st, from, to)
}

// scanRangeLogs detects token/NFT inbound via Transfer logs (§5.8). It chunks the
// [from,to] range by receive.max-log-range and filters on the asset contract +
// topic0 + recipient-indexed topic. Each matching log is classified
// (ERC-20/721/1155, topic-count disambiguation + registry kind cross-check) into
// an attribution:"log" detection.
func (s *Service) scanRangeLogs(ctx context.Context, cc chain.Client, sink domain.EventSink, st *receiveState, from, to uint64) error {
	span := s.cfg.Receive.MaxLogRange
	if span <= 0 {
		span = 1000
	}
	for lo := from; lo <= to; lo += uint64(span) {
		hi := lo + uint64(span) - 1
		if hi > to {
			hi = to
		}
		logs, err := cc.FilterLogs(ctx, s.transferQuery(st, lo, hi))
		if err != nil {
			return mapRPCErr(err)
		}
		for i := range logs {
			det, ok := s.classifyLog(st, logs[i])
			if !ok {
				continue
			}
			s.recordDetection(sink, st, det)
		}
		if hi == to {
			break // avoid uint64 overflow on lo += span when to is near max
		}
	}
	return nil
}

// transferQuery builds the eth_getLogs filter for the asset (§5.8): the contract,
// topic0 (Transfer for 20/721, TransferSingle/Batch for 1155 — we filter topic0 by
// kind), and the recipient-indexed topic positioned by standard (topic2 for
// 20/721, topic3 for 1155). For 1155 both TransferSingle and TransferBatch are
// matched via a topic0 OR-set.
func (s *Service) transferQuery(st *receiveState, from, to uint64) ethereum.FilterQuery {
	recipient := common.BytesToHash(st.addr.Bytes())
	q := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{st.asset.contract},
	}
	switch st.asset.kind {
	case registry.KindERC1155:
		// topic0 ∈ {TransferSingle, TransferBatch}; recipient (to) is topic3.
		q.Topics = [][]common.Hash{
			{transferSingleTopic0, transferBatchTopic0},
			nil, // operator (any)
			nil, // from (any)
			{recipient},
		}
	default:
		// ERC-20 / ERC-721 share the Transfer signature; recipient is topic2.
		q.Topics = [][]common.Hash{
			{transferTopic0},
			nil, // from (any)
			{recipient},
		}
	}
	return q
}

// classifyLog decodes one log into a detection for the listening asset, applying
// the topic-count disambiguation + the registry kind cross-check (§5.8):
//   - 3 topics + 32-byte data ⇒ ERC-20 (value in data). Skipped if the asset is
//     registered erc721.
//   - 4 topics ⇒ ERC-721 (tokenId in topic3, value 1). Skipped if registered erc20.
//   - TransferSingle/Batch topic0 ⇒ ERC-1155 (id+qty in data).
//
// A malformed/removed log, or one whose tokenId does not match a single-NFT
// target, is skipped (ok=false) — tolerant, like erc.ParseTransfers.
func (s *Service) classifyLog(st *receiveState, l types.Log) (pending, bool) {
	if l.Removed {
		return pending{}, false
	}
	li := int(l.Index)
	switch st.asset.kind {
	case registry.KindERC1155:
		return s.classify1155(st, l, li)
	case registry.KindERC721:
		return s.classify721(st, l, li)
	default: // erc20
		return s.classify20(st, l, li)
	}
}

// classify20 decodes an ERC-20 Transfer (3 topics, 32-byte data value).
func (s *Service) classify20(st *receiveState, l types.Log, li int) (pending, bool) {
	if len(l.Topics) != 3 || l.Topics[0] != transferTopic0 || len(l.Data) != 32 {
		return pending{}, false // a 4-topic 721 log on an erc20 asset is skipped here
	}
	if common.BytesToAddress(l.Topics[2].Bytes()) != st.addr {
		return pending{}, false
	}
	val := new(big.Int).SetBytes(l.Data)
	if val.Sign() == 0 {
		return pending{}, false
	}
	return pending{
		txHash:      l.TxHash,
		logIndex:    &li,
		from:        common.BytesToAddress(l.Topics[1].Bytes()),
		value:       val,
		block:       l.BlockNumber,
		blockHash:   l.BlockHash,
		attribution: domain.AttribLog,
	}, true
}

// classify721 decodes an ERC-721 Transfer (4 topics: sig, from, to, tokenId). The
// value is always 1 (one NFT). When the listen targets a single tokenId, a log for
// a different id is skipped.
func (s *Service) classify721(st *receiveState, l types.Log, li int) (pending, bool) {
	if len(l.Topics) != 4 || l.Topics[0] != transferTopic0 {
		return pending{}, false // a 3-topic 20 log on a 721 asset is skipped here
	}
	if common.BytesToAddress(l.Topics[2].Bytes()) != st.addr {
		return pending{}, false
	}
	tokenID := new(big.Int).SetBytes(l.Topics[3].Bytes()).String()
	if st.asset.tokenID != "" && st.asset.tokenID != tokenID {
		return pending{}, false
	}
	return pending{
		txHash:      l.TxHash,
		logIndex:    &li,
		from:        common.BytesToAddress(l.Topics[1].Bytes()),
		value:       big.NewInt(1),
		tokenID:     tokenID,
		block:       l.BlockNumber,
		blockHash:   l.BlockHash,
		attribution: domain.AttribLog,
	}, true
}

// classify1155 decodes an ERC-1155 TransferSingle (id, value in data) for the
// listening recipient. TransferBatch is decoded element-wise; only the targeted
// tokenId (or any, when no specific id) contributes. recipient (to) is topic3.
func (s *Service) classify1155(st *receiveState, l types.Log, li int) (pending, bool) {
	if len(l.Topics) != 4 {
		return pending{}, false
	}
	if common.BytesToAddress(l.Topics[3].Bytes()) != st.addr {
		return pending{}, false
	}
	from := common.BytesToAddress(l.Topics[2].Bytes())
	switch l.Topics[0] {
	case transferSingleTopic0:
		// data = id (32) || value (32)
		if len(l.Data) < 64 {
			return pending{}, false
		}
		id := new(big.Int).SetBytes(l.Data[0:32]).String()
		val := new(big.Int).SetBytes(l.Data[32:64])
		if st.asset.tokenID != "" && st.asset.tokenID != id {
			return pending{}, false
		}
		if val.Sign() == 0 {
			return pending{}, false
		}
		return pending{
			txHash:      l.TxHash,
			logIndex:    &li,
			from:        from,
			value:       val,
			tokenID:     id,
			block:       l.BlockNumber,
			blockHash:   l.BlockHash,
			attribution: domain.AttribLog,
		}, true
	case transferBatchTopic0:
		ids, vals, ok := decode1155Batch(l.Data)
		if !ok {
			return pending{}, false
		}
		sum := big.NewInt(0)
		for i := range ids {
			if st.asset.tokenID != "" && st.asset.tokenID != ids[i].String() {
				continue
			}
			sum.Add(sum, vals[i])
		}
		if sum.Sign() == 0 {
			return pending{}, false
		}
		return pending{
			txHash:      l.TxHash,
			logIndex:    &li,
			from:        from,
			value:       sum,
			tokenID:     st.asset.tokenID,
			block:       l.BlockNumber,
			blockHash:   l.BlockHash,
			attribution: domain.AttribLog,
		}, true
	}
	return pending{}, false
}

// decode1155Batch decodes the ABI (uint256[] ids, uint256[] values) tail of a
// TransferBatch data field. It is tolerant: a malformed/short encoding returns
// ok=false (the log is skipped), never a panic.
func decode1155Batch(data []byte) (ids, vals []*big.Int, ok bool) {
	word := func(off int) (*big.Int, bool) {
		if off < 0 || off+32 > len(data) {
			return nil, false
		}
		return new(big.Int).SetBytes(data[off : off+32]), true
	}
	// data layout: [off_ids][off_vals][ids...][vals...], offsets relative to data start.
	offIdsB, ok1 := word(0)
	offValsB, ok2 := word(32)
	if !ok1 || !ok2 {
		return nil, nil, false
	}
	offIds := int(offIdsB.Int64())
	offVals := int(offValsB.Int64())
	readArr := func(off int) ([]*big.Int, bool) {
		lenB, okL := word(off)
		if !okL {
			return nil, false
		}
		n := int(lenB.Int64())
		if n < 0 || n > 1<<20 { // sanity bound
			return nil, false
		}
		out := make([]*big.Int, 0, n)
		for i := 0; i < n; i++ {
			v, okV := word(off + 32 + i*32)
			if !okV {
				return nil, false
			}
			out = append(out, v)
		}
		return out, true
	}
	ids, ok1 = readArr(offIds)
	vals, ok2 = readArr(offVals)
	if !ok1 || !ok2 || len(ids) != len(vals) {
		return nil, nil, false
	}
	return ids, vals, true
}

// recordDetection adds a new detection to the pending set (dedup by key) and emits
// EvDetected. It bumps cumulativeDetected and refreshes the activity clock.
func (s *Service) recordDetection(sink domain.EventSink, st *receiveState, det pending) {
	k := det.key()
	if _, seen := st.pending[k]; seen {
		return
	}
	if _, done := st.confirmed[k]; done {
		return
	}
	d := det
	st.pending[k] = &d
	st.cumDetected.Add(st.cumDetected, det.value)
	s.emitDetected(sink, st, &d)
}

// advanceConfirmations walks the pending + confirmed sets at the current head:
// pending detections that reach the target are re-verified and moved to confirmed
// (EvConfirmed, cumulative += value); confirmed detections that reorged out emit
// EvReorged and SUBTRACT from the cumulative counter (§5.8). Below-target pending
// detections emit EvConfirming.
func (s *Service) advanceConfirmations(ctx context.Context, cc chain.Client, sink domain.EventSink, st *receiveState, head uint64) error {
	// 1. confirmed-set reorg re-verify: a previously confirmed detection whose
	//    evidence vanished subtracts back out.
	for k, det := range st.confirmed {
		ok, verr := s.reverify(ctx, cc, st, det)
		if verr != nil {
			return verr
		}
		if !ok {
			st.cumConfirmed.Sub(st.cumConfirmed, det.value)
			delete(st.confirmed, k)
			// a reorged detection re-enters detection territory: drop it entirely
			// (its tx, if it re-mines, is re-detected by a future scan).
			s.emitReorged(sink, st, det)
		}
	}

	// 2. pending detections: confirm or keep waiting.
	for k, det := range st.pending {
		if det.block > head {
			continue // not yet at/under head (a reorg shrank the chain)
		}
		conf := head - det.block + 1
		if conf < st.confTarget {
			s.emitConfirming(sink, st, det, conf)
			continue
		}
		ok, verr := s.reverify(ctx, cc, st, det)
		if verr != nil {
			return verr
		}
		if !ok {
			// evidence gone before it ever confirmed: drop + reorged.
			delete(st.pending, k)
			s.emitReorged(sink, st, det)
			continue
		}
		// confirmed: move pending → confirmed, bump cumulative.
		delete(st.pending, k)
		st.confirmed[k] = det
		st.cumConfirmed.Add(st.cumConfirmed, det.value)
		s.emitConfirmed(sink, st, det)
	}
	return nil
}

// reverify re-checks a detection's evidence at the confirmation point (§5.8):
//   - log → re-FilterLogs over [B,B]; re-find the same (tx_hash, log_index) and
//     compare blockHash + receipt.Status==1. Mismatch/absent ⇒ reorged.
//   - tx (ETH block-scan) → Receipt(txHash); compare receipt.BlockHash to the
//     recorded one. Reorged if it differs/absent.
//   - balance-delta → cannot be re-verified at a fixed block in the carry-forward
//     model; it is accepted as-is (a reorg that erases the delta is caught by the
//     baseline drifting back on the next poll, §5.8). Always ok=true here.
func (s *Service) reverify(ctx context.Context, cc chain.Client, st *receiveState, det *pending) (bool, error) {
	switch det.attribution {
	case domain.AttribBalanceDelta:
		return true, nil // carry-forward model; no fixed-block re-read
	case domain.AttribTx:
		rcpt, err := cc.Receipt(ctx, det.txHash)
		if err != nil {
			if isNotFound(err) {
				return false, nil // tx gone ⇒ reorged out
			}
			return false, mapRPCErr(err)
		}
		if rcpt.Status != types.ReceiptStatusSuccessful {
			return false, nil
		}
		return rcpt.BlockHash == det.blockHash, nil
	case domain.AttribLog:
		logs, err := cc.FilterLogs(ctx, s.transferQuery(st, det.block, det.block))
		if err != nil {
			return false, mapRPCErr(err)
		}
		for i := range logs {
			if logs[i].TxHash == det.txHash && det.logIndex != nil && int(logs[i].Index) == *det.logIndex {
				if logs[i].Removed || logs[i].BlockHash != det.blockHash {
					return false, nil
				}
				// receipt status cross-check (a reverted tx emits no real transfer).
				rcpt, rerr := cc.Receipt(ctx, det.txHash)
				if rerr != nil {
					if isNotFound(rerr) {
						return false, nil
					}
					return false, mapRPCErr(rerr)
				}
				return rcpt.Status == types.ReceiptStatusSuccessful, nil
			}
		}
		return false, nil // the log is no longer in block B ⇒ reorged
	}
	return true, nil
}

// completed reports whether the active completion mode is satisfied by the
// CONFIRMED set (§5.8 completion table):
//   - any        → any confirmed inbound (cumulative ≥ 1 base unit).
//   - cumulative → cumulativeConfirmed ≥ targetAmount.
//   - exact      → ONE confirmed ATTRIBUTABLE (tx|log) detection with value ==
//     targetAmount (balance-delta can never satisfy it).
//   - nft        → 721: any confirmed transfer; 1155 with --amount: cumulative
//     quantity ≥ targetAmount (else any confirmed).
func (s *Service) completed(st *receiveState) bool {
	switch st.mode {
	case domain.ModeAny:
		return st.cumConfirmed.Sign() > 0
	case domain.ModeExact:
		for _, det := range st.confirmed {
			if domain.IsAttributable(det.attribution) && det.value.Cmp(st.targetAmount) == 0 {
				return true
			}
		}
		return false
	case domain.ModeNFT:
		if st.targetAmount != nil && st.targetAmount.Sign() > 0 {
			return st.cumConfirmed.Cmp(st.targetAmount) >= 0
		}
		return st.cumConfirmed.Sign() > 0
	default: // cumulative
		if st.targetAmount == nil {
			return st.cumConfirmed.Sign() > 0
		}
		return st.cumConfirmed.Cmp(st.targetAmount) >= 0
	}
}

// remaining returns the still-outstanding amount at FULL fixed-point precision
// (never rounded down — a rounded-down resume under-charges the counterparty,
// §5.8). For ModeAny / a satisfied target it is zero.
func (st *receiveState) remaining() *big.Int {
	if st.targetAmount == nil {
		return big.NewInt(0)
	}
	r := new(big.Int).Sub(st.targetAmount, st.cumConfirmed)
	if r.Sign() < 0 {
		return big.NewInt(0)
	}
	return r
}

// ── result builders ───────────────────────────────────────────────────────────

// completeResult emits the terminal EvComplete (exit 0) and returns the success
// result. complete is the SINGLE terminal success line; confirmed is per-transfer
// and never terminal (§5.8).
func (s *Service) completeResult(sink domain.EventSink, st *receiveState) domain.ReceiveResult {
	res := st.result("complete", 0)
	exit := 0
	domain.Emit(sink, domain.Event{
		Kind:                domain.EvComplete,
		V:                   1,
		Address:             st.addr,
		CumulativeConfirmed: st.cumConfirmed.String(),
		TxHashes:            st.confirmedHashes(),
		LastScanned:         st.lastScanned,
		Exit:                &exit,
		TS:                  s.nowTS(),
		Stream:              "stdout",
	})
	return res
}

// timeoutResult emits the terminal EvTimeout (exit 8, resumable) and returns the
// timeout result. The resume string carries --amount at FULL precision and
// --from-block = last_scanned+1; ETH listens append the verify-balance note (§5.8).
func (s *Service) timeoutResult(sink domain.EventSink, st *receiveState) domain.ReceiveResult {
	res := st.result("timeout", 8)
	exit := 8
	resume := s.resumeCommand(st)
	res.Resume = resume
	note := ""
	if st.asset.isETH() {
		note = "verify balance before resuming"
	}
	domain.Emit(sink, domain.Event{
		Kind:                domain.EvTimeout,
		V:                   1,
		Address:             st.addr,
		CumulativeConfirmed: st.cumConfirmed.String(),
		Remaining:           st.remaining().String(),
		LastScanned:         st.lastScanned,
		Resume:              resume,
		Note:                note,
		Exit:                &exit,
		TS:                  s.nowTS(),
		Stream:              "stdout",
	})
	return res
}

// result projects the running state into the wire ReceiveResult.
func (st *receiveState) result(status string, exit int) domain.ReceiveResult {
	return domain.ReceiveResult{
		Address:             st.addr.Hex(),
		Network:             st.network,
		ChainID:             st.chainID,
		Asset:               st.assetWire(),
		Target:              st.targetWire(),
		Status:              status,
		CumulativeConfirmed: st.cumConfirmed.String(),
		Remaining:           st.remaining().String(),
		Transfers:           st.confirmedTransfers(),
		LastScanned:         st.lastScanned,
		Exit:                exit,
	}
}

// resumeCommand builds the executable `daxie receive …` resume command (§5.8): the
// listening account, the asset flag, --amount <remaining FULL precision>, and
// --from-block <last_scanned+1>. A fresh --new address resumes by --account on the
// derived ref so the same address is listened to again (it is now a stored index).
func (s *Service) resumeCommand(st *receiveState) string {
	var b strings.Builder
	b.WriteString("daxie receive")
	if st.accountRef != "" {
		b.WriteString(" --account ")
		b.WriteString(st.accountRef)
	} else {
		b.WriteString(" --account ")
		b.WriteString(st.addr.Hex())
	}
	switch st.asset.kind {
	case registry.KindERC20:
		b.WriteString(" --token ")
		b.WriteString(assetFlagValue(st.asset))
	case registry.KindERC721, registry.KindERC1155:
		b.WriteString(" --nft ")
		b.WriteString(nftFlagValue(st.asset))
	}
	if st.targetAmount != nil {
		b.WriteString(" --amount ")
		b.WriteString(s.humanAmount(st))
	}
	if st.mode == domain.ModeExact {
		b.WriteString(" --exact")
	}
	fmt.Fprintf(&b, " --from-block %d", st.lastScanned+1)
	return b.String()
}

// humanAmount renders the REMAINING target at FULL precision in the human unit the
// --amount flag expects, so the resume command round-trips back through
// receiveTargetAmount exactly (§5.8 — never rounded down; a rounded-down resume
// under-charges the counterparty):
//   - ETH ⇒ wei formatted back to ETH (exact, no float).
//   - ERC-20 ⇒ the base-unit remainder formatted back to DISPLAY units via the
//     asset's decimals (e.g. 40000000 base → "40" for USDC decimals=6), matching the
//     §5.8 resume example `--token USDC --amount 40` and re-parsing at full precision
//     through ParseTokenAmount.
//   - NFT (721/1155) ⇒ the integer quantity (decimals 0; FormatTokenAmount is the
//     identity, kept explicit so the round-trip is uniform).
func (s *Service) humanAmount(st *receiveState) string {
	rem := st.remaining()
	switch st.asset.kind {
	case registry.KindERC20, registry.KindERC721, registry.KindERC1155:
		// Format back to display units (decimals=0 for NFTs ⇒ the raw integer); this
		// re-parses through ParseTokenAmount at full precision on resume.
		return ethunit.FormatTokenAmount(rem, st.asset.decimals)
	default: // eth
		return ethunit.FormatAmount(rem, ethunit.Eth)
	}
}

// assetFlagValue returns the value to pass to --token on resume: the alias when
// known, else the contract hex.
func assetFlagValue(a listenAsset) string {
	if a.alias != "" {
		return a.alias
	}
	return a.contract.Hex()
}

// nftFlagValue returns the value to pass to --nft on resume: <contract>#<id> when
// an id is targeted, else the contract (collection-wide).
func nftFlagValue(a listenAsset) string {
	if a.tokenID != "" {
		return a.contract.Hex() + "#" + a.tokenID
	}
	if a.alias != "" {
		return a.alias
	}
	return a.contract.Hex()
}

// confirmedHashes returns the distinct tx hashes of the confirmed set (for the
// complete line's tx_hashes), in a stable order; balance-delta detections (no
// hash) are omitted.
func (st *receiveState) confirmedHashes() []string {
	seen := map[string]bool{}
	var out []string
	for _, det := range st.confirmedOrdered() {
		if det.txHash == (common.Hash{}) {
			continue
		}
		h := det.txHash.Hex()
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// confirmedTransfers projects the confirmed set into wire DetectedTransfers.
func (st *receiveState) confirmedTransfers() []domain.DetectedTransfer {
	var out []domain.DetectedTransfer
	for _, det := range st.confirmedOrdered() {
		dt := domain.DetectedTransfer{
			Value:       det.value.String(),
			Block:       det.block,
			Attribution: det.attribution,
			TokenID:     det.tokenID,
		}
		if det.txHash != (common.Hash{}) {
			dt.TxHash = det.txHash.Hex()
		}
		if det.logIndex != nil {
			li := *det.logIndex
			dt.LogIndex = &li
		}
		if det.from != (common.Address{}) {
			dt.From = det.from.Hex()
		}
		if det.blockHash != (common.Hash{}) {
			dt.BlockHash = det.blockHash.Hex()
		}
		out = append(out, dt)
	}
	return out
}

// confirmedOrdered returns the confirmed detections in a deterministic order
// (block, then logIndex, then txHash) so the result + the complete line are stable
// across the map iteration.
func (st *receiveState) confirmedOrdered() []*pending {
	out := make([]*pending, 0, len(st.confirmed))
	for _, d := range st.confirmed {
		out = append(out, d)
	}
	sortPending(out)
	return out
}

// sortPending orders detections by (block, logIndex, txHash) for stable output.
func sortPending(ds []*pending) {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].block != ds[j].block {
			return ds[i].block < ds[j].block
		}
		li, lj := -1, -1
		if ds[i].logIndex != nil {
			li = *ds[i].logIndex
		}
		if ds[j].logIndex != nil {
			lj = *ds[j].logIndex
		}
		if li != lj {
			return li < lj
		}
		return ds[i].txHash.Hex() < ds[j].txHash.Hex()
	})
}

// assetWire / targetWire project the resolved asset + target into the wire views.
func (st *receiveState) assetWire() domain.ReceiveAsset {
	a := domain.ReceiveAsset{Kind: assetKind(st.asset), Alias: st.asset.alias}
	if !st.asset.isETH() {
		a.Contract = st.asset.contract.Hex()
		a.Decimals = int(st.asset.decimals)
		a.TokenID = st.asset.tokenID
	}
	return a
}

func (st *receiveState) targetWire() domain.ReceiveTarget {
	t := domain.ReceiveTarget{Mode: st.mode, Confirmations: st.confTarget}
	if st.targetAmount != nil {
		t.Amount = st.targetAmount.String()
	}
	return t
}

// assetKind maps the internal listenAsset kind to the wire "eth"|"erc20"|… value.
func assetKind(a listenAsset) string {
	if a.isETH() {
		return "eth"
	}
	return a.kind
}

// ── address / asset / amount resolution ───────────────────────────────────────

// resolveListenAddress resolves the listening address (§5.8): a fresh --new index
// (keys.DeriveNext, requires a writable keystore — keystore.read_only ⇒ exit 10;
// optional --name alias), else an existing account ref (flag>env>meta.json default,
// or a raw 0x / ENS read-only ref). It returns the address + the account ref to
// embed in the resume string ("" for a raw 0x). --new requires a passphrase (the
// keystore write authenticates non-interactively via the passphrase channels).
func (s *Service) resolveListenAddress(ctx context.Context, cc chain.Client, req domain.ReceiveRequest) (common.Address, string, error) {
	if req.New {
		pass, _, err := s.acquire(passphraseSpecWith(false, "", false))
		if err != nil {
			return common.Address{}, "", err
		}
		defer pass.Zero()
		idx, addr, derr := s.keys.DeriveNext(ctx, req.Wallet, pass)
		if derr != nil {
			return common.Address{}, "", derr // read-only keystore ⇒ keystore.read_only (exit 10)
		}
		ref := req.Wallet + "/" + utoa(idx)
		if req.Name != "" {
			if aerr := s.keys.Alias(ctx, req.Wallet, idx, req.Name); aerr != nil {
				return common.Address{}, "", aerr
			}
			ref = req.Wallet + "/" + req.Name
		}
		return addr, ref, nil
	}

	refStr := req.Account
	if refStr == "" {
		refStr = s.activeDefault(ctx)
	}
	if refStr == "" {
		return common.Address{}, "", domain.New(domain.CodeUsage+".no_account",
			"no account given and no default account set (pass an address/ref, run `daxie account use`, or use --new)")
	}
	ref, err := domain.ParseAccountRef(refStr)
	if err != nil {
		return common.Address{}, "", err
	}
	var addr common.Address
	if ref.Kind == domain.RefENS {
		addr, err = s.ens.Resolve(ctx, cc, ref.Raw)
		if err != nil {
			return common.Address{}, "", mapENSErr(err, ref.Raw)
		}
	} else {
		addr, err = s.keys.AddressOf(ref)
		if err != nil {
			return common.Address{}, "", err
		}
	}
	accountRef := ""
	if ref.Kind != domain.RefAddress {
		accountRef = ref.Raw
	}
	return addr, accountRef, nil
}

// resolveListenAsset resolves the asset to listen for via the SAME chokepoints
// M5/M6 use (resolveAsset for --token, resolveNFT for --nft), or native ETH.
func (s *Service) resolveListenAsset(ctx context.Context, cc chain.Client, network string, req domain.ReceiveRequest) (listenAsset, error) {
	switch {
	case req.Token != "":
		ra, err := s.resolveAsset(ctx, cc, network, req.Token)
		if err != nil {
			return listenAsset{}, err
		}
		return listenAsset{
			kind:     registry.KindERC20,
			contract: ra.contract,
			alias:    ra.alias,
			decimals: ra.decimals,
		}, nil
	case req.NFT != "":
		rn, err := s.resolveNFT(ctx, cc, network, req.NFT)
		if err != nil {
			return listenAsset{}, err
		}
		alias := rn.nftAlias
		if alias == "" {
			alias = rn.collectionAlias
		}
		return listenAsset{
			kind:     rn.kind,
			contract: rn.collection,
			alias:    alias,
			tokenID:  rn.tokenID,
		}, nil
	default:
		return listenAsset{kind: "eth"}, nil
	}
}

// receiveTargetAmount resolves the completion target amount in BASE UNITS (§5.8):
//   - ModeAny ⇒ nil (any inbound; no fixed amount).
//   - ETH ⇒ human ETH ("0.5") parsed to wei via ethunit.
//   - ERC-20 ⇒ a DISPLAY-unit decimal ("100") SCALED by the asset's decimals to
//     base units, exactly like the send side (tx.go ethunit.ParseTokenAmount) and
//     the cli-spec. The §5.8 listening line then carries target.amount in base
//     units (e.g. "100000000" for --amount 100 on USDC decimals=6); the wire
//     amounts are base-unit decimal strings, but the --amount FLAG is display units.
//   - NFT (721/1155) ⇒ an integer quantity. decimals is 0 for NFTs, so scaling by
//     ParseTokenAmount passes the integer through unchanged (1155 cumulative qty).
//
// Parsed over math/big (NO float). For ModeNFT 721 with no --amount the target is
// nil (one transfer suffices).
func (s *Service) receiveTargetAmount(req domain.ReceiveRequest, mode domain.ReceiveMode, asset listenAsset) (*big.Int, error) {
	if req.Amount == "" {
		return nil, nil // any-inbound / nft-721-any
	}
	if asset.isETH() {
		wei, err := ethunit.ParseAmount(req.Amount, ethunit.Eth)
		if err != nil {
			return nil, domain.Newf(domain.CodeUsage+".bad_amount", "invalid ETH amount %q: %v", req.Amount, err)
		}
		return wei, nil
	}
	// token / NFT: scale the DISPLAY-unit --amount by the asset's decimals into base
	// units — the SAME convention as `tx send` (ethunit.ParseTokenAmount). decimals
	// is the ERC-20 display precision (e.g. 6 for USDC) and 0 for ERC-721/1155, so an
	// NFT integer quantity passes through unchanged. The engine then compares the
	// cumulative base-unit inflow against this base-unit target directly.
	base, err := ethunit.ParseTokenAmount(strings.TrimSpace(req.Amount), asset.decimals)
	if err != nil {
		return nil, domain.Newf(domain.CodeUsage+".bad_amount",
			"invalid amount %q: %v", req.Amount, err)
	}
	return base, nil
}

// ── event emission (all Stream="stdout"; the renderer owns the exact §5.8 line) ──

func (s *Service) emitListening(sink domain.EventSink, st *receiveState, fromBlock uint64) {
	st.lastActivity = s.Now().Unix()
	a := st.assetWire()
	ea := &domain.EventAsset{Kind: a.Kind, Contract: a.Contract, Alias: a.Alias, Decimals: a.Decimals, TokenID: a.TokenID}
	t := st.targetWire()
	et := &domain.EventTarget{Mode: string(t.Mode), Amount: t.Amount, Confirmations: t.Confirmations, Timeout: t.Timeout}
	domain.Emit(sink, domain.Event{
		Kind:       domain.EvListening,
		V:          1,
		Address:    st.addr,
		Network:    st.network,
		ChainID:    st.chainID,
		Asset:      ea,
		TargetSpec: et,
		FromBlock:  fromBlock,
		TS:         s.nowTS(),
		Stream:     "stdout",
	})
}

func (s *Service) emitDetected(sink domain.EventSink, st *receiveState, det *pending) {
	st.lastActivity = s.Now().Unix()
	match := true
	ev := domain.Event{
		Kind:                domain.EvDetected,
		V:                   1,
		From:                addrHexOrEmpty(det.from),
		Value:               det.value.String(),
		Block:               det.block,
		Attribution:         det.attribution,
		Match:               &match,
		CumulativeDetected:  st.cumDetected.String(),
		CumulativeConfirmed: st.cumConfirmed.String(),
		Remaining:           st.remaining().String(),
		LastScanned:         st.lastScanned,
		TS:                  s.nowTS(),
		Stream:              "stdout",
	}
	if det.txHash != (common.Hash{}) {
		ev.TxHash = det.txHash.Hex()
	}
	if det.blockHash != (common.Hash{}) {
		ev.BlockHash = det.blockHash.Hex()
	}
	if det.logIndex != nil {
		li := *det.logIndex
		ev.LogIndex = &li
	}
	if det.tokenID != "" {
		tid := det.tokenID
		ev.TokenID = &tid
	}
	domain.Emit(sink, ev)
}

func (s *Service) emitConfirming(sink domain.EventSink, st *receiveState, det *pending, conf uint64) {
	st.lastActivity = s.Now().Unix()
	domain.Emit(sink, domain.Event{
		Kind:                domain.EvConfirming,
		V:                   1,
		TxHash:              hashHexOrEmpty(det.txHash),
		Conf:                conf,
		Target:              st.confTarget,
		CumulativeConfirmed: st.cumConfirmed.String(),
		Remaining:           st.remaining().String(),
		LastScanned:         st.lastScanned,
		TS:                  s.nowTS(),
		Stream:              "stdout",
	})
}

func (s *Service) emitConfirmed(sink domain.EventSink, st *receiveState, det *pending) {
	st.lastActivity = s.Now().Unix()
	domain.Emit(sink, domain.Event{
		Kind:                domain.EvConfirmed,
		V:                   1,
		TxHash:              hashHexOrEmpty(det.txHash),
		Value:               det.value.String(),
		CumulativeConfirmed: st.cumConfirmed.String(),
		Remaining:           st.remaining().String(),
		LastScanned:         st.lastScanned,
		TS:                  s.nowTS(),
		Stream:              "stdout",
	})
}

func (s *Service) emitReorged(sink domain.EventSink, st *receiveState, det *pending) {
	st.lastActivity = s.Now().Unix()
	domain.Emit(sink, domain.Event{
		Kind:                domain.EvReorged,
		V:                   1,
		TxHash:              hashHexOrEmpty(det.txHash),
		Value:               det.value.String(),
		CumulativeConfirmed: st.cumConfirmed.String(),
		Remaining:           st.remaining().String(),
		LastScanned:         st.lastScanned,
		TS:                  s.nowTS(),
		Stream:              "stdout",
	})
}

// maybeHeartbeat emits an EvHeartbeat when no event has fired for at least
// receive.heartbeat-interval (§5.8 quiet-period keepalive). It refreshes the
// activity clock so heartbeats are spaced, not continuous.
func (s *Service) maybeHeartbeat(sink domain.EventSink, st *receiveState) {
	hb := s.cfg.Receive.HeartbeatInterval
	if hb <= 0 {
		return
	}
	now := s.Now().Unix()
	if now-st.lastActivity < int64(hb.Seconds()) {
		return
	}
	st.lastActivity = now
	domain.Emit(sink, domain.Event{
		Kind:                domain.EvHeartbeat,
		V:                   1,
		CumulativeConfirmed: st.cumConfirmed.String(),
		Remaining:           st.remaining().String(),
		LastScanned:         st.lastScanned,
		TS:                  s.nowTS(),
		Stream:              "stdout",
	})
}

// nowTS renders the service clock as an RFC3339 (UTC) timestamp string for the
// "ts" field on every receive line (§5.8). It reads time only through s.Now().
func (s *Service) nowTS() string {
	t := s.Now()
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// addrHexOrEmpty / hashHexOrEmpty render zero values as "" (omitted by the
// renderer) so a balance-delta detection (no from/hash) does not carry a 0x0…0.
func addrHexOrEmpty(a common.Address) string {
	if a == (common.Address{}) {
		return ""
	}
	return a.Hex()
}

func hashHexOrEmpty(h common.Hash) string {
	if h == (common.Hash{}) {
		return ""
	}
	return h.Hex()
}

// isNotFound reports whether err is a not-found (tx/receipt absent), used by
// reverify to treat a vanished receipt as a reorg rather than a transport failure.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if de := domain.AsError(err); de.Code == domain.CodeRefNotFound {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}
