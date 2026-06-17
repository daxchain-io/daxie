package service

import (
	"context"
	"errors"
	"math/big"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/policy"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// txstatus.go is the M3 read/observe side of the pipeline: TxStatus (fold the
// journal record + one receipt/nonce re-check), WaitTx (the §5.3 wait state
// machine), ListTxs (the journal history), plus the ONE shared rebroadcast helper
// every rebroadcast path goes through (§5.3 binding rule) and the destination
// resolver SendTx/RBF share.
//
// Neither TxStatus nor WaitTx acquires an account lock — they take only the
// journal flock (the §5.6 deadlock-free rule: lock ordering is account→journal, so
// a status query that never takes the account lock can never deadlock an in-flight
// send).

// TxStatus folds the journal record for a hash plus a single receipt/nonce
// re-check. It never broadcasts and never acquires an account lock.
func (s *Service) TxStatus(ctx context.Context, p domain.Principal, req domain.TxStatusRequest, sink domain.EventSink) (domain.TxResult, error) {
	hash, err := parseHash(req.Hash)
	if err != nil {
		return domain.TxResult{}, err
	}

	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.TxResult{}, err
	}
	defer cc.Close()

	chainID, err := cc.ChainID(ctx)
	if err != nil {
		return domain.TxResult{}, mapRPCErr(err)
	}

	// §5.6: restart reconciliation runs on `tx status` — resurrect any crash-left
	// `signed` record (a transport-exhausted send whose bytes may be in a mempool)
	// through the shared receipt-first helper. Best-effort; never fails the query.
	s.resurrectUnresolved(ctx, cc, chainID.Uint64())

	rec, err := s.journal.ByHash(ctx, chainID.Uint64(), hash)
	if err != nil && !errors.Is(err, journal.ErrNotFound) {
		return domain.TxResult{}, err
	}

	target := s.confirmTarget(req.Network, nil)
	res, _, err := s.observe(ctx, cc, chainID, hash, rec, s.networkName(req.Network), target)
	if err != nil {
		return domain.TxResult{}, err
	}
	return res, nil
}

// WaitTx runs the §5.3 state machine on a known hash (the resume-after-timeout
// entry point). It resolves the per-network confirmation target + the timeout,
// dials, and loops via the shared wait body.
func (s *Service) WaitTx(ctx context.Context, p domain.Principal, req domain.WaitRequest, sink domain.EventSink) (domain.TxResult, error) {
	hash, err := parseHash(req.Hash)
	if err != nil {
		return domain.TxResult{}, err
	}

	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.TxResult{}, err
	}
	defer cc.Close()

	chainID, err := cc.ChainID(ctx)
	if err != nil {
		return domain.TxResult{}, mapRPCErr(err)
	}

	rec, jerr := s.journal.ByHash(ctx, chainID.Uint64(), hash)
	if jerr != nil && !errors.Is(jerr, journal.ErrNotFound) {
		return domain.TxResult{}, jerr
	}
	journalID := ""
	if rec != nil {
		journalID = rec.ID
	}

	wait := domain.WaitOpts{Enabled: true, Confirmations: req.Confirmations, Timeout: req.Timeout}
	return s.waitOnHash(ctx, p, cc, s.networkName(req.Network), hash, journalID, chainID, wait, sink)
}

// ListTxs reads the journal (latest-per-id, newest-first) for an account (or all
// when Account is empty), backing `tx list`. It takes only the journal flock.
func (s *Service) ListTxs(ctx context.Context, p domain.Principal, req domain.TxListRequest) (domain.TxListResult, error) {
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.TxListResult{}, err
	}
	defer cc.Close()
	chainID, err := cc.ChainID(ctx)
	if err != nil {
		return domain.TxListResult{}, mapRPCErr(err)
	}

	// §5.6: restart reconciliation runs on `tx list` — resurrect crash-left `signed`
	// records before reporting history, so the list reflects the reconciled state.
	// Best-effort; never fails the listing.
	s.resurrectUnresolved(ctx, cc, chainID.Uint64())

	var from common.Address
	if req.Account != "" {
		ref, perr := domain.ParseAccountRef(req.Account)
		if perr != nil {
			return domain.TxListResult{}, perr
		}
		addr, aerr := s.keys.AddressOf(ref)
		if aerr != nil {
			return domain.TxListResult{}, aerr
		}
		from = addr
	}

	recs, err := s.journal.List(ctx, chainID.Uint64(), from)
	if err != nil {
		return domain.TxListResult{}, err
	}

	out := domain.TxListResult{Txs: make([]domain.TxRow, 0, len(recs))}
	for i, r := range recs {
		if req.Limit > 0 && i >= req.Limit {
			break
		}
		out.Txs = append(out.Txs, txRow(r))
	}
	return out, nil
}

// waitOnHash is the §5.3 wait state machine. It polls tx.poll-interval, emits an
// EvConfirmation per new confirmation (stderr), and maps the terminal states to
// the §5.7 exit codes: confirmed→0 (+SettleActual), reverted→7, replaced→9,
// dropped→re-reserve+rebroadcast (shared helper), deadline→timeout 8 (resumable).
// The deadline is enforced via the injected clock (s.clock()), never a wall read.
func (s *Service) waitOnHash(ctx context.Context, p domain.Principal, cc chain.Client, network string, hash common.Hash, journalID string, chainID *big.Int, wait domain.WaitOpts, sink domain.EventSink) (domain.TxResult, error) {
	target := s.confirmTarget(network, wait.Confirmations)
	timeout := wait.Timeout.D
	if timeout <= 0 {
		timeout = s.cfg.Tx.WaitTimeout
	}
	deadline := s.clock().Add(timeout)
	poll := s.cfg.Tx.PollInterval

	chainU := chainID.Uint64()
	lastConf := uint64(0)

	for {
		rec, jerr := s.journal.ByHash(ctx, chainU, hash)
		if jerr != nil && !errors.Is(jerr, journal.ErrNotFound) {
			return domain.TxResult{}, jerr
		}

		res, st, oerr := s.observe(ctx, cc, chainID, hash, rec, network, target)
		if oerr != nil {
			// A transport failure during wait is recoverable: if the chain never
			// saw the tx we may need to rebroadcast (handled in the dropped branch);
			// here a plain RPC error is surfaced as rpc.unreachable (retryable, the
			// wait is resumable). The caller re-runs `tx wait`.
			return res, oerr
		}

		switch st {
		case waitConfirmed:
			if res.Confirmations > lastConf {
				emitConfirmation(sink, hash, res.Confirmations, target)
			}
			return res, nil

		case waitReverted:
			return res, domain.New(domain.CodeTxReverted, "transaction reverted on-chain")

		case waitReplaced:
			return res, domain.New(domain.CodeTxReplaced, "transaction replaced by another with the same nonce")

		case waitMined:
			if res.Confirmations > lastConf {
				lastConf = res.Confirmations
				emitConfirmation(sink, hash, res.Confirmations, target)
			}
			if res.Confirmations >= target {
				// Reached the target: confirm + SettleActual already handled by
				// observe's confirmed branch on the next loop; mark confirmed now.
				res.Status = domain.TxStatusConfirmed
				return res, nil
			}

		case waitDropped:
			// The nonce/receipt re-check classified this as dropped (not replaced):
			// re-reserve + rebroadcast the SAME bytes through the shared helper, then
			// keep polling.
			if rec != nil {
				if _, rerr := s.rebroadcast(ctx, cc, rec); rerr != nil {
					return res, rerr
				}
			}

		case waitPending:
			// nothing to do — keep polling.
		}

		// Deadline check (injected clock): timeout is exit 8, NOT failure, resumable.
		if !s.clock().Before(deadline) {
			res.Status = domain.TxStatusTimeout
			res.Resume = "daxie tx wait " + hash.Hex()
			return res, domain.WithData(
				domain.New(domain.CodeTxWaitTimeout, "wait deadline reached; transaction still pending (resumable)"),
				map[string]any{"resume": res.Resume, "status": "pending"})
		}

		if serr := s.sleep(ctx, poll); serr != nil {
			// ctx cancelled (SIGTERM during --wait, §5.3): resumable, not failed.
			res.Status = domain.TxStatusTimeout
			res.Resume = "daxie tx wait " + hash.Hex()
			return res, domain.WithData(
				domain.New(domain.CodeTxWaitTimeout, "wait interrupted; transaction still pending (resumable)"),
				map[string]any{"resume": res.Resume, "status": "pending"})
		}
	}
}

// waitState classifies one poll of the §5.3 machine.
type waitState int

const (
	waitPending waitState = iota
	waitMined             // a receipt exists, status 1, below the confirmation target
	waitConfirmed
	waitReverted
	waitReplaced
	waitDropped
)

// observe performs one §5.3 poll: query the receipt first, then disambiguate via
// the journal + the nonce. It returns the wire TxResult, the classified waitState,
// and any RPC error. It does NOT mutate the journal except to record a terminal
// transition (confirmed/reverted) + call SettleActual on confirmed. target is the
// resolved confirmation count (the same one waitOnHash enforces) so the confirmed
// verdict is consistent across the loop.
func (s *Service) observe(ctx context.Context, cc chain.Client, chainID *big.Int, hash common.Hash, rec *journal.Record, network string, target uint64) (domain.TxResult, waitState, error) {
	res := s.recordResult(rec, network, hash)

	rcpt, rerr := cc.Receipt(ctx, hash)
	if rerr != nil && !errors.Is(rerr, chain.ErrTxNotFound) {
		return res, waitPending, mapRPCErr(rerr)
	}

	if rcpt != nil {
		// A receipt exists.
		head, herr := cc.BlockNumber(ctx)
		if herr != nil {
			return res, waitPending, mapRPCErr(herr)
		}
		blk := rcpt.BlockNumber.Uint64()
		conf := uint64(0)
		if head >= blk {
			conf = head - blk + 1
		}
		res.Confirmations = conf
		bn := blk
		res.BlockNumber = &bn

		if rcpt.Status == 0 {
			// reverted (receipt status 0x0).
			res.Status = domain.TxStatusReverted
			s.recordTerminal(ctx, chainID.Uint64(), rec, hash, journal.StatusReverted, rcpt)
			return res, waitReverted, nil
		}
		// mined (status 0x1).
		if conf >= target {
			res.Status = domain.TxStatusConfirmed
			s.recordConfirmed(ctx, chainID.Uint64(), rec, hash, rcpt)
			return res, waitConfirmed, nil
		}
		res.Status = domain.TxStatusPending
		return res, waitMined, nil
	}

	// No receipt. Disambiguate replaced vs dropped vs still-pending via the journal
	// + the nonce (§5.3). A foreign hash (no journal record) just stays pending to
	// the deadline.
	if rec == nil {
		res.Status = domain.TxStatusPending
		return res, waitPending, nil
	}

	// We own this hash. Check whether our nonce was consumed by a DIFFERENT hash:
	// if the account's latest (mined) nonce already exceeds this tx's nonce and no
	// receipt for our hash exists, a sibling replaced us (exit 9). Otherwise the tx
	// was dropped from the mempool and should be rebroadcast.
	from := common.HexToAddress(rec.From)
	minedNonce, nerr := cc.Nonce(ctx, from, false) // latest (mined) count
	if nerr != nil {
		return res, waitPending, mapRPCErr(nerr)
	}
	if rec.ReplacedBy != nil && *rec.ReplacedBy != "" {
		res.Status = domain.TxStatusReplaced
		res.Replaced = rec.TxHash
		s.recordTerminal(ctx, chainID.Uint64(), rec, hash, journal.StatusReplaced, nil)
		return res, waitReplaced, nil
	}
	if minedNonce > rec.Nonce {
		// The nonce is already on-chain via a different hash and our hash has no
		// receipt → replaced.
		res.Status = domain.TxStatusReplaced
		s.recordTerminal(ctx, chainID.Uint64(), rec, hash, journal.StatusReplaced, nil)
		return res, waitReplaced, nil
	}
	// Nonce not yet consumed + no receipt + known to us → dropped from the mempool.
	res.Status = domain.TxStatusPending
	return res, waitDropped, nil
}

// resurrectUnresolved is the §5.6 CHAIN-AWARE restart reconciliation: it folds
// journal.Unresolved(chainID) and, for each non-terminal record, runs the
// receipt-first branch through the shared rebroadcast() helper. That helper already
// (a) queries the receipt/nonce FIRST and (b) branches per §5.6: unknown/pending →
// re-broadcast the persisted bytes (tolerating already-known); receipt found →
// never re-broadcast (the mined-while-down case is caught by the receipt gate);
// same-nonce sibling mined → mark replaced. It enforces the double-spend gates and
// the signed→re-reserve vs broadcast→ride rule.
//
// This is the on-chain counterpart of the OFFLINE service.reconcile() (reconcile.go,
// no RPC): the offline pass resolves crash-left RESERVATIONS at Open; this pass
// resurrects crash-left `signed` records (a transport-exhausted send whose bytes may
// be in a mempool) wherever a chain client is available — §5.6 names the call sites
// as tx status / tx list / service.Open / the send lock acquisition.
//
// It must NEVER fail its caller's primary operation: a per-record resurrection error
// (a transient RPC blip, a double-spend gate) is swallowed — the record stays
// recoverable and the next status/list/send retries. It takes NO account lock (only
// the journal flock inside Unresolved + SetState), preserving the account→journal
// ordering, so it can run from a status/list query without deadlocking an in-flight
// send. The caller supplies an already-dialed client + the resolved chain id.
func (s *Service) resurrectUnresolved(ctx context.Context, cc chain.Client, chainID uint64) {
	if s.journal == nil || cc == nil {
		return
	}
	recs, err := s.journal.Unresolved(ctx, chainID)
	if err != nil {
		return // a torn/locked journal is non-fatal here; the primary op proceeds
	}
	for _, rec := range recs {
		if rec == nil || rec.TxHash == "" {
			continue
		}
		// rebroadcast runs the §5.6 receipt-first branch + the double-spend gates +
		// the signed/broadcast reservation rule. Errors are swallowed (best-effort).
		_, _ = s.rebroadcast(ctx, cc, rec)
	}
}

// rebroadcast is the ONE shared helper every rebroadcast path goes through (§5.3
// binding rule): the reconcile-resurrect, the wait "dropped" transition, and the
// tx-wait exit-6 transport recovery. It (a) gates on the double-spend rule —
// refuse if a canonical receipt exists for this hash OR a same-nonce sibling has a
// receipt, OR a live replaced_by link exists — and (b) resolves the reservation by
// record status: signed (no recorded broadcast) → policy.Reserve again BEFORE
// rebroadcasting; broadcast → ride the already-committed reservation; broadcast
// with a vanished reservation → never rebroadcast, mark failed with
// tx.integrity.reservation_missing (exit 12).
func (s *Service) rebroadcast(ctx context.Context, cc chain.Client, rec *journal.Record) (broadcast bool, err error) {
	chainU := rec.ChainID
	hash := common.HexToHash(rec.TxHash)

	// ── double-spend gate (a): a canonical receipt for THIS hash ⇒ never rebroadcast ──
	if rcpt, rerr := cc.Receipt(ctx, hash); rerr == nil && rcpt != nil {
		return false, nil // already mined; nothing to do
	} else if rerr != nil && !errors.Is(rerr, chain.ErrTxNotFound) {
		return false, mapRPCErr(rerr)
	}

	// ── double-spend gate (b): a live replaced_by link ⇒ a sibling owns this nonce ──
	if rec.ReplacedBy != nil && *rec.ReplacedBy != "" {
		return false, nil
	}

	// ── double-spend gate (c): a same-nonce sibling already mined ⇒ never rebroadcast ──
	from := common.HexToAddress(rec.From)
	minedNonce, nerr := cc.Nonce(ctx, from, false)
	if nerr != nil {
		return false, mapRPCErr(nerr)
	}
	if minedNonce > rec.Nonce {
		// The nonce is consumed on-chain by some hash; if it were ours the receipt
		// gate above would have caught it, so a sibling consumed it → do not
		// rebroadcast (it would be rejected nonce-too-low anyway). Mark replaced.
		_ = s.journal.SetState(ctx, chainU, rec.ID, journal.StateMutation{Status: journal.StatusReplaced})
		return false, nil
	}

	// ── resolve the reservation by record status (the §5.3 binding rule) ──
	switch rec.Status {
	case journal.StatusSigned:
		// No recorded broadcast ⇒ re-reserve BEFORE rebroadcasting (crashes only
		// ever under-spend). On a successful rebroadcast we Commit the fresh
		// reservation; on failure we Release it.
		worst := bigOrZero(rec.WorstCaseGasWei)
		value := bigOrZero(rec.ValueWei)
		recNonce := rec.Nonce
		reservation, perr := s.policy.Reserve(ctx, policy.Check{
			Account:    common.HexToAddress(rec.From),
			Dest:       common.HexToAddress(rec.To),
			SpendWei:   value,
			MaxGasWei:  worst,
			Kind:       string(rec.Kind),
			IsRBFDelta: rec.Replaces != nil,
			// §4.1: the re-reservation MUST key the same per-network counter + per-
			// network limit overrides as the original send — without Network it would
			// land in the empty-network bucket (Sepolia spend consuming mainnet
			// headroom). §4.4/§5.5: carry the account_nonce so an RBF re-reservation
			// folds into the superseded entry instead of double-counting.
			Network:      rec.Network,
			Asset:        rec.Asset.Kind,
			AccountNonce: &recNonce,
		})
		if perr != nil {
			return false, perr
		}
		if berr := s.doRebroadcast(ctx, cc, rec); berr != nil {
			_ = s.policy.Release(ctx, reservation.ID)
			return false, berr
		}
		_ = s.policy.Commit(ctx, reservation.ID, common.HexToHash(rec.TxHash))
		return true, nil

	case journal.StatusBroadcast, journal.StatusPending, journal.StatusMined, journal.StatusDropped:
		// Already-committed reservation: ride it. A `broadcast` record whose
		// reservation id resolves to NO durable reservation is integrity tampering
		// (§5.3) → never rebroadcast; mark failed with reservation_missing (exit 12).
		// policy.Commit is idempotent for an already-committed reservation, so
		// re-committing here is safe and surfaces a vanished one as the integrity
		// error. (Service bridges this because policy may not import journal.)
		if rec.Status == journal.StatusBroadcast && rec.ReservationID != "" {
			if cerr := s.policy.Commit(ctx, rec.ReservationID, hash); cerr != nil {
				if domain.AsError(cerr).Code == domain.CodeTxIntegrityReservationMissing {
					msg := "broadcast record's reservation vanished (counter-file tampering)"
					_ = s.journal.SetState(ctx, chainU, rec.ID, journal.StateMutation{
						Status: journal.StatusFailed, Error: &msg,
					})
					return false, domain.New(domain.CodeTxIntegrityReservationMissing, msg)
				}
				return false, cerr
			}
		}
		if berr := s.doRebroadcast(ctx, cc, rec); berr != nil {
			return false, berr
		}
		return true, nil

	default:
		// terminal (confirmed/reverted/replaced/failed) — nothing to rebroadcast.
		return false, nil
	}
}

// doRebroadcast submits the stored raw_tx and flips the record to `broadcast` on
// success (tolerating `already known`).
func (s *Service) doRebroadcast(ctx context.Context, cc chain.Client, rec *journal.Record) error {
	raw, derr := decodeHex(rec.RawTx)
	if derr != nil {
		return domain.Wrap(domain.CodeStateCorrupt, "journal raw_tx is not valid hex", derr)
	}
	if _, serr := cc.SendRawTransaction(ctx, raw); serr != nil {
		if !containsAny(lowerErr(serr), "already known", "already exists", "alreadyknown") {
			return mapRPCErr(serr)
		}
		// already-known ⇒ the mempool has it; treat as success.
	}
	return s.journal.SetState(ctx, rec.ChainID, rec.ID, journal.StateMutation{Status: journal.StatusBroadcast})
}

// ── result/record projection helpers ─────────────────────────────────────────

// recordResult seeds a TxResult from a journal record (the known fields), to be
// overlaid by observe's on-chain re-check.
func (s *Service) recordResult(rec *journal.Record, network string, hash common.Hash) domain.TxResult {
	res := domain.TxResult{
		Hash:    hash.Hex(),
		Network: network,
		Status:  domain.TxStatusPending,
	}
	if rec != nil {
		res.From = common.HexToAddress(rec.From)
		res.To = domain.Dest{Address: common.HexToAddress(rec.To)}
		res.Asset = wireAsset(rec.Asset, "") // journal record has no in-memory symbol
		res.AmountWei = rec.ValueWei
		res.Nonce = rec.Nonce
		res.JournalID = rec.ID
		res.Gas = gasResultFromFees(rec.Fees)
		res.Status = wireStatus(rec.Status)
		if rec.ReplacedBy != nil {
			res.Replaced = rec.TxHash
		}
	}
	return res
}

// recordTerminal records a terminal (reverted/replaced) transition into the
// journal. On a REVERTED receipt it also drives policy.SettleActual with
// reverted=true so the reservation keeps actual gas but RELEASES the native value
// (§4.4: the EVM did not move it) — otherwise a reverted tx would permanently
// consume its full value against the rolling-24h daily limit. A `replaced`
// transition (rcpt==nil) never settles (the replacement carries the spend).
func (s *Service) recordTerminal(ctx context.Context, chainID uint64, rec *journal.Record, hash common.Hash, status journal.Status, rcpt *types.Receipt) {
	if rec == nil {
		return
	}
	mut := journal.StateMutation{Status: status, Receipt: journalReceipt(rcpt)}
	_ = s.journal.SetState(ctx, chainID, rec.ID, mut)
	if status == journal.StatusReverted && rec.ReservationID != "" {
		_ = s.policy.SettleActual(ctx, rec.ReservationID, actualGas(rcpt), true)
	}
}

// recordConfirmed records the confirmed transition + calls policy.SettleActual
// with the actual gas (gasUsed × effectiveGasPrice), shrinking the reservation
// (§5.4 "shrunk to actual on receipt"). Idempotent: a second confirmed write is
// harmless (last-wins-per-id).
func (s *Service) recordConfirmed(ctx context.Context, chainID uint64, rec *journal.Record, hash common.Hash, rcpt *types.Receipt) {
	if rec == nil {
		return
	}
	mut := journal.StateMutation{Status: journal.StatusConfirmed, Receipt: journalReceipt(rcpt)}
	_ = s.journal.SetState(ctx, chainID, rec.ID, mut)
	if rec.ReservationID != "" {
		actual := actualGas(rcpt)
		_ = s.policy.SettleActual(ctx, rec.ReservationID, actual, false)
	}
}

// ── destination resolver (shared by SendTx/RBF) ──────────────────────────────

// resolveDest maps a --to value to a Dest (§5.1): a 0x literal → itself; else a
// contact name → its address (the human name echoed back); else ENS (M7, fails
// clean). An empty --to is a usage error (no recipient).
func (s *Service) resolveDest(ctx context.Context, to string) (domain.Dest, error) {
	if to == "" {
		return domain.Dest{}, domain.New(domain.CodeUsage+".no_recipient", "--to is required (address or contact name)")
	}
	ref, err := domain.ParseAccountRef(to)
	if err == nil && ref.Kind == domain.RefAddress {
		return domain.Dest{Address: ref.Addr}, nil
	}
	// ENS: M7. Fail clean (never faked).
	if err == nil && ref.Kind == domain.RefENS {
		return domain.Dest{}, domain.Newf(domain.CodeUsageUnsupported,
			"ENS resolution (%s) lands in M7; pass a 0x address or a contact name", to)
	}
	// Contact name (case-insensitive). A miss falls through to ref.not_found.
	addr, found, cerr := s.contacts.Resolve(ctx, to)
	if cerr != nil {
		return domain.Dest{}, cerr
	}
	if found {
		return domain.Dest{Address: addr, Name: to}, nil
	}
	return domain.Dest{}, domain.Newf(domain.CodeRefNotFound,
		"--to %q is not a 0x address or a known contact (add it with `daxie contacts add`)", to)
}

// confirmTarget resolves the confirmation count: the explicit override >
// networks.<n>.confirmations > the built-in (§5.2). A zero/absent everywhere
// falls back to 1.
func (s *Service) confirmTarget(network string, override *uint64) uint64 {
	if override != nil {
		return *override
	}
	name := s.networkName(network)
	if n, ok := s.cfg.Networks[name]; ok && n.Confirmations > 0 {
		return uint64(n.Confirmations)
	}
	return 1
}

// emitConfirmation fires an EvConfirmation progress event (stderr; §5.9). --json
// stdout carries one final object — the renderer, not this sink, enforces that.
func emitConfirmation(sink domain.EventSink, hash common.Hash, conf, target uint64) {
	domain.Emit(sink, domain.Event{
		Kind:   domain.EvConfirmation,
		Hash:   hash.Hex(),
		Conf:   conf,
		Target: target,
		Stream: "stderr",
	})
}

// ── pure projections ─────────────────────────────────────────────────────────

// txRow maps a journal record into the `tx list` wire row.
func txRow(r *journal.Record) domain.TxRow {
	row := domain.TxRow{
		JournalID: r.ID,
		Hash:      r.TxHash,
		Kind:      string(r.Kind),
		Status:    string(r.Status),
		From:      r.From,
		To:        r.To,
		Nonce:     r.Nonce,
		ValueWei:  r.ValueWei,
		TS:        r.TS,
		Network:   r.Network,
	}
	if r.Replaces != nil {
		row.Replaces = *r.Replaces
	}
	if r.ReplacedBy != nil {
		row.ReplacedBy = *r.ReplacedBy
	}
	return row
}

// wireStatus maps a journal status to the wire TxStatus (the §5.2 four-value
// enum; intermediate journal states fold to pending).
func wireStatus(st journal.Status) domain.TxStatus {
	switch st {
	case journal.StatusConfirmed:
		return domain.TxStatusConfirmed
	case journal.StatusReverted:
		return domain.TxStatusReverted
	case journal.StatusReplaced:
		return domain.TxStatusReplaced
	default:
		return domain.TxStatusPending
	}
}

// gasResultFromFees rebuilds the wire GasResult from a journal Fees block (for the
// status/list views, which have no live Quote).
func gasResultFromFees(f journal.Fees) domain.GasResult {
	r := domain.GasResult{Legacy: f.Type == "legacy", GasLimit: f.GasLimit, Speed: f.Speed}
	if f.GasPrice != nil {
		r.GasPrice = *f.GasPrice
	}
	if f.MaxFeePerGas != nil {
		r.MaxFeePerGas = *f.MaxFeePerGas
	}
	if f.MaxPriorityPerGas != nil {
		r.PriorityFee = *f.MaxPriorityPerGas
	}
	return r
}

// journalReceipt projects a geth receipt into the §5.6 journal Receipt block.
func journalReceipt(rcpt *types.Receipt) *journal.Receipt {
	if rcpt == nil {
		return nil
	}
	egp := "0"
	if rcpt.EffectiveGasPrice != nil {
		egp = rcpt.EffectiveGasPrice.String()
	}
	return &journal.Receipt{
		BlockNumber:       rcpt.BlockNumber.Uint64(),
		BlockHash:         rcpt.BlockHash.Hex(),
		GasUsed:           rcpt.GasUsed,
		EffectiveGasPrice: egp,
		Status:            rcpt.Status,
	}
}

// actualGas = gasUsed × effectiveGasPrice (the value SettleActual shrinks the
// reservation to, §5.4).
func actualGas(rcpt *types.Receipt) *big.Int {
	if rcpt == nil || rcpt.EffectiveGasPrice == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Mul(new(big.Int).SetUint64(rcpt.GasUsed), rcpt.EffectiveGasPrice)
}

// bigOrZero parses a decimal string into a *big.Int, returning 0 for an empty or
// malformed value (journal quantities are always well-formed; this is defensive).
func bigOrZero(s string) *big.Int {
	if s == "" {
		return big.NewInt(0)
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return big.NewInt(0)
	}
	return v
}

// parseHash parses a 0x tx hash, mapping a malformed value to a usage error.
func parseHash(s string) (common.Hash, error) {
	if len(s) < 2 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return common.Hash{}, domain.Newf(domain.CodeUsage+".bad_hash", "invalid tx hash %q (want 0x…)", s)
	}
	if len(s) != 66 {
		return common.Hash{}, domain.Newf(domain.CodeUsage+".bad_hash", "invalid tx hash %q (want 32 bytes)", s)
	}
	return common.HexToHash(s), nil
}

// decodeHex decodes a 0x-prefixed hex string to bytes.
func decodeHex(s string) ([]byte, error) {
	if len(s) >= 2 && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	if len(s)%2 != 0 {
		return nil, errBadHex
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := hexVal(s[i*2])
		lo, ok2 := hexVal(s[i*2+1])
		if !ok1 || !ok2 {
			return nil, errBadHex
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

var errBadHex = errors.New("invalid hex")
