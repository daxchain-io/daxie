package service

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/daxchain-io/daxie/internal/chain"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/ethunit"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/policy"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// tx.go is the M3 ETH transaction pipeline: the §2.7 authorize/settle/abort
// kernel, the §5.1 SendTx stage machine + deferred-abort commit lifecycle, the
// broadcast-error taxonomy, and the destination resolver. RBF (Speedup/Cancel)
// in rbf.go and the wait state machine in txstatus.go reuse this kernel
// wholesale.
//
// The ONE non-negotiable ordering (§5.1, the "crash to reset counters" defense):
//
//	acquire account lock → derive nonce → policy.Reserve (DURABLE, before sign)
//	  → Signer.SignTx → journal.Append(status=signed, raw_tx, reservation_id)
//	  → broadcast → {accepted: SetState(broadcast)+reservation.Commit+lease.Commit
//	               | transport-exhausted: stays signed, lease.Commit
//	               | rejected: lease.Release(nonce untouched)+SetState(failed)+Release}
//
// EvalContext-prefetch (the base fee, the gas quote, the destination) happens
// BEFORE the spend lock (§2.7), so the locked window is bounded and
// non-interactive. The deferred abort guarantees exactly-one-of settle/abort for
// the live process; reconciliation (reconcile.go) handles a crash.

// Intent is the fully-resolved, network-prefetched send the kernel signs.
// SendTx/Speedup/Cancel each build one and hand it to authorize. It is an
// internal type — it never crosses the wire (it holds a dialed client + the
// signing ref).
type Intent struct {
	chainID *big.Int
	network string
	rpc     string
	cc      chain.Client // the dialed client (caller owns Close)

	from common.Address
	ref  domain.AccountRef // the signing ref (for Signer.SignTx)
	dest domain.Dest       // resolved To + the human name it came from

	to    common.Address
	value *big.Int
	data  []byte // calldata (empty for plain ETH)

	// policyDest is the policy allowlist SUBJECT: the decoded recipient (an ERC-20
	// transfer) or the spender (an approval). For a plain ETH send it equals `to`.
	// For a token op it is NEVER the token contract (`to`) — the contract is identity-
	// checked, the human flow of value goes to the recipient/spender (§4.2/§5.1). It
	// is the zero address for paths that never set it (then authorize falls back to
	// `to`, the correct value for ETH).
	policyDest common.Address
	// policyKind selects the Check kind for a non-ETH op: policyKindApprove routes a
	// token approval/revoke through KindApprove (the spend-equivalent gates). The
	// zero value (policyKindDefault) leaves the kind to the journal.Kind mapping.
	policyKind policyKind
	// tokenAmt / unlimited / acked carry the §4.2 token-op fields into the Check:
	// tokenAmt is the raw base-unit amount (display only — SpendWei stays 0 for token
	// ops, no price oracle); unlimited is the 2^256-1 sentinel match; acked is the
	// --unlimited --yes ceremony bit. All zero for a plain ETH send.
	tokenAmt  *big.Int
	unlimited bool
	acked     bool

	kind  journal.Kind
	asset journal.Asset
	// assetSymbol is the token's display symbol carried into the result Asset block
	// (the journal.Asset has no symbol field). Empty for ETH.
	assetSymbol string

	gas Quote // the built gas quote (limit + fees) — filled by buildGas

	nonce    *uint64 // forced --nonce (RBF pins it), else nil (derived under lock)
	replaces *string // RBF cross-link (speedup/cancel), else nil

	source   string // "cli" | "mcp"
	unlocker domain.Unlocker
}

// policyKind selects how an Intent maps to the policy.Check kind. policyKindDefault
// leaves it to the journal.Kind string mapping (ETH/token transfers → KindTransfer);
// policyKindApprove forces KindApprove (the approval spend-equivalent gates).
type policyKind int

const (
	policyKindDefault policyKind = iota
	policyKindApprove
)

// checkDest returns the policy allowlist subject for this Intent: the explicit
// policyDest (a token transfer's recipient / an approval's spender) when set, else
// `to` (a plain ETH send's recipient). NEVER the token contract for a token op
// (the token paths set policyDest to the decoded recipient/spender, §4.2/§5.1).
func (in *Intent) checkDest() common.Address {
	if in.policyDest != (common.Address{}) {
		return in.policyDest
	}
	return in.to
}

// applyDestProvenance is the §4.3 STAGE-4 PIN-DRIFT PRODUCER (the one load-bearing
// M7 wiring): it sets the Check's ToSrc/ToInput/ENSName/ENSResolved/Dest from the
// resolved destination's provenance so the engine's already-existing pin-drift gate
// fires correctly. The engine compares only — it does no network I/O; this supplies
// the fresh resolution + the allow-time pin.
//
// The subtle reconciliation (design §4.3 stages 3+4, plan §3-B): both stages read
// Check.Dest but with opposite meanings — stage 3 (allowlist) matches Dest against a
// pinned address; stage 4 (pin_drift) treats Dest as the allow-time PIN and
// ENSResolved as the FRESH resolution. They reconcile only if, for a pinned ENS/
// contact name, Check.Dest = the ALLOW-TIME PIN (so stage 3 matches the pinned entry
// and the refusal surfaces as pin_drift, which §4.9 ranks BELOW allowlist — Dest=pin
// keeps stage 3 passing so pin_drift is the only gate that fires) and
// Check.ENSResolved = the fresh resolution. When NO pin exists for the name, both are
// set to the fresh resolution so stage 4 is a no-op (fresh==fresh, no false drift).
//
// fresh is the per-invocation resolution already done pre-lock (in.checkDest()); no
// second network call happens here (the §4.3 invariant: no I/O inside the lock).
func (s *Service) applyDestProvenance(check *policy.Check, in *Intent) error {
	fresh := in.checkDest()
	switch in.dest.Via {
	case "ens":
		check.ToSrc = policy.SourceENS
		check.ENSName = in.dest.ENSName
		check.ToInput = in.dest.ENSName
		check.ENSResolved = fresh
		// Look up the allow-time pin for this ENS name. If found, Dest = the pin (stage
		// 3 matches it; stage 4 compares fresh vs pin → ens_drift on a re-point). If
		// absent, Dest = fresh (stage 4 no-op). A halted seal fails closed.
		pin, found, err := s.policy.AllowlistPin("ens", in.dest.ENSName)
		if err != nil {
			return err
		}
		if found {
			check.Dest = pin
		} else {
			check.Dest = fresh
		}
	case "contact":
		check.ToSrc = policy.SourceContact
		check.ToInput = in.dest.Name
		check.ENSResolved = fresh
		pin, found, err := s.policy.AllowlistPin("contact", in.dest.Name)
		if err != nil {
			return err
		}
		if found {
			check.Dest = pin
		} else {
			check.Dest = fresh
		}
	default:
		// literal 0x / self / RBF-built: a raw address cannot drift — leave ToSrc as
		// SourceRawAddress (the zero value) and Dest as the literal recipient.
		check.ToSrc = policy.SourceRawAddress
	}
	return nil
}

// checkAsset returns the policy Asset tag: "eth" for a plain ETH send (no
// data/approval), else the lowercase token contract address. The stage-3c
// fail-closed rule + isTokenOrApproval read this (a non-"eth" Asset marks a
// token/approval op), so a token transfer/approval fires the fail-closed-no-
// allowlist gate (§4.3).
func (in *Intent) checkAsset() string {
	if in.isTokenOp() {
		return strings.ToLower(in.to.Hex())
	}
	return "eth"
}

// tokenTag returns the policy Token field: the lowercase token contract for a
// token/approval op (the per-token rule key the unlimited hard-deny + stage-3c
// read), else "" (a plain ETH send carries no token tag). It is the lowercase
// contract for the SAME reasons checkAsset is — both are set so isTokenOrApproval
// fires on either field.
func (in *Intent) tokenTag() string {
	if in.isTokenOp() {
		return strings.ToLower(in.to.Hex())
	}
	return ""
}

// isTokenOp reports whether this Intent is a token/NFT transfer or an approval
// (not a plain ETH send). A token/NFT transfer carries non-empty calldata to the
// asset contract under a recognized token-class kind; an approval is
// policyKindApprove. A plain ETH send has neither.
//
// M6: an ERC-721/1155 NFT send is a token-class op (non-empty safeTransferFrom
// calldata + kind erc721/1155-transfer), so checkAsset()/tokenTag() return the
// COLLECTION contract (a non-"eth" Asset) and the §4.3 stage-3c fail-closed-no-
// allowlist gate fires for it — "ETH exempt, NFT NOT" (design §4.3). A plain ETH
// send is the only broadcasting path that stays Asset="eth".
func (in *Intent) isTokenOp() bool {
	if in.policyKind == policyKindApprove {
		return true
	}
	if len(in.data) == 0 {
		return false
	}
	switch in.kind {
	case journal.KindERC20Transfer, journal.KindERC721Transfer, journal.KindERC1155Transfer:
		return true
	}
	return false
}

// policyCheckKind maps the Intent's policyKind to the policy.Check Kind string the
// engine's effectiveKind() reads. policyKindApprove → "approve" (→ KindApprove);
// default → the journal.Kind string (ETH/erc20 transfers → KindTransfer).
func (in *Intent) policyCheckKind() string {
	if in.policyKind == policyKindApprove {
		return "approve"
	}
	return string(in.kind)
}

// authorized is what the kernel returns (§2.7): a signed, journaled,
// reservation-backed tx ready to broadcast, with the account lock still held so
// settle/abort can commit/release it.
type authorized struct {
	raw         []byte
	hash        common.Hash
	nonce       uint64
	chainID     uint64 // carried so settle/abort can address the journal (Lease keeps it private)
	journalID   string
	reservation policy.Reservation
	lease       *journal.Lease // held account lock; settle/abort commit/release it
}

// broadcastOutcome classifies a broadcast result so SendTx drives the §5.1
// {accepted | transport-exhausted | rejected} branch.
type broadcastOutcome int

const (
	// outcomeAccepted: accepted / already-known / ours-mined-race — the chain has
	// (or will have) the tx. SetState(broadcast) + reservation.Commit + lease.Commit.
	outcomeAccepted broadcastOutcome = iota
	// outcomeTransportExhausted: transport/5xx/timeout after backoff — the tx MAY
	// have reached the mempool. Record stays `signed` (no recorded broadcast);
	// lease.Commit (the nonce is consumed-or-recoverable). Recovery resurrects it.
	outcomeTransportExhausted
	// outcomeRejected: permanently refused (replaced / underpriced / insufficient
	// funds). lease.Release (nonce never burned) + SetState(failed) + Release.
	outcomeRejected
	// outcomeNonceTooLow: the node reports "nonce too low". This is the §5.1
	// race-with-self case: our OWN tx may have already mined at this nonce (a prior
	// attempt that actually landed, or a sibling daxie process that broadcast OUR
	// bytes). runSend MUST re-fetch our receipt first — present ⇒ accepted (exit 0,
	// the nonce was consumed BY US); absent ⇒ tx.replaced (exit 9, a different tx
	// consumed it). It is never terminalized blindly.
	outcomeNonceTooLow
)

// SendTx is THE pipeline (§5.1). It resolves the destination, prefetches the gas
// quote (BEFORE the lock), runs the optional TTY confirmation, then enters the
// bounded locked critical section via authorize, broadcasts, settles/aborts, and
// optionally waits.
func (s *Service) SendTx(ctx context.Context, p domain.Principal, req domain.TxRequest, sink domain.EventSink) (domain.TxResult, error) {
	in, err := s.resolveIntent(ctx, p, req, sink)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer in.cc.Close()

	// ── preview build: the gas quote the user/agent sees BEFORE the lock (§5.1) ──
	if err := s.previewGas(ctx, &in, req, sink); err != nil {
		return domain.TxResult{}, err
	}

	// ── --dry-run: policy.Evaluate (no reservation), print, stop before sign ──
	if req.DryRun {
		return s.dryRun(ctx, &in)
	}

	// Resolve the signing passphrase (held for the minimum window; zeroed on
	// defer). Only the signing path reaches here — dry-run returned above.
	unlocker, zero, err := s.withUnlocker(false)
	if err != nil {
		return domain.TxResult{}, err
	}
	defer zero()
	in.unlocker = unlocker

	// ── the locked critical section: authorize → broadcast → settle/abort ──
	return s.runSend(ctx, p, &in, req.Wait, sink)
}

// runSend is the shared locked-send body used by SendTx and RBF (rbf.go): it
// authorizes (lock+nonce+reserve+sign+journal), broadcasts, and settles/aborts
// with the deferred exactly-once guarantee, then optionally waits.
func (s *Service) runSend(ctx context.Context, p domain.Principal, in *Intent, wait domain.WaitOpts, sink domain.EventSink) (domain.TxResult, error) {
	a, err := s.authorize(ctx, p, *in, sink)
	if err != nil {
		return domain.TxResult{}, err
	}

	// The deferred abort guarantees exactly-one-of settle/abort for the live
	// process: settled is flipped true by the success path; if it never is (a
	// panic, an early return on a build/broadcast failure), abort runs.
	settled := false
	defer func() {
		if !settled {
			_ = s.abort(ctx, a, errAbortIncomplete)
		}
	}()

	domain.Emit(sink, domain.Event{Kind: domain.EvSigned, Hash: a.hash.Hex(), Stream: "stderr"})

	outcome, berr := s.broadcast(ctx, in.cc, a)
	switch outcome {
	case outcomeAccepted:
		if serr := s.settle(ctx, a, a.hash, domain.TxStatusPending, nil); serr != nil {
			return domain.TxResult{}, serr
		}
		settled = true
		domain.Emit(sink, domain.Event{Kind: domain.EvBroadcast, Hash: a.hash.Hex(), Stream: "stderr"})

	case outcomeTransportExhausted:
		// The record stays `signed` (no recorded broadcast). The nonce lease is
		// committed (the tx may be in a mempool; recovery rebroadcasts the SAME
		// bytes). This is NOT a settle (no reservation.Commit) — but the lease
		// must commit. CRITICAL: mark settled BEFORE attempting lease.Commit so a
		// failed cache write here does NOT fall through to the deferred abort, which
		// would terminalize this `signed` record and lose the raw_tx + free its
		// nonce (the lost-broadcast window). The lease cache is an accelerator; the
		// journal `signed` record is the source of truth and stays recoverable
		// regardless. A failed Commit is surfaced (a wedged FS is visible) but never
		// destroys the recoverable record.
		settled = true
		_ = a.lease.Commit()
		// Surface the transport failure as the (retryable) result error so the
		// caller knows the broadcast is unconfirmed; the record is recoverable.
		return s.txResult(in, a, domain.TxStatusPending), berr

	case outcomeNonceTooLow:
		// §5.1 race-with-self: re-fetch OUR receipt FIRST. If our hash already mined,
		// the nonce was consumed BY US — this is a SUCCESS (settle, exit 0), not a
		// conflict. Only when no receipt of ours exists did a DIFFERENT tx consume the
		// nonce → tx.replaced (exit 9), and the deferred abort releases the lease (the
		// nonce is the sibling's, our bytes never landed) + reservation + marks failed.
		rcpt, rerr := in.cc.Receipt(ctx, a.hash)
		if rerr != nil && !errors.Is(rerr, chain.ErrTxNotFound) {
			// A transport error re-checking our receipt is itself retryable; leave the
			// record recoverable (signed/broadcast unchanged) rather than terminalizing
			// on an inconclusive check — commit the lease so the nonce is not re-derived
			// while our bytes may have landed, and surface the transport error.
			if cerr := a.lease.Commit(); cerr != nil {
				return domain.TxResult{}, cerr
			}
			settled = true
			return domain.TxResult{}, mapRPCErr(rerr)
		}
		if rcpt != nil {
			// Our tx mined at this nonce → accepted. Record the broadcast + commit the
			// reservation and lease exactly like the accepted path.
			st := domain.TxStatusPending
			var gasWei *big.Int
			if rcpt.Status == 0 {
				st = domain.TxStatusReverted
				// A revert settles gas to actual AND releases the native value (§4.4) —
				// pass the receipt's actual gas so SettleActual shrinks gas correctly.
				gasWei = actualGas(rcpt)
			}
			if serr := s.settle(ctx, a, a.hash, st, gasWei); serr != nil {
				return domain.TxResult{}, serr
			}
			settled = true
			domain.Emit(sink, domain.Event{Kind: domain.EvBroadcast, Hash: a.hash.Hex(), Stream: "stderr"})
			if st == domain.TxStatusReverted {
				return s.txResult(in, a, st), domain.New(domain.CodeTxReverted, "transaction reverted on-chain")
			}
			// Fall through to the wait/result tail below.
			break
		}
		// No receipt of ours → a different tx consumed the nonce. tx.replaced (exit 9);
		// the deferred abort frees the lease (nonce untouched) + reservation + failed.
		return domain.TxResult{}, berr

	case outcomeRejected:
		// abort runs via defer (settled stays false): lease.Release (nonce
		// untouched) + SetState(failed) + reservation.Release.
		return domain.TxResult{}, berr
	}

	res := s.txResult(in, a, domain.TxStatusPending)

	// ── optional wait (§5.3) — runs AFTER the lock is released (settle freed it) ──
	if wait.Enabled {
		wres, werr := s.waitOnHash(ctx, p, in.cc, in.network, a.hash, a.journalID, in.chainID, wait, sink)
		// waitOnHash rebuilds To from the journal record (a bare 0x address — the
		// journal never stores the human provenance), which would drop the ENS/contact
		// Via+ENSName the resolved-address echo carried (§4.8: the result block surfaces
		// the name the agent/human sent to). Re-overlay the in-memory dest provenance
		// when the resolved address still matches, on BOTH the success and the error
		// (e.g. reverted/timeout) result so the rendered destination is consistent.
		wres.To = overlayDestProvenance(wres.To, in.dest)
		if werr != nil {
			return wres, werr
		}
		return wres, nil
	}
	return res, nil
}

// authorize is the §2.7 privileged kernel. The prefetch (base fee, gas quote,
// destination) happened in the caller; here it takes the account lock, derives
// (or pins) the nonce, runs policy.Reserve (durable, BEFORE sign), signs, and
// journals status=signed with the full raw_tx + reservation_id. It does NOT
// broadcast — a signed tx is already authorized. Lock ordering is account →
// journal (the lease holds the account lock; journal.Append takes the journal
// flock under it).
func (s *Service) authorize(ctx context.Context, p domain.Principal, in Intent, sink domain.EventSink) (authorized, error) {
	chainID := in.chainID.Uint64()
	lockTimeout := s.cfg.Tx.LockTimeout

	// §5.6: restart reconciliation runs at the send lock acquisition — resurrect any
	// crash-left `signed` record (a transport-exhausted prior send whose bytes may be
	// in a mempool) through the shared receipt-first helper BEFORE we acquire the
	// account lock + derive the nonce, so the nonce fold sees the reconciled state.
	// It takes only the journal flock (never the account lock), so running it here
	// preserves the account→journal lock ordering. Best-effort; never blocks the send.
	s.resurrectUnresolved(ctx, in.cc, chainID)

	// chainPending feeds the §5.6 NextNonce derivation (max(chainPending,
	// localNext, journalNext)). Read it BEFORE taking the lock (prefetch) so the
	// locked window stays bounded; the lease re-derives under the lock.
	chainPending, err := in.cc.Nonce(ctx, in.from, true)
	if err != nil {
		return authorized{}, mapRPCErr(err)
	}

	// ── acquire account lock → derive nonce (the lease holds the lock) ──
	lease, err := s.nonce.AcquireNonce(ctx, chainID, in.from, chainPending, in.nonce, lockTimeout)
	if err != nil {
		return authorized{}, err // state.lock_timeout (exit 11) on contention
	}
	nonce := lease.Nonce()

	// From here on, ANY failure must Release the lease (nonce never burned). We
	// release inline on the pre-journal failures; once the signed record exists,
	// the caller's settle/abort owns the lease.

	// ── policy.Reserve: DURABLE spend reservation, BEFORE sign (§5.1) ──
	worst := in.gas.WorstCaseGasWei
	if worst == nil {
		worst = big.NewInt(0)
	}
	check := policy.Check{
		Account: in.from,
		// §4.2/§5.1: the policy allowlist subject is the DECODED recipient (an ERC-20
		// transfer) / SPENDER (an approval) — NEVER the token contract. checkDest
		// returns in.policyDest when set, else in.to (the plain-ETH recipient).
		Dest: in.checkDest(),
		// SpendWei is the ETH-denominated native value ONLY (§4.2). A token op carries
		// no ETH value (in.value == 0) and no price oracle exists, so a token amount is
		// NEVER written here — it rides in TokenAmt (display) instead.
		SpendWei:     in.value,
		MaxGasWei:    worst,
		MaxFeePerGas: perGasPrice(in.gas),
		// Kind routes the §4.3 gates: a token approval/revoke → "approve" (KindApprove,
		// the spend-equivalent gates); ETH/token transfers → KindTransfer.
		Kind:       in.policyCheckKind(),
		IsRBFDelta: in.replaces != nil,
		// M4 additive wiring (§4.1/§4.3): the per-network spend bucket + rule key.
		// Without Network the rolling-24h counter file path and the per-network limit
		// overrides cannot key correctly. Sepolia spends never consume mainnet headroom.
		Network: in.network,
		// Token/Asset carry the lowercase token contract for a token/approval op (else
		// "eth"). The stage-3c fail-closed rule + isTokenOrApproval read these — set
		// BOTH so a token transfer/approval fires the fail-closed-no-allowlist gate.
		Token:    in.tokenTag(),
		Asset:    in.checkAsset(),
		TokenAmt: in.tokenAmt, // raw base units, display only (§4.2)
		// §4.2 unlimited ceremony: Unlimited is the 2^256-1 sentinel match; Acked is the
		// --unlimited --yes acknowledgement. The engine's stage-6 unlimited gate reads
		// both — an unacked unlimited approval is denied unlimited_unacked (exit 3).
		Unlimited: in.unlimited,
		Acked:     in.acked,
		// §4.4/§5.5 RBF supersession: EVERY send carries its pinned account_nonce so
		// the counter entry is keyed by (network, from, account_nonce). The original
		// send must store it so a later speedup/cancel (IsRBFDelta) can fold its
		// candidate into the SAME entry (max-across-candidates) instead of
		// double-counting value+gas in the rolling-24h window.
		AccountNonce: &nonce,
	}
	// §4.3 stage-4 producer (M7): set ToSrc/ENSName/ToInput/ENSResolved + (for a
	// pinned name) Dest=the allow-time pin, so a re-pointed ENS/contact name is
	// refused with policy.denied.pin_drift. A halted seal fails closed here.
	if err := s.applyDestProvenance(&check, &in); err != nil {
		_ = lease.Release()
		return authorized{}, err
	}
	reservation, err := s.policy.Reserve(ctx, check)
	if err != nil {
		_ = lease.Release()
		// §4.9 gas_cap: the engine is base-fee-blind (pure); the service overlays the
		// LIVE base fee so the caller distinguishes "fee spike, retry" from "my flags
		// are wrong". A no-op for every other denial code.
		return authorized{}, overlayBaseFee(err, in.gas.BaseFee) // policy.denied.* (exit 3) — nothing signed
	}
	domain.Emit(sink, domain.Event{Kind: domain.EvPolicyOK, Stream: "stderr"})

	// ── Signer.SignTx (the passphrase flows via in.unlocker) ──
	txObj := buildTx(in, nonce)
	raw, hash, err := s.signer.SignTx(ctx, in.ref, txObj, in.chainID, in.unlocker)
	if err != nil {
		_ = s.policy.Release(ctx, reservation.ID)
		_ = lease.Release()
		return authorized{}, err
	}

	// ── journal.Append(status=signed, raw_tx, reservation_id) BEFORE broadcast ──
	rec := s.signedRecord(in, nonce, hash, raw, reservation.ID, worst)
	if err := s.journal.Append(ctx, rec); err != nil {
		// The signed bytes were not journaled — recovery cannot resurrect them,
		// so this is a hard pre-broadcast failure: release the reservation + lease
		// (nothing reached the chain).
		_ = s.policy.Release(ctx, reservation.ID)
		_ = lease.Release()
		return authorized{}, err
	}

	return authorized{
		raw:         raw,
		hash:        hash,
		nonce:       nonce,
		chainID:     chainID,
		journalID:   rec.ID,
		reservation: reservation,
		lease:       lease,
	}, nil
}

// settle finalizes an accepted send (§5.1): journal SetState(broadcast),
// reservation.Commit(hash), and the nonce lease Commit (which releases the lock).
// The optional gasWei + a confirmed status drive policy.SettleActual (§5.3).
func (s *Service) settle(ctx context.Context, a authorized, h common.Hash, st domain.TxStatus, gasWei *big.Int) error {
	chainID := a.chainID

	// Map the wire status to the journal status for this transition.
	jstatus := journal.StatusBroadcast
	switch st {
	case domain.TxStatusConfirmed:
		jstatus = journal.StatusConfirmed
	case domain.TxStatusReverted:
		jstatus = journal.StatusReverted
	}

	mut := journal.StateMutation{Status: jstatus}
	hh := h.Hex()
	mut.TxHash = &hh
	if err := s.journal.SetState(ctx, chainID, a.journalID, mut); err != nil {
		return err
	}

	if err := s.policy.Commit(ctx, a.reservation.ID, h); err != nil {
		return err
	}
	// SettleActual shrinks the committed reservation's gas to actual on a settled
	// receipt, and on a REVERT also releases the native value (§4.4: the EVM did not
	// move it). Confirmed and reverted both settle gas; only reverted releases value.
	switch st {
	case domain.TxStatusConfirmed:
		if gasWei != nil {
			_ = s.policy.SettleActual(ctx, a.reservation.ID, gasWei, false)
		}
	case domain.TxStatusReverted:
		_ = s.policy.SettleActual(ctx, a.reservation.ID, gasWei, true)
	}

	// Commit the nonce lease (next = nonce+1) and release the account lock.
	return a.lease.Commit()
}

// abort is the deferred exactly-once partner of settle (§5.1). It is destructive
// ONLY before a broadcast has been RECORDED: it must NEVER terminalize a record
// that already shows a recorded broadcast, because that would free a nonce whose
// tx is genuinely on the chain and will mine — the classic double-allocation the
// journal-as-source-of-truth design exists to prevent.
//
// It reads the record's CURRENT latest status under the journal lock and branches:
//
//   - status == `signed` (no recorded broadcast) ⇒ the genuine refusal/incomplete
//     path: SetState(failed) + reservation.Release + lease.Release (nonce never
//     burned on a refusal);
//   - status is broadcast/pending/mined/confirmed (the spend is DURABLE) ⇒ the
//     deferred abort fired after settle recorded the broadcast but a later
//     policy/lease commit failed: do NOT terminalize and do NOT release the
//     reservation — COMMIT the lease (the nonce is spent) and leave the record +
//     reservation intact so the next derivation cannot re-allocate the nonce;
//   - status is terminal (failed/reverted/replaced) ⇒ already resolved: just
//     release the lock (Release; the cache write is irrelevant either way).
//
// This guard makes the deferred abort safe under EVERY settle-failure-after-
// broadcast crash-matrix case.
func (s *Service) abort(ctx context.Context, a authorized, reason error) error {
	if a.lease == nil {
		return nil // nothing was acquired
	}
	chainID := a.chainID

	// Read the record's current latest status (it may have advanced to `broadcast`
	// inside a partially-completed settle). A missing/unreadable record is treated
	// as `signed` (the safe, pre-broadcast assumption) so a genuine pre-broadcast
	// failure still releases.
	status := journal.StatusSigned
	if a.journalID != "" {
		if rec, rerr := s.journal.ByID(ctx, chainID, a.journalID); rerr == nil && rec != nil {
			status = rec.Status
		}
	}

	// A recorded broadcast means the spend is DURABLE: never terminalize, never
	// release the reservation, and COMMIT (not release) the lease — the nonce is
	// consumed and must not be re-allocated.
	if status != journal.StatusSigned && status != journal.StatusFailed {
		return a.lease.Commit()
	}

	// No recorded broadcast (signed) — the genuine refusal/incomplete path.
	if a.journalID != "" && status == journal.StatusSigned {
		msg := ""
		if reason != nil {
			msg = reason.Error()
		}
		mut := journal.StateMutation{Status: journal.StatusFailed}
		if msg != "" {
			mut.Error = &msg
		}
		_ = s.journal.SetState(ctx, chainID, a.journalID, mut)
	}
	if a.reservation.ID != "" {
		_ = s.policy.Release(ctx, a.reservation.ID)
	}
	// Release the lease LAST (account lock freed, nonce file untouched).
	return a.lease.Release()
}

// broadcast submits a.raw and normalizes the §5.1 broadcast error taxonomy into
// a broadcastOutcome + a mapped error. It retries transport failures with 1s/2s/4s
// backoff before declaring transport-exhausted. The classification is by the
// canonical geth/erigon/nethermind error strings.
func (s *Service) broadcast(ctx context.Context, cc chain.Client, a authorized) (broadcastOutcome, error) {
	backoffs := []time.Duration{0, 1 * time.Second, 2 * time.Second, 4 * time.Second} // immediate, then 1s/2s/4s
	var lastErr error
	for _, d := range backoffs {
		if d > 0 {
			if err := s.sleep(ctx, d); err != nil {
				return outcomeTransportExhausted, mapRPCErr(err)
			}
		}
		_, err := cc.SendRawTransaction(ctx, a.raw)
		if err == nil {
			return outcomeAccepted, nil
		}
		lastErr = err
		outcome, mapped, retry := classifyBroadcastErr(err)
		if !retry {
			return outcome, mapped
		}
		// transport/5xx/timeout → retry (unless this was the last attempt)
	}
	// Backoff exhausted: leave the record `signed` (recovery resurrects it).
	return outcomeTransportExhausted, domain.Wrap(domain.CodeRPCUnreachable,
		"broadcast unconfirmed after retries: "+lastErr.Error(), lastErr)
}

// classifyBroadcastErr maps an eth_sendRawTransaction error to the §5.1 taxonomy.
// It returns the outcome, the mapped error, and whether the caller should retry
// (transport class). "already known" is handled by the caller as success only —
// here it returns accepted with a nil error so the no-retry path treats it so.
func classifyBroadcastErr(err error) (broadcastOutcome, error, bool) {
	msg := lowerErr(err)
	switch {
	case containsAny(msg, "already known", "already exists", "transaction already in pool", "alreadyknown"):
		// The mempool already has it — success, ride the existing broadcast.
		return outcomeAccepted, nil, false
	case containsAny(msg, "nonce too low", "nonce is too low", "oldnonce"):
		// The nonce is already consumed on-chain. §5.1 race-with-self: the caller
		// (runSend) MUST re-fetch OUR receipt first — if our hash mined, the nonce
		// was consumed BY US (success); only when no receipt of ours exists is it a
		// genuine tx.replaced (exit 9). We carry the tx.replaced error as the
		// no-receipt verdict; the caller overrides it on a found receipt.
		return outcomeNonceTooLow, domain.Wrap(domain.CodeTxReplaced,
			"nonce already consumed (replaced): "+err.Error(), err), false
	case containsAny(msg, "replacement transaction underpriced", "replacement underpriced"):
		return outcomeRejected, domain.Wrap(domain.CodeTxReplacementUnderpriced,
			"replacement underpriced: "+err.Error(), err), false
	case containsAny(msg, "insufficient funds"):
		return outcomeRejected, domain.Wrap(domain.CodeFundsInsufficient,
			"insufficient funds: "+err.Error(), err), false
	case containsAny(msg, "transaction underpriced", "fee too low", "max fee per gas less than block base fee"):
		// Underpriced (not a replacement) — a permanent rejection for these fees.
		return outcomeRejected, domain.Wrap(domain.CodeTxReplacementUnderpriced,
			"transaction underpriced: "+err.Error(), err), false
	default:
		// transport / 5xx / timeout / context — retry, then transport-exhausted.
		return outcomeTransportExhausted, mapRPCErr(err), true
	}
}

// resolveIntent builds the prefetch-stage Intent (§2.7): it resolves From (the
// signing ref), the destination (To via 0x/contact/ENS), dials the endpoint, and
// reads the chain id + the value. ENS is M7 (fails clean); a contact name
// resolves via the registry.
func (s *Service) resolveIntent(ctx context.Context, p domain.Principal, req domain.TxRequest, sink domain.EventSink) (Intent, error) {
	// ── From: the signing ref (flag>env>meta.json default) ──
	fromStr := req.From
	if fromStr == "" {
		fromStr = s.activeDefault(ctx)
	}
	if fromStr == "" {
		return Intent{}, domain.New(domain.CodeUsage+".no_account",
			"no --from given and no default account set (run `daxie account use`)")
	}
	fromRef, err := domain.ParseAccountRef(fromStr)
	if err != nil {
		return Intent{}, err
	}
	from, err := s.keys.AddressOf(fromRef)
	if err != nil {
		return Intent{}, err
	}

	// ── To: resolve the destination (0x → contact → ENS) ──
	dest, err := s.resolveDest(ctx, ChainRequest{Network: req.Network, RPC: req.RPC}, req.To)
	if err != nil {
		return Intent{}, err
	}
	emitResolved(sink, dest.Address.Hex(), "to "+destLabel(dest))

	// ── dial + chain id ──
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return Intent{}, err
	}
	chainID, err := cc.ChainID(ctx)
	if err != nil {
		cc.Close()
		return Intent{}, mapRPCErr(err)
	}

	network := s.networkName(req.Network)
	source := sourceOf(p)

	// ── token transfer (--token): an ERC-20 send (§5.1) ──
	if strings.TrimSpace(req.Token) != "" {
		// Resolve the asset (registry-only alias resolution; a raw 0x reads decimals
		// on-chain for display). A miss is the anti-spoofing ref.not_found.
		ra, aerr := s.resolveAsset(ctx, cc, network, req.Token)
		if aerr != nil {
			cc.Close()
			return Intent{}, aerr
		}
		// The --amount is in TOKEN base units (no float; decimals applied via ethunit).
		amount, perr := ethunit.ParseTokenAmount(strings.TrimSpace(req.Amount), ra.decimals)
		if perr != nil {
			cc.Close()
			return Intent{}, domain.Wrap(domain.CodeUsage+".bad_amount", "invalid --amount "+req.Amount, perr)
		}
		// Build the ERC-20 transfer calldata: selector 0xa9059cbb || abi(recipient,
		// amount). The recipient is the DECODED dest — the policy subject — NOT the
		// token contract (§4.2/§5.1).
		data := s.erc.TransferCalldata(dest.Address, amount)
		decInt := int(ra.decimals)
		amtStr := amount.String()
		contractHex := strings.ToLower(ra.contract.Hex())
		return Intent{
			chainID: chainID,
			network: network,
			rpc:     req.RPC,
			cc:      cc,
			from:    from,
			ref:     fromRef,
			dest:    dest,
			to:      ra.contract,   // the tx goes TO the token contract
			value:   big.NewInt(0), // a token transfer carries no ETH
			data:    data,
			// THE policy subject = the decoded recipient (NOT the token contract).
			policyDest: dest.Address,
			tokenAmt:   new(big.Int).Set(amount),
			kind:       journal.KindERC20Transfer,
			asset: journal.Asset{
				Kind:     "erc20",
				Contract: &contractHex,
				Alias:    ra.alias,
				Decimals: &decInt,
				Amount:   &amtStr,
			},
			assetSymbol: ra.symbol,
			nonce:       req.Nonce,
			source:      source,
		}, nil
	}

	// ── plain ETH send ──
	value, err := parseEthAmount(req.Amount)
	if err != nil {
		cc.Close()
		return Intent{}, err
	}

	return Intent{
		chainID: chainID,
		network: network,
		rpc:     req.RPC,
		cc:      cc,
		from:    from,
		ref:     fromRef,
		dest:    dest,
		to:      dest.Address,
		value:   value,
		data:    nil, // plain ETH (contract calldata is M10)
		kind:    journal.KindETHTransfer,
		asset:   journal.Asset{Kind: "eth", Amount: strPtr(value.String())},
		nonce:   req.Nonce,
		source:  source,
		// unlocker is set by the caller (SendTx/RBF) just before the locked window
		// so the resolved passphrase is held for the minimum lifetime and zeroed on
		// defer; a read-only/dry-run path never resolves a passphrase.
	}, nil
}

// withUnlocker resolves the keystore passphrase via the §3.6 channels and builds
// the core-owned domain.Unlocker for a send, returning a zeroing cleanup the
// caller MUST defer. A raw-address --from cannot sign (LookupSigning rejects it),
// so this is reached only for keystore refs. The resolved *secret.Bytes is owned
// here and never logged/journaled (§3.10).
func (s *Service) withUnlocker(stdinTaken bool) (domain.Unlocker, func(), error) {
	pass, _, err := s.acquire(passphraseSpec(stdinTaken))
	if err != nil {
		return nil, func() {}, err
	}
	return serviceUnlocker{pass: pass}, func() { pass.Zero() }, nil
}

// previewGas builds the gas quote for the preview (§5.1: before the lock). It is
// the same buildGas the locked window re-runs; M3 keeps it simple (no
// confirm/drift loop in the non-interactive core path — the cli frontend owns
// the TTY confirmation, and a --yes/non-TTY send skips the drift check entirely,
// §5.1).
func (s *Service) previewGas(ctx context.Context, in *Intent, req domain.TxRequest, sink domain.EventSink) error {
	q, err := s.buildGas(ctx, in.cc, in, req)
	if err != nil {
		return err
	}
	in.gas = q
	emitEstimated(sink, "gas: limit "+utoa64(q.GasLimit)+" "+feeDetail(q))
	return nil
}

// dryRun runs the check-only policy verdict (no reservation, §5.1) and returns
// the previewed tx + verdict. A denied dry-run surfaces the policy error (exit 3).
func (s *Service) dryRun(ctx context.Context, in *Intent) (domain.TxResult, error) {
	worst := in.gas.WorstCaseGasWei
	if worst == nil {
		worst = big.NewInt(0)
	}
	check := policy.Check{
		Account: in.from,
		// Mirror authorize EXACTLY (§5.1: --dry-run runs the full verdict): the policy
		// dest is the decoded recipient/spender (NOT the token contract), the asset is
		// the token contract for a token op, and the kind routes the spend-equivalent
		// gates for an approval.
		Dest:         in.checkDest(),
		SpendWei:     in.value,
		MaxGasWei:    worst,
		MaxFeePerGas: perGasPrice(in.gas),
		Kind:         in.policyCheckKind(),
		IsRBFDelta:   in.replaces != nil,
		Network:      in.network, // M4: per-network bucket/rule key (§4.1)
		Token:        in.tokenTag(),
		Asset:        in.checkAsset(),
		TokenAmt:     in.tokenAmt,
		Unlimited:    in.unlimited,
		Acked:        in.acked,
		// §4.4/§5.5: carry the intended account_nonce so an RBF dry-run evaluates
		// against the superseded entry (in.nonce is the pinned nonce on the RBF path,
		// nil for a normal send — harmless then).
		AccountNonce: in.nonce,
	}
	// §4.3 stage-4 producer (M7): a --dry-run / `policy check` MUST run the same
	// pin-drift comparison the real send does, so an agent pre-flights a re-pointed
	// name and sees policy.denied.pin_drift before burning a signing attempt.
	if err := s.applyDestProvenance(&check, in); err != nil {
		return domain.TxResult{}, err
	}
	dec, err := s.policy.Evaluate(ctx, check)
	if err != nil {
		return domain.TxResult{}, err
	}
	if !dec.Allowed {
		code := dec.Code
		if code == "" {
			code = domain.CodePolicyDenied
		}
		de := domain.New(code, dec.Reason)
		if dec.Data != nil {
			de = domain.WithData(de, dec.Data) // carry the §4.9 per-code payload + violations
		}
		if dec.RetryAfter != "" {
			de = domain.WithData(de, map[string]any{"retry_after": dec.RetryAfter})
		}
		return domain.TxResult{}, overlayBaseFee(de, in.gas.BaseFee)
	}
	res := domain.TxResult{
		Network:   in.network,
		From:      in.from,
		To:        in.dest,
		Asset:     wireAsset(in.asset, in.assetSymbol),
		AmountWei: in.value.String(),
		Gas:       in.gas.result(),
		Status:    domain.TxStatusPending,
		DryRun:    true,
	}
	return res, nil
}

// txResult projects an authorized send into the wire TxResult.
func (s *Service) txResult(in *Intent, a authorized, st domain.TxStatus) domain.TxResult {
	return domain.TxResult{
		Hash:      a.hash.Hex(),
		Network:   in.network,
		From:      in.from,
		To:        in.dest,
		Asset:     wireAsset(in.asset, in.assetSymbol),
		AmountWei: in.value.String(),
		Nonce:     a.nonce,
		Gas:       in.gas.result(),
		Status:    st,
		JournalID: a.journalID,
	}
}

// overlayDestProvenance re-applies the in-memory destination provenance (Name/Via/
// ENSName) onto a result Dest that was rebuilt from a journal record (which stores
// only the resolved 0x address). It is a no-op unless the two addresses match — a
// guard so a re-derived result for a DIFFERENT tx (it never happens on this path,
// but the guard keeps the overlay honest) can never paint the wrong name onto an
// address. Used after waitOnHash so the §4.8 result block still shows the ENS/contact
// name the send was addressed to. When `mem` carries no provenance (a raw-address
// send / RBF), the journal-derived Dest is returned unchanged.
func overlayDestProvenance(fromRecord, mem domain.Dest) domain.Dest {
	if mem.Via == "" && mem.Name == "" && mem.ENSName == "" {
		return fromRecord
	}
	if fromRecord.Address != mem.Address {
		return fromRecord
	}
	fromRecord.Name = mem.Name
	fromRecord.Via = mem.Via
	fromRecord.ENSName = mem.ENSName
	return fromRecord
}

// signedRecord builds the journal Record for the status=signed append (§5.6).
func (s *Service) signedRecord(in Intent, nonce uint64, hash common.Hash, raw []byte, reservationID string, worst *big.Int) *journal.Record {
	rec := &journal.Record{
		V:               1,
		ChainID:         in.chainID.Uint64(),
		Network:         in.network,
		Kind:            in.kind,
		Status:          journal.StatusSigned,
		Source:          in.source,
		From:            in.from.Hex(),
		To:              in.to.Hex(),
		Nonce:           nonce,
		TxHash:          hash.Hex(),
		RawTx:           hexBytes(raw),
		ValueWei:        in.value.String(),
		Asset:           in.asset,
		Fees:            feesRecord(in.gas),
		ReservationID:   reservationID,
		WorstCaseGasWei: worst.String(),
		Replaces:        in.replaces,
		RPC:             in.rpc,
	}
	return rec
}

// ── pure helpers ─────────────────────────────────────────────────────────────

// errAbortIncomplete is the reason recorded when the deferred abort fires because
// settle never ran (a panic or an early failure return).
var errAbortIncomplete = errors.New("send did not complete; reservation released and nonce freed")

// buildTx constructs the unsigned *types.Transaction from an Intent + nonce. It
// emits a DynamicFeeTx (EIP-1559) unless the quote is legacy, in which case a
// LegacyTx. ChainID is set on the 1559 tx; the signer applies EIP-155 either way.
func buildTx(in Intent, nonce uint64) *types.Transaction {
	if in.gas.Legacy {
		return types.NewTx(&types.LegacyTx{
			Nonce:    nonce,
			GasPrice: in.gas.GasPrice,
			Gas:      in.gas.GasLimit,
			To:       addrPtr(in.to),
			Value:    in.value,
			Data:     in.data,
		})
	}
	return types.NewTx(&types.DynamicFeeTx{
		ChainID:   in.chainID,
		Nonce:     nonce,
		GasTipCap: in.gas.PriorityFee,
		GasFeeCap: in.gas.MaxFeePerGas,
		Gas:       in.gas.GasLimit,
		To:        addrPtr(in.to),
		Value:     in.value,
		Data:      in.data,
	})
}

// perGasPrice returns the per-gas price the policy gas-cap check uses:
// maxFeePerGas (1559) or gasPrice (legacy).
func perGasPrice(q Quote) *big.Int {
	if q.Legacy {
		return q.GasPrice
	}
	return q.MaxFeePerGas
}

// feesRecord projects a Quote into the §5.6 journal Fees block (decimal strings).
func feesRecord(q Quote) journal.Fees {
	f := journal.Fees{GasLimit: q.GasLimit, Speed: string(q.Speed)}
	if q.Legacy {
		f.Type = "legacy"
		if q.GasPrice != nil {
			gp := q.GasPrice.String()
			f.GasPrice = &gp
		}
	} else {
		f.Type = "eip1559"
		if q.MaxFeePerGas != nil {
			mf := q.MaxFeePerGas.String()
			f.MaxFeePerGas = &mf
		}
		if q.PriorityFee != nil {
			pf := q.PriorityFee.String()
			f.MaxPriorityPerGas = &pf
		}
	}
	return f
}

// wireAsset maps a journal.Asset (+ an in-memory display symbol, "" when none) into
// the wire domain.Asset. The journal record has no symbol field, so the live send
// path passes the resolved symbol; the status/list path (reading a journal record)
// passes "".
func wireAsset(a journal.Asset, symbol string) domain.Asset {
	out := domain.Asset{Kind: a.Kind, Symbol: symbol}
	if a.Contract != nil {
		out.Contract = *a.Contract
	}
	out.Decimals = a.Decimals
	return out
}

// parseEthAmount parses the --amount as ETH (the M3 native path). A bare number
// is ETH; an explicit unit suffix is honored. Empty/zero is allowed (a 0-value
// send is legal, e.g. a self-poke).
func parseEthAmount(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return big.NewInt(0), nil
	}
	value, unit := ethunit.SplitAmountUnit(s)
	u := ethunit.Eth
	if unit != "" {
		parsed, err := ethunit.ParseUnit(unit)
		if err != nil {
			return nil, domain.Newf(domain.CodeUsage+".bad_amount",
				"invalid amount unit in %q (want eth|gwei|wei)", s)
		}
		u = parsed
	}
	wei, err := ethunit.ParseAmount(value, u)
	if err != nil {
		return nil, domain.Wrap(domain.CodeUsage+".bad_amount", "invalid amount "+s, err)
	}
	return wei, nil
}

// overlayBaseFee enriches a policy.denied.gas_cap error with the LIVE network base
// fee (§4.9): the pure engine cannot see the base fee, so the service — which
// fetched it pre-lock for the gas estimate — overlays current_base_fee onto the
// denial payload so the caller distinguishes "fee spike, retry later" from "my
// flags are wrong". It is a no-op for a nil error, a non-domain error, any other
// code, or a nil base fee.
func overlayBaseFee(err error, baseFee *big.Int) error {
	if err == nil || baseFee == nil {
		return err
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodePolicyDeniedGasCap {
		return err
	}
	return domain.WithData(de, map[string]any{"current_base_fee": baseFee.String()})
}

// destLabel renders the destination echo: the contact/ENS name if present, else
// the address.
func destLabel(d domain.Dest) string {
	if d.Name != "" {
		return d.Name + " (" + d.Address.Hex() + ")"
	}
	return d.Address.Hex()
}

// feeDetail renders a short fee summary for the EvEstimated progress line.
func feeDetail(q Quote) string {
	if q.Legacy {
		if q.GasPrice != nil {
			return "gasPrice " + q.GasPrice.String()
		}
		return "legacy"
	}
	if q.MaxFeePerGas != nil {
		return "maxFee " + q.MaxFeePerGas.String()
	}
	return "1559"
}

// lowerErr returns a lowercased error string for taxonomy matching ("" for nil).
func lowerErr(err error) string {
	if err == nil {
		return ""
	}
	return strings.ToLower(err.Error())
}

// containsAny reports whether s contains any of the substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// hexBytes returns the 0x-prefixed hex of b (the raw_tx encoding).
func hexBytes(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 2+len(b)*2)
	out[0], out[1] = '0', 'x'
	for i, c := range b {
		out[2+i*2] = hexdigits[c>>4]
		out[2+i*2+1] = hexdigits[c&0xf]
	}
	return string(out)
}

// strPtr / utoa64.
func strPtr(s string) *string { return &s }

func utoa64(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
