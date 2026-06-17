// Package policy is the guardrail engine that runs in core, AHEAD of the signer
// (§2.7). M4 turns the M3 always-allow stub into the REAL engine: the sealed
// policy.json (Ed25519 over canonical body bytes + policy-anchor.json + the
// monotonic nonce watermark, §4.5/§4.6), the rolling-24h window counter (§4.1),
// the ETH per-tx/per-day limits, the fail-closed token rule (§4.3 stage 3c), the
// gas-cap check, the EIP-712 spend-equivalent recognizers (§4.2), gas accrual +
// cross-link release + SettleActual (§4.4) — WITHOUT changing any exported
// signature internal/service already calls. The M3 reservation lifecycle
// (reservation.go / orphan.go / id.go) is preserved verbatim — it is correct —
// and the rolling-24h counter (counter.go) is added alongside it as the window
// accumulator.
//
// SECURITY DIRECTION (the whole agent-safety story, fail-closed always):
//   - the seal is an admin-passphrase-derived Ed25519 SIGNATURE (scrypt→HKDF→
//     ed25519): the agent host VERIFIES with the pinned public key but CANNOT
//     forge (a symmetric MAC is WRONG and forbidden, §4.5).
//   - the verify-key pin lives in config-class policy-anchor.json, reachable by
//     NO Viper key/env/flag — passed in at Open by config (the engine never reads
//     it itself).
//   - load REFUSES body.nonce < anchor.watermark (anti-rollback) and REFUSES a
//     missing/unverifiable policy whenever an anchor exists ("delete the policy to
//     escape it" is itself a violation).
//   - counters are durable and reserved BEFORE sign; Release is valid ONLY
//     pre-signature (once signed, nothing at broadcast releases — over-count is
//     the safe direction).
//   - opt-in when no anchor: no anchor AND no policy ⇒ guardrails are a no-op
//     allow until the operator runs the first `policy set`.
//
// Dependency rules (§2.2, enforced by arch_test): policy imports policyseal, fsx,
// secret, domain. It NEVER imports journal (service bridges reconciliation, §5.1,
// because policy⊥journal), NEVER service, NEVER a frontend.
package policy

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/policyseal"
	"github.com/ethereum/go-ethereum/common"
)

// Engine is the policy provider. M4: the durable reservation store (the orphan
// source of truth, M3) + the per-(network,account) rolling-24h counter + the
// sealed policy file load/verify/watermark + the admin mutation surface. The
// state dir, clock, and the config-class anchor are injected at Open; the engine
// holds no other long-lived state (lazy on disk — it creates nothing until the
// first Reserve/Set, §7.3).
type Engine struct {
	dir         string            // the state-class root (<stateDir>)
	clock       func() time.Time  // injected wall clock; deterministic in tests, §2.4
	anchor      policyseal.Anchor // the trust root (config-class; read by config, passed in)
	anchorFound bool              // false ⇒ no anchor ⇒ opt-in no-op allow (until a policy exists)
	mu          sync.Map          // per-network in-process mutexes (taken before the flock)

	// accounts is the policy⊥keystore hook (§4.1 "Limit scope"): service injects a
	// function returning every keystore account on a network so the rolling-24h
	// window can AGGREGATE across all accounts (the unit of compromise is the
	// keystore passphrase, so a per-account cap would silently multiply the limit
	// by the account count). nil ⇒ the engine falls back to the signing account
	// alone (tests / pre-wiring). Mirrors how RefreshSelf is supplied to mutations.
	accounts func(network string) []common.Address
}

// SetAccountsHook installs the policy⊥keystore enumeration hook (§4.1). service
// calls this once after Open with a closure over its keystore so the aggregate
// rolling-24h window can sum across every account on a network. It is set-once at
// wiring time, before any Reserve/Evaluate, so no lock is needed.
func (e *Engine) SetAccountsHook(fn func(network string) []common.Address) {
	e.accounts = fn
}

// networkAccounts returns the full set of accounts whose in-window debits the
// aggregate daily window must include for this Check: every keystore account on
// the network (from the injected hook) PLUS the signing account (always, so a
// signer not yet in the snapshot still counts). De-duplicated, lowercased-keyed.
func (e *Engine) networkAccounts(network string, signer common.Address) []common.Address {
	seen := map[common.Address]bool{}
	var out []common.Address
	add := func(a common.Address) {
		if a == (common.Address{}) || seen[a] {
			return
		}
		seen[a] = true
		out = append(out, a)
	}
	if e.accounts != nil {
		for _, a := range e.accounts(network) {
			add(a)
		}
	}
	add(signer) // the signing account is always in the aggregate, hook or not
	return out
}

// aggregateWindow sums the rolling-24h in-window debits across EVERY account on
// the network (§4.1 aggregate-across-accounts), optionally EXCLUDING one counter
// entry by (account, entry-id) — the RBF superseded entry, whose contribution the
// caller re-adds as max(orig,new) so a speedup counts only the positive gas delta
// (§5.5). The caller MUST hold the per-network lock so the cross-account read is
// atomic against concurrent reserves. Returns the aggregate sum.
func (e *Engine) aggregateWindow(network string, signer common.Address, now time.Time, excludeAcct common.Address, excludeID string) (*big.Int, error) {
	sum := new(big.Int)
	for _, acct := range e.networkAccounts(network, signer) {
		cf, err := e.loadCounter(network, acct)
		if err != nil {
			return nil, err
		}
		if excludeID != "" && acct == excludeAcct {
			sum.Add(sum, sumWindowExcluding(cf, now, excludeID))
			continue
		}
		sum.Add(sum, sumWindow(cf, now))
	}
	return sum, nil
}

// Open binds the engine to the state dir, the injected clock, and the anchor.
// anchorFound==false AND no policy.json ⇒ guardrails opt-in (no-op allow,
// requirements §5). anchorFound==true ⇒ a missing/unverifiable policy is itself a
// violation (§4 intro). A nil clock defaults to time.Now (production wiring always
// passes the service clock so reservations + the rolling-24h window are
// reproducible in tests).
func Open(stateDir string, clock func() time.Time, anchor policyseal.Anchor, anchorFound bool) (*Engine, error) {
	if clock == nil {
		clock = time.Now
	}
	return &Engine{dir: stateDir, clock: clock, anchor: anchor, anchorFound: anchorFound}, nil
}

// Evaluate is the CHECK-ONLY path (no reservation written) — backs --dry-run and
// daxie policy check (§5.1), and the future authorizeSignature path. It runs the
// §4.3 stage-1 seal/freshness load, classification (pre-built in the Check),
// computes the rolling-24h window under the per-account read lock, and calls the
// pure Evaluate. NO durable write.
func (e *Engine) Evaluate(ctx context.Context, c Check) (Decision, error) {
	pol, present, err := e.loadActivePolicy()
	if err != nil {
		return Decision{}, err
	}
	if !present {
		// Opt-in: no anchor + no policy ⇒ guardrails not configured ⇒ allow.
		return Decision{Allowed: true}, nil
	}

	// Kill switch: messages:"deny" is handled at the SignMessage seam in service;
	// here we evaluate the tx/approval/permit path.

	var dec Decision
	if err := e.withNetworkLock(ctx, c.Network, func() error {
		cf, lerr := e.loadCounter(c.Network, c.Account)
		if lerr != nil {
			return lerr
		}
		now := e.now()
		// §4.1: the daily window is AGGREGATE across every account on the network,
		// not just the signing account — the unit of compromise is the keystore
		// passphrase. The cross-account read is atomic under the network lock.
		spent, rbf, serr := e.windowFor(c, cf, now)
		if serr != nil {
			return serr
		}
		dec = Evaluate(pol, c, spent, now)
		// Tighten day_limit's retry_after from the actual entry timestamps (the
		// aggregate cross-account view, RBF-adjusted).
		e.refineRetryAfter(&dec, c, now, rbf)
		return nil
	}); err != nil {
		return Decision{}, err
	}
	return dec, nil
}

// Reserve is the DURABLE pre-sign reservation (§5.1): it seal-verifies +
// anti-rollback-checks the policy, classifies, computes the rolling-24h window,
// runs the pure Evaluate, and — if allowed — atomically debits the per-account
// counter AND writes the {state:"reserved"} reservation record. This MUST run
// BEFORE Signer.SignTx — the durable, fsynced write precedes the signed bytes
// reaching the chain, which defeats the "crash to reset counters" attack. A denied
// verdict returns a domain.Error whose Code is the policy.denied.* string (exit 3)
// and writes NOTHING.
func (e *Engine) Reserve(ctx context.Context, c Check) (Reservation, error) {
	pol, present, err := e.loadActivePolicy()
	if err != nil {
		return Reservation{}, err
	}

	r := e.newReservation(c)

	if present {
		// Network-lock critical section (§4.1 per-(network) day lock): read every
		// account's counter → AGGREGATE the rolling-24h window across all accounts →
		// Evaluate → (if allowed) debit the signing account's counter. The denial
		// returns BEFORE any durable write (the ordering service depends on). The
		// network lock makes the cross-account read-sum-then-reserve atomic, so two
		// parallel sends on DIFFERENT accounts cannot jointly overshoot max_day (R2a).
		if err := e.withNetworkLock(ctx, c.Network, func() error {
			cf, lerr := e.loadCounter(c.Network, c.Account)
			if lerr != nil {
				return lerr
			}
			now := e.now()
			spent, rbf, werr := e.windowFor(c, cf, now)
			if werr != nil {
				return werr
			}
			dec := Evaluate(pol, c, spent, now)
			if !dec.Allowed {
				e.refineRetryAfter(&dec, c, now, rbf)
				return deniedError(dec)
			}
			// Permits are gasless and never broadcast — they have no wei to count
			// and never reserve (§4.4). They run pure Evaluate above and stop here.
			if c.effectiveKind() == KindPermit {
				r.skipReserve = true
				return nil
			}
			e.debitCounter(cf, &r, c, now)
			cf.PolicyNonce = pol.Nonce
			return e.writeCounter(c.Network, c.Account, cf, now)
		}); err != nil {
			return Reservation{}, err
		}
		if r.skipReserve {
			// A permit: allowed, nothing reserved (no reservation record, no
			// counter debit). Return a sentinel reservation with an empty id so
			// service's settle/abort treat it as a no-op (Release/Commit on "" are
			// no-ops).
			return Reservation{}, nil
		}
	}

	// Durable reservation record (the orphan source of truth, M3 — global lock).
	if werr := e.withLock(ctx, func() error {
		byID, order, lerr := e.loadAll()
		if lerr != nil {
			return lerr
		}
		return e.appendAndCompact(byID, order, &r)
	}); werr != nil {
		return Reservation{}, werr
	}
	return r, nil
}

// Commit promotes a reservation to {state:"committed", hash} after a successful
// broadcast (§5.1), in BOTH the reservation log (orphan source of truth) and the
// per-account counter (window accumulator). The live-process path; CommitOrphan
// is its reconcile twin. Idempotent; committing a released reservation is a no-op
// (the safe direction). A missing id is tx.integrity.reservation_missing (exit 12).
func (e *Engine) Commit(ctx context.Context, id string, hash common.Hash) error {
	if err := e.transition(ctx, id, func(r *Reservation) error {
		if r.State == stateReleased {
			return nil
		}
		r.State = stateCommitted
		r.Hash = hash.Hex()
		return nil
	}); err != nil {
		return err
	}
	// Mirror into the counter: mark the candidate committed with the broadcast hash.
	return e.counterTransition(ctx, id, func(cf *counterFile, entry *counterEntry) {
		if c := primaryCandidate(entry); c != nil && c.State != candReleased {
			c.State = candCommitted
			c.TxHash = hash.Hex()
		}
	})
}

// Release frees a reservation to {state:"released"} (the pre-sign failure path).
// Idempotent. A missing id is NOT an error for Release (the safe direction).
// CRITICAL (§4.4): a COMMITTED reservation is never released — once signed bytes
// are broadcast, released allowance could correspond to live spendable bytes; the
// release is a no-op. Mirrors into the counter (mark the candidate released so it
// drops out of the window sum).
func (e *Engine) Release(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	if err := e.withLock(ctx, func() error {
		byID, order, err := e.loadAll()
		if err != nil {
			return err
		}
		r, ok := byID[id]
		if !ok {
			return nil // nothing reserved ⇒ nothing to release
		}
		if r.State == stateCommitted {
			return nil // once signed/committed, nothing releases (over-count is safe)
		}
		r.State = stateReleased
		return e.appendAndCompact(byID, order, r)
	}); err != nil {
		return err
	}
	return e.counterTransition(ctx, id, func(cf *counterFile, entry *counterEntry) {
		if c := primaryCandidate(entry); c != nil && c.State == candReserved {
			c.State = candReleased
		}
	})
}

// SettleActual shrinks the reserved worst-case gas to the actual gas on an
// observed receipt (§5.4; down-only) in BOTH stores. On a REVERTED receipt
// (reverted=true) the gas still counts (the EVM charged it) but the native VALUE
// is RELEASED — the value did not move on-chain, so §4.4's "on a revert, value
// released" zeroes value_wei for the committed candidate (and the reservation's
// SpendWei) so it drops out of the rolling-24h window. A missing id is
// tx.integrity.reservation_missing (exit 12). Monotonic-down: a later, larger
// actual never re-inflates gas.
func (e *Engine) SettleActual(ctx context.Context, id string, actualGasWei *big.Int, reverted bool) error {
	if actualGasWei == nil {
		actualGasWei = big.NewInt(0)
	}
	if err := e.transition(ctx, id, func(r *Reservation) error {
		newActual := new(big.Int).Set(actualGasWei)
		if r.ActualGasWei != nil {
			if prev, ok := new(big.Int).SetString(*r.ActualGasWei, 10); ok && prev.Cmp(newActual) < 0 {
				newActual = prev
			}
		}
		if worst, ok := new(big.Int).SetString(r.MaxGasWei, 10); ok && newActual.Cmp(worst) > 0 {
			newActual = worst
		}
		s := newActual.String()
		r.ActualGasWei = &s
		if reverted {
			// The value never moved on-chain ⇒ release it from the spend record.
			r.SpendWei = "0"
		}
		return nil
	}); err != nil {
		return err
	}
	return e.counterTransition(ctx, id, func(cf *counterFile, entry *counterEntry) {
		c := primaryCandidate(entry)
		if c == nil {
			return
		}
		// Down-only gas adjustment, clamped to the worst case.
		newActual := new(big.Int).Set(actualGasWei)
		if c.GasActualWei != nil {
			if prev, ok := new(big.Int).SetString(*c.GasActualWei, 10); ok && prev.Cmp(newActual) < 0 {
				newActual = prev
			}
		}
		if worst, ok := new(big.Int).SetString(c.GasMaxWei, 10); ok && newActual.Cmp(worst) > 0 {
			newActual = worst
		}
		s := newActual.String()
		c.GasActualWei = &s
		if reverted {
			// §4.4 revert releases value: zero this committed candidate's value_wei so
			// the rolling-24h window stops counting native value the EVM never moved.
			c.ValueWei = "0"
		}
	})
}

// transition is the shared committed/settle mutator on the reservation log: load
// under the global lock, locate the id (missing ⇒ reservation_missing exit 12),
// apply mut, write compacted.
func (e *Engine) transition(ctx context.Context, id string, mut func(*Reservation) error) error {
	if id == "" {
		return domain.New("tx.integrity.reservation_missing",
			"policy reservation id is empty; the signed tx has no reservation to settle")
	}
	return e.withLock(ctx, func() error {
		byID, order, err := e.loadAll()
		if err != nil {
			return err
		}
		r, ok := byID[id]
		if !ok {
			return domain.Newf("tx.integrity.reservation_missing",
				"policy reservation %q is missing; refusing to proceed (the durable spend record vanished)", id)
		}
		if merr := mut(r); merr != nil {
			return merr
		}
		return e.appendAndCompact(byID, order, r)
	})
}

// counterTransition locates the reservation in the reservation log to learn its
// (network, account), then mutates the matching counter entry under the account
// lock. A missing counter entry is tolerated (the safe direction — the counter is
// the window accumulator, not the integrity source of truth; a permit or an
// opt-in send has no counter entry). It NEVER fails a settle/commit/release for a
// missing counter line.
func (e *Engine) counterTransition(ctx context.Context, id string, mut func(*counterFile, *counterEntry)) error {
	if id == "" {
		return nil
	}
	// Resolve the reservation's account from the reservation log (best-effort).
	var network string
	var acct common.Address
	var found bool
	_ = e.withLock(ctx, func() error {
		byID, _, err := e.loadAll()
		if err != nil {
			return err
		}
		if r, ok := byID[id]; ok {
			network = r.Network
			acct = r.Account
			found = true
		}
		return nil
	})
	if !found || acct == (common.Address{}) {
		return nil // no counter context (permit / opt-in / pre-counter record)
	}
	// The counter lock is per-NETWORK (§4.1 aggregate scope), so commit/settle/
	// release serialize on the SAME lock as the aggregate read in Reserve/Evaluate.
	return e.withNetworkLock(ctx, network, func() error {
		cf, lerr := e.loadCounter(network, acct)
		if lerr != nil {
			return lerr
		}
		entry := cf.findEntry(id)
		if entry == nil {
			return nil // tolerated
		}
		mut(cf, entry)
		return e.writeCounter(network, acct, cf, e.now())
	})
}

// debitCounter appends a reserved candidate for this Check, cross-linked by the
// reservation id. RBF supersession (§4.4): a speedup/cancel with a matching
// account_nonce appends a candidate to the EXISTING entry rather than creating a
// new one (the counted envelope is the max across candidates). The caller MUST
// hold the account lock.
func (e *Engine) debitCounter(cf *counterFile, r *Reservation, c Check, now time.Time) {
	cand := counterCandidate{
		ValueWei:  weiString(c.spendWei()),
		GasMaxWei: weiString(c.maxGasWei()),
		State:     candReserved,
	}
	if c.IsRBFDelta {
		if existing := cf.findEntryByNonce(c.AccountNonce); existing != nil {
			existing.Candidates = append(existing.Candidates, cand)
			r.entryID = existing.ID // the reservation's counter entry is the superseded one
			return
		}
	}
	entry := counterEntry{
		ID:           r.ID,
		TS:           now.UTC().Format(time.RFC3339Nano),
		AccountNonce: c.AccountNonce,
		Kind:         c.Kind,
		Asset:        assetOf(c),
		Candidates:   []counterCandidate{cand},
	}
	cf.Entries = append(cf.Entries, entry)
	sortEntriesByTS(cf)
}

// rbfContext carries what the daily-window computation learned about an RBF
// request: the superseded entry's id + account (so refineRetryAfter can exclude
// it from the aged-out walk and re-add the merged envelope) and the merged
// envelope itself (max(origValue,newValue) + max(origGas,newGas)). present=false
// for a non-RBF request or an RBF with no matching superseded entry.
type rbfContext struct {
	present      bool
	supersededID string
	account      common.Address
	mergedEnv    *big.Int // the counted envelope after merging the new candidate
}

// windowFor computes the value stageDaily must treat as spentWindowWei (§4.1
// aggregate across all accounts), correctly handling RBF supersession so a
// speedup/cancel counts only the positive gas delta (§5.5: value is NOT
// re-counted). The caller MUST hold the network lock.
//
// Non-RBF: spentWindowWei = Σ over every account of its in-window envelopes; the
// pure stageDaily then adds thisDebit = newValue+newGas. Correct.
//
// RBF with a matching superseded (network, account, account_nonce) entry: the
// original envelope is ALREADY inside that aggregate. A speedup must compare
// window_excluding_that_entry + max(originalEnvelope, newEnvelope) ≤ limit. Since
// pure stageDaily unconditionally adds thisDebit (= newValue+newGas), windowFor
// returns spentWindowWei = aggregateExcludingEntry + mergedEnvelope − thisDebit so
// the gate's (spent + thisDebit) collapses to aggregateExcludingEntry +
// mergedEnvelope — i.e. the original envelope is removed and only the positive
// gas delta (the max-across-candidates increase) is re-added.
func (e *Engine) windowFor(c Check, cf *counterFile, now time.Time) (*big.Int, rbfContext, error) {
	// Locate the RBF superseded entry (same account_nonce) in the signing account's
	// own counter file — RBF candidates always share the signer's (network, from).
	var existing *counterEntry
	if c.IsRBFDelta {
		existing = cf.findEntryByNonce(c.AccountNonce)
	}
	if existing == nil {
		// Non-RBF (or no matching entry): plain aggregate across all accounts.
		spent, err := e.aggregateWindow(c.Network, c.Account, now, common.Address{}, "")
		if err != nil {
			return nil, rbfContext{}, err
		}
		return spent, rbfContext{}, nil
	}

	// RBF: aggregate EXCLUDING the superseded entry, then fold the merged envelope.
	excl, err := e.aggregateWindow(c.Network, c.Account, now, c.Account, existing.ID)
	if err != nil {
		return nil, rbfContext{}, err
	}
	// The merged envelope: max value / max gas across the EXISTING candidates and
	// THIS new candidate (the speedup/cancel) — value is never re-counted, only the
	// positive gas delta survives.
	mergedVal := new(big.Int).Set(maxValueWei(existing))
	if v := c.spendWei(); v.Cmp(mergedVal) > 0 {
		mergedVal = v
	}
	mergedGas := new(big.Int).Set(maxGasWei(existing))
	if g := c.maxGasWei(); g.Cmp(mergedGas) > 0 {
		mergedGas = g
	}
	merged := new(big.Int).Add(mergedVal, mergedGas)

	// stageDaily adds thisDebit = newValue + newGas unconditionally, so pre-subtract
	// it: (excl + merged − thisDebit) + thisDebit == excl + merged.
	thisDebit := new(big.Int).Add(c.spendWei(), c.maxGasWei())
	spent := new(big.Int).Add(excl, merged)
	spent.Sub(spent, thisDebit)
	return spent, rbfContext{present: true, supersededID: existing.ID, account: c.Account, mergedEnv: merged}, nil
}

// refineRetryAfter overrides a day_limit denial's conservative retry_after (now+24h)
// with the precise instant: the earliest time enough of the in-window debits age
// out for THIS request's debit to fit. It walks the AGGREGATE window entries (§4.1
// across every account on the network) oldest-first, dropping each entry's
// contribution until the remaining window + this debit ≤ limit, and reports that
// entry's (ts + 24h). For an RBF request it excludes the superseded entry and
// folds the merged envelope in its place (so the walk matches the gate). The
// caller MUST hold the network lock. Best-effort: if it cannot improve on the
// conservative bound it leaves it.
func (e *Engine) refineRetryAfter(dec *Decision, c Check, now time.Time, rbf rbfContext) {
	if dec.Allowed || dec.Code != codeDayLimit {
		return
	}
	limStr, _ := dec.Data["limit"].(string)
	limit, ok := new(big.Int).SetString(limStr, 10)
	if !ok {
		return
	}
	// The debit being fit: for a normal send it is this request's value+gas; for an
	// RBF the merged envelope is already folded into `total` below (it replaces the
	// superseded entry), so the marginal debit the walk must fit is zero.
	thisDebit := new(big.Int).Add(c.spendWei(), c.maxGasWei())
	if rbf.present {
		thisDebit = big.NewInt(0)
	}

	type wEntry struct {
		ts  time.Time
		wei *big.Int
	}
	var win []wEntry
	cutoff := now.Add(-24 * time.Hour)
	total := new(big.Int)
	// Walk EVERY account's in-window entries (the aggregate the gate evaluated).
	for _, acct := range e.networkAccounts(c.Network, c.Account) {
		cf, lerr := e.loadCounter(c.Network, acct)
		if lerr != nil {
			return // best-effort: leave the conservative bound
		}
		for i := range cf.Entries {
			ent := &cf.Entries[i]
			// RBF: the superseded entry's original envelope is replaced by the merged
			// envelope (max across candidates) — fold the merged value at the entry's
			// own timestamp so aging it out frees exactly the merged contribution.
			if rbf.present && acct == rbf.account && ent.ID == rbf.supersededID {
				ts := parseTS(ent.TS)
				if !ts.IsZero() && ts.Before(cutoff) {
					continue
				}
				w := new(big.Int).Set(rbf.mergedEnv)
				win = append(win, wEntry{ts: ts, wei: w})
				total.Add(total, w)
				continue
			}
			ts := parseTS(ent.TS)
			if !ts.IsZero() && ts.Before(cutoff) {
				continue
			}
			if entryAllReleased(ent) {
				continue
			}
			w := new(big.Int).Add(maxValueWei(ent), maxGasWei(ent))
			win = append(win, wEntry{ts: ts, wei: w})
			total.Add(total, w)
		}
	}
	// Sort oldest-first; drop until headroom fits.
	for i := 0; i < len(win); i++ {
		for j := i + 1; j < len(win); j++ {
			if win[j].ts.Before(win[i].ts) {
				win[i], win[j] = win[j], win[i]
			}
		}
	}
	remaining := new(big.Int).Set(total)
	for _, w := range win {
		// After this entry ages out, does the remainder + this debit fit?
		remaining.Sub(remaining, w.wei)
		if new(big.Int).Add(remaining, thisDebit).Cmp(limit) <= 0 {
			if !w.ts.IsZero() {
				dec.RetryAfter = w.ts.Add(24 * time.Hour).UTC().Format(time.RFC3339)
				dec.Data["retry_after"] = dec.RetryAfter
			}
			return
		}
	}
}

// loadActivePolicy loads + seal-verifies the active policy. It returns
// (Policy{}, present=false, nil) only when NO anchor is pinned AND no policy file
// exists (the opt-in case). Any seal/rollback/version/state failure returns the
// fail-closed error (exit 8).
func (e *Engine) loadActivePolicy() (Policy, bool, error) {
	res, err := loadPolicy(e.dir, e.anchor, e.anchorFound)
	if err != nil {
		return Policy{}, false, err
	}
	return res.policy, res.present, nil
}

// Close flushes the engine. No-op (no long-lived fd; every mutation opens, locks,
// writes, releases). Present for the Service.Close lifecycle.
func (e *Engine) Close() error { return nil }

// deniedError renders a denied Decision as the canonical domain.Error (exit 3 via
// the policy.denied prefix in the §5.7 registry), carrying the per-code Data and
// the retryable hint (day_limit + gas_cap are retryable, §4.9).
func deniedError(d Decision) error {
	code := d.Code
	if code == "" {
		code = codeDenied
	}
	msg := d.Reason
	if msg == "" {
		msg = "the transaction was denied by policy"
	}
	err := domain.New(code, msg)
	if d.Data != nil {
		err = domain.WithData(err, d.Data)
	}
	// day_limit + gas_cap are the retryable denials (§4.9). domain's defaults do
	// not (yet) include them, so set the hint explicitly here.
	if code == codeDayLimit || code == codeGasCap {
		err.Retryable = true
	}
	return err
}

// assetOf returns the counter entry's asset ("eth" or the lowercase token/NFT
// contract) for display.
func assetOf(c Check) string {
	if c.Asset != "" {
		return c.Asset
	}
	if c.Token != "" {
		return c.Token
	}
	return "eth"
}

// primaryCandidate returns the candidate a commit/settle/release acts on: the
// last non-released candidate (the most recent RBF candidate), or nil.
func primaryCandidate(e *counterEntry) *counterCandidate {
	for i := len(e.Candidates) - 1; i >= 0; i-- {
		if e.Candidates[i].State != candReleased {
			return &e.Candidates[i]
		}
	}
	if len(e.Candidates) > 0 {
		return &e.Candidates[len(e.Candidates)-1]
	}
	return nil
}
