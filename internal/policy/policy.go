// Package policy is the guardrail engine that runs in core, AHEAD of the signer
// (§2.7). M3 ships an ALWAYS-ALLOW stub with a REAL durable reservation lifecycle
// so service's §5.1 ordering (policy.Reserve is durable BEFORE Signer.SignTx) and
// the §5.1 crash reconciliation are exercised and tested NOW. M4 replaces the
// BODY — sealed policy.json (Ed25519 + policy-anchor.json + the monotonic nonce
// watermark, §4.5/§4.6), the rolling-24h window counter (§4.1), the ETH
// per-tx/per-day limits, the fail-closed token rule (§4.3), the gas-cap check,
// the typed-data/calldata classifiers, RBF gas-delta accrual — WITHOUT changing
// this contract or any service call site.
//
// Dependency rules (§2.2, enforced by arch_test): policy imports fsx, domain (and
// in M4: policyseal, abi). It NEVER imports journal (service bridges the
// reconciliation, §5.1, because policy⊥journal), NEVER service, NEVER a frontend.
//
// The "crash to reset counters" attack (§7a) is defeated by ordering, not by this
// stub allowing everything: Reserve writes a durable, fsynced reservation BEFORE
// any signature exists, so a compromised agent that SIGKILLs itself to dodge a
// counter gains nothing — the durable write already happened and M4's body will
// debit off it. The stub's job is to make that ordering and its reconciliation
// real and testable today; M4 only fills in the verdict.
package policy

import (
	"context"
	"math/big"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// Engine is the policy provider. M3: a durable reservation store under
// <stateDir>/policy/reservations.jsonl (+ <stateDir>/locks/policy.lock) and an
// always-allow verdict. The state dir and clock are injected at Open; the engine
// holds no other state (lazy on disk — it creates nothing until the first
// Reserve, §7.3).
type Engine struct {
	dir   string           // the state-class root (<stateDir>)
	clock func() time.Time // injected wall clock; deterministic in tests, §2.4
}

// Open binds the engine to the state dir with an injected clock. Lazy: it creates
// nothing on disk until the first Reserve. clock supplies reservation timestamps
// and ULID time prefixes; a nil clock defaults to time.Now (production wiring
// always passes the service clock so reservations are reproducible in tests).
func Open(stateDir string, clock func() time.Time) (*Engine, error) {
	if clock == nil {
		clock = time.Now
	}
	return &Engine{dir: stateDir, clock: clock}, nil
}

// Evaluate is the CHECK-ONLY path (no reservation written) — backs --dry-run and
// daxie policy check (§5.1), and the future authorizeSignature path. M3: always
// {Allowed:true}, nil. M4 runs §4.3 stages 1–8 here and returns the full
// (possibly denied) Decision with NO durable write.
func (e *Engine) Evaluate(ctx context.Context, c Check) (Decision, error) {
	_ = ctx
	_ = c
	// M3 STUB: the verdict is unconditionally allow. M4 replaces this body with
	// the seal/freshness load + the rolling-24h + per-tx/day/gas-cap checks.
	return Decision{Allowed: true}, nil
}

// Reserve is the DURABLE pre-sign reservation (§5.1): it evaluates AND, if
// allowed, atomically writes a {state:"reserved"} reservation and returns it.
// This MUST run BEFORE Signer.SignTx — the durable, fsynced write precedes the
// signed bytes reaching the chain, which is what defeats the "crash to reset
// counters" attack. M3 always allows and always writes the real reservation. A
// denied verdict (M4) returns a domain.Error whose Code is the policy.denied.*
// string (exit 3) and writes NOTHING.
func (e *Engine) Reserve(ctx context.Context, c Check) (Reservation, error) {
	// Evaluate first so M4's deny path returns before any durable write — the stub
	// always allows, but the ordering is the contract service depends on.
	dec, err := e.Evaluate(ctx, c)
	if err != nil {
		return Reservation{}, err
	}
	if !dec.Allowed {
		return Reservation{}, deniedError(dec)
	}

	r := e.newReservation(c)
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
// broadcast (§5.1). It is the live-process path; CommitOrphan is its reconcile
// twin. Committing an already-committed reservation is idempotent; committing a
// released one is a no-op (the safe direction — a released reservation never had
// a recorded broadcast). A missing id is tx.integrity.reservation_missing (exit
// 12) — the durable reservation vanished out from under a signed tx.
func (e *Engine) Commit(ctx context.Context, id string, hash common.Hash) error {
	return e.transition(ctx, id, func(r *Reservation) error {
		if r.State == stateReleased {
			return nil
		}
		r.State = stateCommitted
		r.Hash = hash.Hex()
		return nil
	})
}

// Release frees a reservation to {state:"released"} (the pre-sign failure /
// permanently-rejected / defer-abort path). Idempotent. A missing id is NOT an
// error for Release (the safe direction: nothing to undo means nothing was
// debited) — service's abort calls Release on a path that may have failed before
// the reservation was ever written.
func (e *Engine) Release(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	return e.withLock(ctx, func() error {
		byID, order, err := e.loadAll()
		if err != nil {
			return err
		}
		r, ok := byID[id]
		if !ok {
			return nil // nothing reserved ⇒ nothing to release
		}
		if r.State == stateCommitted {
			// A committed reservation must never be released — the §4.4 rule: once
			// signed bytes are broadcast (and committed), released allowance could
			// correspond to live spendable bytes. Treat as a no-op.
			return nil
		}
		r.State = stateReleased
		return e.appendAndCompact(byID, order, r)
	})
}

// SettleActual shrinks the reserved worst-case gas to the actual
// gasUsed × effectiveGasPrice on a confirmed receipt (§5.4 "shrunk to actual on
// receipt"; down-only). M3 records actual_gas_wei on the committed reservation;
// M4 debits the rolling-24h counter by (worst − actual). Called by service on the
// §5.3 confirmed transition. A missing id is tx.integrity.reservation_missing
// (exit 12). The adjustment is monotonic-down: a later, larger actual never
// re-inflates the reservation (no sequence of settles creates headroom, §4.4).
func (e *Engine) SettleActual(ctx context.Context, id string, actualGasWei *big.Int) error {
	if actualGasWei == nil {
		actualGasWei = big.NewInt(0)
	}
	return e.transition(ctx, id, func(r *Reservation) error {
		// Down-only: keep the smaller of the existing actual and this observation.
		newActual := new(big.Int).Set(actualGasWei)
		if r.ActualGasWei != nil {
			if prev, ok := new(big.Int).SetString(*r.ActualGasWei, 10); ok && prev.Cmp(newActual) < 0 {
				newActual = prev
			}
		}
		// Never record an actual above the reserved worst case (it would create
		// retroactive headroom for M4's counter); clamp to MaxGasWei.
		if worst, ok := new(big.Int).SetString(r.MaxGasWei, 10); ok && newActual.Cmp(worst) > 0 {
			newActual = worst
		}
		s := newActual.String()
		r.ActualGasWei = &s
		return nil
	})
}

// transition is the shared committed/settle mutator: load under the lock, locate
// the id (missing ⇒ reservation_missing exit 12), apply mut, write compacted.
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

// Close flushes the engine. No-op in M3 (no long-lived fd; every mutation opens,
// locks, writes, releases). Present for the Service.Close lifecycle.
func (e *Engine) Close() error { return nil }

// deniedError renders a denied Decision as the canonical domain.Error (exit 3
// via the policy.denied prefix in the §5.7 registry). M3 never reaches this (the
// stub always allows); it is here so M4's deny path is a one-line return.
func deniedError(d Decision) error {
	code := d.Code
	if code == "" {
		code = domain.CodeUsage // defensive: a denied decision must carry a code
	}
	msg := d.Reason
	if msg == "" {
		msg = "the transaction was denied by policy"
	}
	return domain.New(code, msg)
}
