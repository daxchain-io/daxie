package policy

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
)

// orphan.go is the §5.1 crash-reconciliation surface. Because policy may NOT
// import journal (§2.2), service drives reconciliation at Open: it asks policy
// for the orphan set (Orphans), reads each reservation's journal record
// (journal.ByReservation, chain-scoped), and feeds the verdict back through
// CommitOrphan / ReleaseOrphan. The discriminator is EXACTLY §5.1's:
//
//   - journal record shows a recorded BROADCAST  ⇒ CommitOrphan(hash)
//     (crash between broadcast and Commit — the spend really reached the chain)
//   - journal record still SIGNED, or no record  ⇒ ReleaseOrphan
//     (crash between Reserve and broadcast — no signed bytes reached the chain)
//
// "No broadcast recorded ⇒ release; broadcast recorded ⇒ commit" is the
// safe-direction proof: crashes can only ever UNDER-spend. When tx wait later
// rebroadcasts a journaled `signed` record whose reservation was released here,
// service RE-RESERVES before rebroadcasting (the shared rebroadcast helper), so
// the released allowance is re-debited before the bytes go back out.

// Orphans returns every reservation still in {state:"reserved"} — a crash left it
// un-committed, un-released. The caller (service.Open) resolves each against the
// journal and feeds back the verdict. Returned newest-first is not required; the
// order is the on-disk fold order. Holds the policy lock for the read.
func (e *Engine) Orphans(ctx context.Context) ([]Reservation, error) {
	var out []Reservation
	if err := e.withLock(ctx, func() error {
		byID, order, err := e.loadAll()
		if err != nil {
			return err
		}
		for _, id := range order {
			r := byID[id]
			if r != nil && r.State == stateReserved {
				out = append(out, *r)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// CommitOrphan is Commit for the reconcile path: the journal shows a recorded
// broadcast for this reservation ⇒ the spend really happened ⇒ commit it (§5.1
// "broadcast recorded ⇒ commit"). It shares Commit's body so the live and
// reconcile paths can never diverge.
func (e *Engine) CommitOrphan(ctx context.Context, id string, hash common.Hash) error {
	return e.Commit(ctx, id, hash)
}

// ReleaseOrphan is Release for the reconcile path: the journal shows NO recorded
// broadcast (status still signed, or no record at all) ⇒ the spend never reached
// the chain ⇒ release (§5.1 "no broadcast recorded ⇒ release"). Crashes
// therefore only ever UNDER-spend. It shares Release's body.
func (e *Engine) ReleaseOrphan(ctx context.Context, id string) error {
	return e.Release(ctx, id)
}
