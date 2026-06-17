package service

import (
	"context"
	"errors"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/journal"
	"github.com/daxchain-io/daxie/internal/registry"
	"github.com/ethereum/go-ethereum/common"
)

// registryContact aliases registry.Contact so the contactRow mapper can name it
// without a second registry import elsewhere (the one registry-typed seam in the
// service mappers; OpenContacts is wired in service.Open).
type registryContact = registry.Contact

// reconcile.go is the §5.1 restart-reconciliation bridge plus the AbandonTx
// escape hatch and the contacts use cases.
//
// The reconciliation discriminator is the heart of M3's crash-safety:
//
//	"no broadcast recorded ⇒ release; broadcast recorded ⇒ commit"
//
// A crash between policy.Reserve+sign and the broadcast/Commit pair leaves a
// reservation in state `reserved`. service.Open resolves each such orphan against
// its journal record (chain-scoped ByReservation) and feeds the verdict to
// policy's orphan surface — policy may NOT import journal, so service (which
// legally imports both) is the ONLY place this bridge can live. Because a
// reservation whose record has no recorded broadcast is RELEASED, crashes only
// ever UNDER-spend (the safe direction): the bytes never reached the chain, so the
// counter must not stay bumped.
//
// This bridge is OFFLINE (no RPC): it only compares durable local state. The
// on-chain resurrection of `signed` records (rebroadcast) happens lazily on the
// next `tx wait`/AcquireNonce, through the shared double-spend-gated helper.

// reconcile runs at Open. For every reservation still in state `reserved`, it
// looks up the matching journal record across the configured chains and:
//
//   - record shows a recorded broadcast (status NOT `signed`, i.e. broadcast/
//     pending/mined/…) ⇒ CommitOrphan (the spend really happened);
//   - record is still `signed`, or there is no record at all ⇒ ReleaseOrphan (the
//     spend never reached the chain).
//
// It is a no-op on a fresh install (no orphans). It never fails Open: a per-orphan
// resolution error is collected but the others still process.
func (s *Service) reconcile(ctx context.Context) error {
	if s.policy == nil || s.journal == nil {
		return nil
	}
	orphans, err := s.policy.Orphans(ctx)
	if err != nil {
		return err
	}
	if len(orphans) == 0 {
		return nil
	}

	chains := s.configuredChainIDs()
	var firstErr error
	for _, o := range orphans {
		rec, found := s.findReservationRecord(ctx, chains, o.ID)
		switch {
		case found && rec.Status != journal.StatusSigned:
			// A recorded broadcast exists ⇒ the spend happened ⇒ commit.
			hash := common.HexToHash(rec.TxHash)
			if cerr := s.policy.CommitOrphan(ctx, o.ID, hash); cerr != nil && firstErr == nil {
				firstErr = cerr
			}
		default:
			// No record, or status still `signed` (no recorded broadcast) ⇒ release.
			if rerr := s.policy.ReleaseOrphan(ctx, o.ID); rerr != nil && firstErr == nil {
				firstErr = rerr
			}
		}
	}
	return firstErr
}

// findReservationRecord locates the journal record for a reservation id by
// scanning the configured chains (the reservation struct carries no chain id in
// M3; the journal is chain-scoped). It returns the record + whether one was found.
// A chain with no journal file (or no matching record) returns ErrNotFound, which
// is the not-found signal, not a hard error.
func (s *Service) findReservationRecord(ctx context.Context, chains []uint64, reservationID string) (*journal.Record, bool) {
	for _, cid := range chains {
		rec, err := s.journal.ByReservation(ctx, cid, reservationID)
		if err == nil && rec != nil {
			return rec, true
		}
		if err != nil && !errors.Is(err, journal.ErrNotFound) {
			// A torn/corrupt file on one chain should not abort the scan; skip it.
			continue
		}
	}
	return nil, false
}

// configuredChainIDs returns the distinct chain ids of every configured network
// (built-in + user). It is the reconciliation search space — a crash-left
// reservation's record lives under one of these chains. Deterministic + os-free
// (read from the merged config, never the filesystem, §2.3).
func (s *Service) configuredChainIDs() []uint64 {
	seen := make(map[uint64]bool, len(s.cfg.Networks))
	out := make([]uint64, 0, len(s.cfg.Networks))
	for _, n := range s.cfg.Networks {
		if n.ChainID != 0 && !seen[n.ChainID] {
			seen[n.ChainID] = true
			out = append(out, n.ChainID)
		}
	}
	return out
}

// AbandonTx voids a signed-never-broadcast record (the §5.6 operator escape
// hatch): it marks the record failed, releases its reservation, and frees the
// nonce. It refuses to abandon a record that shows a recorded broadcast (a
// broadcast tx may yet mine — abandoning it locally would not unspend it).
func (s *Service) AbandonTx(ctx context.Context, p domain.Principal, req domain.AbandonRequest) (domain.AbandonResult, error) {
	hash, err := parseHash(req.Hash)
	if err != nil {
		return domain.AbandonResult{}, err
	}
	cc, err := s.chains.ClientFor(ctx, ChainRequest{Network: req.Network, RPC: req.RPC})
	if err != nil {
		return domain.AbandonResult{}, err
	}
	defer cc.Close()
	chainID, err := cc.ChainID(ctx)
	if err != nil {
		return domain.AbandonResult{}, mapRPCErr(err)
	}

	rec, err := s.journal.ByHash(ctx, chainID.Uint64(), hash)
	if err != nil {
		if errors.Is(err, journal.ErrNotFound) {
			return domain.AbandonResult{}, domain.Newf(domain.CodeRefNotFound,
				"no journal record for %s", req.Hash)
		}
		return domain.AbandonResult{}, err
	}

	// Only a signed-never-broadcast record can be abandoned safely (§5.6). A
	// broadcast record may still mine; a terminal one needs no abandon.
	if rec.Status != journal.StatusSigned {
		return domain.AbandonResult{}, domain.Newf(domain.CodeUsage+".not_abandonable",
			"transaction is %s; only a signed-never-broadcast tx can be abandoned", rec.Status)
	}

	msg := "abandoned by operator"
	if serr := s.journal.SetState(ctx, chainID.Uint64(), rec.ID, journal.StateMutation{
		Status: journal.StatusFailed, Error: &msg,
	}); serr != nil {
		return domain.AbandonResult{}, serr
	}
	if rec.ReservationID != "" {
		_ = s.policy.Release(ctx, rec.ReservationID)
	}
	// The nonce is freed implicitly: NextNonce folds only non-failed records, so a
	// failed record no longer consumes its nonce (§5.6).
	return domain.AbandonResult{Hash: req.Hash, JournalID: rec.ID, Abandoned: true}, nil
}

// ── contacts use cases (§7.8) ────────────────────────────────────────────────

// ContactAdd writes a name→address entry to the network-agnostic contacts
// registry. The registry validates the §3.1 name grammar + a duplicate-name
// collision; a read-only mount fails the state-class read-only sibling (exit 10).
func (s *Service) ContactAdd(ctx context.Context, p domain.Principal, req domain.ContactAddRequest) (domain.ContactResult, error) {
	ref, err := domain.ParseAccountRef(req.Address)
	if err != nil || ref.Kind != domain.RefAddress {
		return domain.ContactResult{}, domain.Newf(domain.CodeUsage+".bad_address",
			"contact address must be a 0x address, got %q", req.Address)
	}
	if err := s.contacts.Add(ctx, req.Name, ref.Addr); err != nil {
		return domain.ContactResult{}, err
	}
	return domain.ContactResult{Contact: domain.ContactRow{
		Name:    req.Name,
		Address: ref.Addr.Hex(),
	}}, nil
}

// ContactList returns every contact, name-sorted (the registry sorts).
func (s *Service) ContactList(ctx context.Context, p domain.Principal, _ domain.ContactListRequest) (domain.ContactListResult, error) {
	cs, err := s.contacts.List(ctx)
	if err != nil {
		return domain.ContactListResult{}, err
	}
	out := domain.ContactListResult{Contacts: make([]domain.ContactRow, 0, len(cs))}
	for _, c := range cs {
		out.Contacts = append(out.Contacts, contactRow(c))
	}
	return out, nil
}

// ContactShow returns one contact by name (case-insensitive), or ref.not_found.
func (s *Service) ContactShow(ctx context.Context, p domain.Principal, req domain.ContactShowRequest) (domain.ContactResult, error) {
	c, err := s.contacts.Show(ctx, req.Name)
	if err != nil {
		return domain.ContactResult{}, err
	}
	return domain.ContactResult{Contact: contactRow(c)}, nil
}

// ContactRemove deletes a contact by name, or ref.not_found.
func (s *Service) ContactRemove(ctx context.Context, p domain.Principal, req domain.ContactRemoveRequest) (domain.ContactRemoveResult, error) {
	if err := s.contacts.Remove(ctx, req.Name); err != nil {
		return domain.ContactRemoveResult{}, err
	}
	return domain.ContactRemoveResult{Name: req.Name, Removed: true}, nil
}

// contactRow maps a registry.Contact into the wire row.
func contactRow(c registryContact) domain.ContactRow {
	return domain.ContactRow{
		Name:     c.Name,
		Address:  c.Address.Hex(),
		ENS:      c.ENS,
		PinnedAt: c.PinnedAt,
	}
}
