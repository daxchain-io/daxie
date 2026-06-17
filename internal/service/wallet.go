package service

import (
	"context"

	"github.com/daxchain-io/daxie/internal/domain"
)

// wallet.go holds the M1 HD-wallet use cases (cli-spec §wallet). Each is one
// method per use case in the uniform shape (§2.10): (ctx, Principal, Request,
// EventSink) → (Result, error). Principal is the journal-attribution WHO (M1
// writes no journal yet but threads it so M3+ inherits the shape); the EventSink
// carries the create/export confirmation progress (§5.9). Secret material is
// NEVER in a request struct — it arrives as a *secret.Bytes the caller resolved
// and owns (the frontend resolves it from flags/env/stdin via the service's
// acquire seam; see WalletCreateInput below).
//
// keys.* error codes (keystore.bad_passphrase/confirm_required exit 4,
// keystore.read_only exit 10, keystore.perms_insecure exit 12,
// usage.name_collision exit 2) originate in the keys provider and flow back
// unchanged through the cli render registry (§5.7). The service adds no string
// matching; it maps keys structs to the domain.*Result wire shapes.

// WalletCreateInput carries the out-of-band secret channels the create use case
// resolves itself (the JSON request omits all secrets, §2.4). The frontend fills
// the flag/env wiring; the service acquires + zeroes. Keeping these here rather
// than in domain.WalletCreateRequest keeps secret material off the wire and out
// of any future MCP schema (§6.1: no wallet create tool).
type WalletCreateInput struct {
	// PassphraseStdin is true when --passphrase-stdin was set.
	PassphraseStdin bool
	// PassphraseFile is the --passphrase-file path ("" unset).
	PassphraseFile string
	// ConfirmStdin / ConfirmFile feed the first-init double-entry confirm channel
	// (§3.3). They are consulted ONLY on first init; after the verifier exists
	// they are ignored.
	ConfirmStdin bool
	ConfirmFile  string
	// StdinTaken is true when stdin is already claimed (it never is for create,
	// but the field keeps the shape uniform with import).
	StdinTaken bool
}

// WalletCreate generates a fresh BIP-39 wallet, returning the mnemonic ONCE in
// the result (sensitive=true) — the display-once contract (§3.5). It verifies (or
// on first init, double-entry-confirms then writes) the keystore passphrase
// before any secret is written, so a typo cannot fork the keystore onto an
// un-unlockable passphrase (§3.3).
func (s *Service) WalletCreate(ctx context.Context, p domain.Principal, req domain.WalletCreateRequest, in WalletCreateInput, emit domain.EventSink) (domain.WalletCreateResult, error) {
	words := req.Words
	if words == 0 {
		words = 12
	}

	pass, _, err := s.acquire(passphraseSpecWith(in.PassphraseStdin, in.PassphraseFile, in.StdinTaken))
	if err != nil {
		return domain.WalletCreateResult{}, err
	}
	defer pass.Zero()

	// First-init confirm (§3.3): verifies an existing keystore, or on first use
	// confirms by double-entry before keys writes the verifier — so a typo cannot
	// fork the keystore onto an un-unlockable passphrase. The fingerprint is the
	// non-secret salted hash echoed on first init.
	fingerprint, err := s.ensureInitialized(ctx, pass, in.ConfirmStdin, in.ConfirmFile, in.StdinTaken)
	if err != nil {
		return domain.WalletCreateResult{}, err
	}

	res, err := s.keys.CreateWallet(ctx, req.Name, words, pass)
	if err != nil {
		return domain.WalletCreateResult{}, err
	}
	// The freshly-generated mnemonic + 25th word are sensitive; surface them ONCE.
	// keys returns them as *secret.Bytes; Reveal here is one of the two greppable
	// escape hatches (§3.10). The caller (cli create) renders them once and the
	// result is never journaled/logged.
	defer res.Mnemonic.Zero()
	defer res.BIP39Pass.Zero()

	emitResolved(emit, res.Index0Addr.Hex(), "wallet "+req.Name+" created")

	out := domain.WalletCreateResult{
		Name:            req.Name,
		WalletID:        res.WalletID,
		PathPrefix:      res.PathPrefix,
		Account0:        req.Name + "/0",
		Account0Address: res.Index0Addr.Hex(),
		Mnemonic:        string(res.Mnemonic.Reveal()),
		Sensitive:       true,
	}
	if res.BIP39Pass != nil && res.BIP39Pass.Len() > 0 {
		out.BIP39Passphrase = string(res.BIP39Pass.Reveal())
	}
	// The fingerprint is non-secret (a salted hash) and emitted only on first
	// init so an orchestrator can assert its secret source re-derives the same
	// keystore (§3.3).
	out.PassphraseFinger = fingerprint
	return out, nil
}

// WalletImportInput carries the import secret channels (mnemonic, optional 25th
// word, keystore passphrase) — all out-of-band, never on the wire.
type WalletImportInput struct {
	MnemonicStdin bool
	MnemonicFile  string

	BIP39Stdin bool
	BIP39File  string

	PassphraseStdin bool
	PassphraseFile  string

	ConfirmStdin bool
	ConfirmFile  string
}

// WalletImport imports an existing BIP-39 mnemonic (NFKD-normalized + checksum
// validated in keys). The mnemonic arrives via stdin/file (never a flag value,
// §3.5); supplying it on stdin marks stdin taken so a passphrase cannot also come
// from stdin without a hard conflict error.
func (s *Service) WalletImport(ctx context.Context, p domain.Principal, req domain.WalletImportRequest, in WalletImportInput, emit domain.EventSink) (domain.WalletImportResult, error) {
	stdinTaken := in.MnemonicStdin

	mnemonic, _, err := s.acquire(secretSpec{
		StdinFlag:   in.MnemonicStdin,
		FilePath:    in.MnemonicFile,
		PromptLabel: "BIP-39 mnemonic: ",
	})
	if err != nil {
		return domain.WalletImportResult{}, err
	}
	defer mnemonic.Zero()

	// Optional BIP-39 25th-word passphrase. Absent → empty (keys treats nil as
	// "no passphrase"). If it would come from stdin, that conflicts with the
	// mnemonic on stdin — secret.Acquire raises usage.stdin_conflict.
	bip39, _, err := s.acquireOptional(secretSpec{
		StdinFlag:   in.BIP39Stdin,
		FilePath:    in.BIP39File,
		PromptLabel: "BIP-39 passphrase (25th word, blank if none): ",
		StdinTaken:  stdinTaken,
	})
	if err != nil {
		return domain.WalletImportResult{}, err
	}
	defer bip39.Zero()
	if in.BIP39Stdin {
		stdinTaken = true
	}

	pass, _, err := s.acquire(passphraseSpecWith(in.PassphraseStdin, in.PassphraseFile, stdinTaken))
	if err != nil {
		return domain.WalletImportResult{}, err
	}
	defer pass.Zero()

	if _, eerr := s.ensureInitialized(ctx, pass, in.ConfirmStdin, in.ConfirmFile, stdinTaken); eerr != nil {
		return domain.WalletImportResult{}, eerr
	}

	walletID, index0, err := s.keys.ImportWallet(ctx, req.Name, mnemonic, bip39, pass)
	if err != nil {
		return domain.WalletImportResult{}, err
	}

	emitResolved(emit, index0.Hex(), "wallet "+req.Name+" imported")
	return domain.WalletImportResult{
		Name:            req.Name,
		WalletID:        walletID,
		PathPrefix:      "m/44'/60'/0'/0",
		Account0:        req.Name + "/0",
		Account0Address: index0.Hex(),
	}, nil
}

// WalletList lists every wallet with its account count and creation time. It is a
// read — no unlock, no lock on POSIX (§3.3).
func (s *Service) WalletList(ctx context.Context, p domain.Principal, _ domain.WalletListRequest) (domain.WalletListResult, error) {
	wallets, err := s.keys.ListWallets(ctx)
	if err != nil {
		return domain.WalletListResult{}, err
	}
	out := domain.WalletListResult{Wallets: make([]domain.WalletSummary, 0, len(wallets))}
	for _, w := range wallets {
		out.Wallets = append(out.Wallets, domain.WalletSummary{
			Name:      w.Name,
			WalletID:  w.ID,
			Accounts:  len(w.Accounts),
			CreatedAt: w.CreatedAt.UTC().Format(rfc3339),
		})
	}
	return out, nil
}

// WalletShow returns one wallet's derivation prefix, next index, and materialized
// accounts. Read-only.
func (s *Service) WalletShow(ctx context.Context, p domain.Principal, req domain.WalletShowRequest) (domain.WalletShowResult, error) {
	w, err := s.keys.ShowWallet(ctx, req.Name)
	if err != nil {
		return domain.WalletShowResult{}, err
	}
	out := domain.WalletShowResult{
		Name:       w.Name,
		WalletID:   w.ID,
		PathPrefix: w.PathPrefix,
		NextIndex:  w.NextIndex,
		CreatedAt:  w.CreatedAt.UTC().Format(rfc3339),
		Accounts:   make([]domain.AccountSummary, 0, len(w.Accounts)),
	}
	for idx, a := range w.Accounts {
		i := idx
		ref := w.Name + "/" + utoa(i)
		if a.Alias != "" {
			ref = w.Name + "/" + a.Alias
		}
		out.Accounts = append(out.Accounts, domain.AccountSummary{
			Ref:       ref,
			Address:   a.Address.Hex(),
			Kind:      "hd",
			Wallet:    w.Name,
			Index:     uptr(i),
			Alias:     a.Alias,
			CreatedAt: a.CreatedAt.UTC().Format(rfc3339),
		})
	}
	sortAccounts(out.Accounts)
	return out, nil
}

// WalletRename renames a wallet (a meta.json mutation; the secret blob is keyed
// by UUID so it is never rewritten, §3.1). A collision with an existing wallet /
// standalone name fails usage.name_collision (exit 2) in keys.
func (s *Service) WalletRename(ctx context.Context, p domain.Principal, req domain.WalletRenameRequest) (domain.WalletRenameResult, error) {
	walletID, err := s.keys.RenameWallet(ctx, req.Old, req.New)
	if err != nil {
		return domain.WalletRenameResult{}, err
	}
	return domain.WalletRenameResult{Old: req.Old, New: req.New, WalletID: walletID}, nil
}

// WalletExportInput carries the freshly-resolved passphrase channel. Export NEVER
// reuses a cached unlock (§3.9); the passphrase is resolved here every time.
type WalletExportInput struct {
	PassphraseStdin bool
	PassphraseFile  string
}

// WalletExport prints a wallet's mnemonic + 25th word (stdout only; never a file,
// never journaled, §3.9). The confirm ceremony (typed name / --yes) is enforced
// by the frontend before this is called; the service still re-resolves the
// passphrase so a serve-cached unlock cannot satisfy it.
func (s *Service) WalletExport(ctx context.Context, p domain.Principal, req domain.WalletExportRequest, in WalletExportInput) (domain.WalletExportResult, error) {
	pass, _, err := s.acquire(passphraseSpecWith(in.PassphraseStdin, in.PassphraseFile, false))
	if err != nil {
		return domain.WalletExportResult{}, err
	}
	defer pass.Zero()

	mnemonic, bip39, err := s.keys.ExportWallet(ctx, req.Name, pass)
	if err != nil {
		return domain.WalletExportResult{}, err
	}
	defer mnemonic.Zero()
	defer bip39.Zero()

	out := domain.WalletExportResult{
		Name:      req.Name,
		Mnemonic:  string(mnemonic.Reveal()),
		Sensitive: true,
	}
	if bip39 != nil && bip39.Len() > 0 {
		out.BIP39Passphrase = string(bip39.Reveal())
	}
	return out, nil
}

// WalletDelete removes a wallet (its secret blob + meta entry). The confirm
// ceremony is the frontend's; keys performs the atomic removal under the lock.
func (s *Service) WalletDelete(ctx context.Context, p domain.Principal, req domain.WalletDeleteRequest) (domain.WalletDeleteResult, error) {
	walletID, err := s.keys.DeleteWallet(ctx, req.Name)
	if err != nil {
		return domain.WalletDeleteResult{}, err
	}
	return domain.WalletDeleteResult{Name: req.Name, WalletID: walletID, Deleted: true}, nil
}

// ── shared secret-spec helpers ───────────────────────────────────────────────

// passphraseSpecWith builds the §3.6 keystore-passphrase request from the
// command's stdin/file flags (env channels are always consulted per precedence).
func passphraseSpecWith(stdin bool, file string, stdinTaken bool) secretSpec {
	sp := passphraseSpec(stdinTaken)
	sp.StdinFlag = stdin
	sp.FilePath = file
	return sp
}

// confirmSpec is the first-init double-entry confirm channel (§3.3).
func confirmSpec(stdin bool, file string, stdinTaken bool) secretSpec {
	return secretSpec{
		StdinFlag:   stdin,
		FilePath:    file,
		EnvFileVar:  "DAXIE_PASSPHRASE_CONFIRM_FILE",
		EnvVar:      "DAXIE_PASSPHRASE_CONFIRM",
		PromptLabel: "Confirm keystore passphrase: ",
		StdinTaken:  stdinTaken,
	}
}

// emitResolved fires an EvResolved progress event when a sink is present. M1 uses
// it for the create/import/derive echo; nil sink = no-op (the common case). The
// address is carried in Detail (a non-secret public value) so the frontend can
// render an echo line before signing in later milestones.
func emitResolved(emit domain.EventSink, addr, detail string) {
	if emit == nil {
		return
	}
	d := detail
	if addr != "" {
		d = detail + " (" + addr + ")"
	}
	emit(domain.Event{Kind: domain.EvResolved, Detail: d, Stream: "stderr"})
}

// emitResolvedDest fires the EvResolved echo for a resolved send/spender
// destination (§5.10). destLabel already carries the address — "name (0x…)" for a
// contact/ENS, the bare 0x for a literal — so the address is rendered exactly once
// and NOT appended a second time. The structured Address field is still populated
// from the resolved dest for any consumer that prefers it over parsing Detail.
func emitResolvedDest(emit domain.EventSink, prefix string, dest domain.Dest) {
	if emit == nil {
		return
	}
	emit(domain.Event{
		Kind:    domain.EvResolved,
		Address: dest.Address,
		Detail:  prefix + destLabel(dest),
		Stream:  "stderr",
	})
}
