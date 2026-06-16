package service

import (
	"context"
	"sort"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
)

// account.go holds the M1 account use cases (HD-derived + standalone), cli-spec
// §account. Same uniform shape as wallet.go. The active-account default (§7.7) is
// resolved flag>env (service.account, filled by the frontend) > meta.json
// default_account (keys.DefaultAccount) — the one cross-class resolution.
//
// HD accounts are metadata (deriving writes meta.json only; the key is re-derived
// at signing time, §3.1), so DeriveNext/DeriveIndex unlock once to cache the
// public address. Standalone accounts are stock geth v3 files. account delete is a
// pure forget for HD, a key-file removal for standalone (keys reports which mode).

// rfc3339 is the on-the-wire timestamp layout. Timestamps never cross the wire as
// time.Time (§2.5 no non-string time on the wire); the service formats them from
// the keys-provider time.Time values it reads.
const rfc3339 = time.RFC3339

// AccountDeriveInput carries the keystore-passphrase channel the derive use case
// resolves (deriving an HD index requires one unlock to compute the address).
type AccountDeriveInput struct {
	PassphraseStdin bool
	PassphraseFile  string
}

// AccountDerive allocates the next free index (or validates an explicit one) on a
// wallet, derives the address (one unlock), and records the metadata. On a
// read-only keystore (K8s Secret mount) the meta.json write fails
// keystore.read_only (exit 10) — derive at provisioning time on such mounts
// (§3.3). An optional --name aliases the index in the same step.
func (s *Service) AccountDerive(ctx context.Context, p domain.Principal, req domain.AccountDeriveRequest, in AccountDeriveInput, emit domain.EventSink) (domain.AccountDeriveResult, error) {
	pass, _, err := s.acquire(passphraseSpecWith(in.PassphraseStdin, in.PassphraseFile, false))
	if err != nil {
		return domain.AccountDeriveResult{}, err
	}
	defer pass.Zero()

	var (
		index uint32
		addr  string
	)
	if req.Index != nil {
		a, derr := s.keys.DeriveIndex(ctx, req.Wallet, *req.Index, pass)
		if derr != nil {
			return domain.AccountDeriveResult{}, derr
		}
		index = *req.Index
		addr = a.Hex()
	} else {
		idx, a, derr := s.keys.DeriveNext(ctx, req.Wallet, pass)
		if derr != nil {
			return domain.AccountDeriveResult{}, derr
		}
		index = idx
		addr = a.Hex()
	}

	res := domain.AccountDeriveResult{
		Ref:     req.Wallet + "/" + utoa(index),
		Address: addr,
		Index:   index,
	}
	if req.Name != "" {
		if aerr := s.keys.Alias(ctx, req.Wallet, index, req.Name); aerr != nil {
			return domain.AccountDeriveResult{}, aerr
		}
		res.Alias = req.Name
		res.Ref = req.Wallet + "/" + req.Name
	}
	emitResolved(emit, addr, "derived "+res.Ref)
	return res, nil
}

// AccountAlias names an existing HD index (the "name a BIP-39 index" feature). The
// ref is the index form "treasury/3"; keys rejects a purely-numeric or colliding
// alias (usage.name_collision, exit 2).
func (s *Service) AccountAlias(ctx context.Context, p domain.Principal, req domain.AccountAliasRequest) (domain.AccountAliasResult, error) {
	ref, err := domain.ParseAccountRef(req.Ref)
	if err != nil {
		return domain.AccountAliasResult{}, err
	}
	if ref.Kind != domain.RefHDIndex {
		return domain.AccountAliasResult{}, domain.Newf("usage.bad_account_ref",
			"alias target %q must be an HD index (wallet/N)", req.Ref)
	}
	if err := s.keys.Alias(ctx, ref.Wallet, ref.Index, req.Alias); err != nil {
		return domain.AccountAliasResult{}, err
	}
	info, err := s.keys.ShowAccount(ctx, ref)
	if err != nil {
		return domain.AccountAliasResult{}, err
	}
	return domain.AccountAliasResult{
		Ref:     ref.Wallet + "/" + req.Alias,
		Alias:   req.Alias,
		Address: info.Address.Hex(),
	}, nil
}

// AccountUnalias removes an index's alias (the index itself survives — it is
// keystore metadata, §3.1). The ref may be the alias form "treasury/payroll" or
// the index form; either resolves to the index keys forgets the alias on.
func (s *Service) AccountUnalias(ctx context.Context, p domain.Principal, req domain.AccountUnaliasRequest) (domain.AccountUnaliasResult, error) {
	ref, err := domain.ParseAccountRef(req.Ref)
	if err != nil {
		return domain.AccountUnaliasResult{}, err
	}
	// Resolve to a concrete (wallet, index): an alias ref needs a lookup; an
	// index ref already carries it.
	info, err := s.keys.ShowAccount(ctx, ref)
	if err != nil {
		return domain.AccountUnaliasResult{}, err
	}
	removed, err := s.keys.Unalias(ctx, info.Wallet, info.Index)
	if err != nil {
		return domain.AccountUnaliasResult{}, err
	}
	return domain.AccountUnaliasResult{
		Wallet:       info.Wallet,
		Index:        info.Index,
		RemovedAlias: removed,
	}, nil
}

// AccountImportInput carries the raw-key + passphrase channels (raw key via
// stdin/file, never a flag value, §3.5).
type AccountImportInput struct {
	KeyStdin bool
	KeyFile  string

	PassphraseStdin bool
	PassphraseFile  string

	ConfirmStdin bool
	ConfirmFile  string
}

// AccountImport imports a standalone account from a raw 32-byte hex private key
// (validated in [1, n-1] by keys), encrypting it to a stock geth v3 file under
// accounts/. The key on stdin marks stdin taken so a passphrase from stdin is a
// hard conflict.
func (s *Service) AccountImport(ctx context.Context, p domain.Principal, req domain.AccountImportRequest, in AccountImportInput, emit domain.EventSink) (domain.AccountImportResult, error) {
	stdinTaken := in.KeyStdin

	rawKey, _, err := s.acquire(secretSpec{
		StdinFlag:   in.KeyStdin,
		FilePath:    in.KeyFile,
		PromptLabel: "Private key (hex): ",
	})
	if err != nil {
		return domain.AccountImportResult{}, err
	}
	defer rawKey.Zero()

	pass, _, err := s.acquire(passphraseSpecWith(in.PassphraseStdin, in.PassphraseFile, stdinTaken))
	if err != nil {
		return domain.AccountImportResult{}, err
	}
	defer pass.Zero()

	if _, eerr := s.ensureInitialized(ctx, pass, in.ConfirmStdin, in.ConfirmFile, stdinTaken); eerr != nil {
		return domain.AccountImportResult{}, eerr
	}

	accountID, addr, err := s.keys.ImportStandalone(ctx, req.Name, rawKey, pass)
	if err != nil {
		return domain.AccountImportResult{}, err
	}
	emitResolved(emit, addr.Hex(), "imported "+req.Name)
	return domain.AccountImportResult{Name: req.Name, Address: addr.Hex(), AccountID: accountID}, nil
}

// AccountUse sets the default account in meta.json (§3.3, §7.7) — a meta.json
// mutation that fails keystore.read_only on a Secret mount (workaround:
// DAXIE_ACCOUNT). The ref must resolve to a signing identity.
func (s *Service) AccountUse(ctx context.Context, p domain.Principal, req domain.AccountUseRequest) (domain.AccountUseResult, error) {
	ref, err := domain.ParseAccountRef(req.Ref)
	if err != nil {
		return domain.AccountUseResult{}, err
	}
	info, err := s.keys.ShowAccount(ctx, ref)
	if err != nil {
		return domain.AccountUseResult{}, err
	}
	if err := s.keys.SetDefault(ctx, ref); err != nil {
		return domain.AccountUseResult{}, err
	}
	return domain.AccountUseResult{Ref: req.Ref, Address: info.Address.Hex()}, nil
}

// AccountList lists all accounts (HD + standalone), optionally filtered to one
// wallet, with the active default marked. Read-only.
func (s *Service) AccountList(ctx context.Context, p domain.Principal, req domain.AccountListRequest) (domain.AccountListResult, error) {
	infos, err := s.keys.ListAccounts(ctx, req.Wallet)
	if err != nil {
		return domain.AccountListResult{}, err
	}
	def := s.activeDefault(ctx)
	out := domain.AccountListResult{
		Accounts: make([]domain.AccountSummary, 0, len(infos)),
		Default:  def,
	}
	for _, a := range infos {
		sum := accountSummary(a)
		if def != "" && a.Ref == def {
			sum.Default = true
		}
		out.Accounts = append(out.Accounts, sum)
	}
	sortAccounts(out.Accounts)
	return out, nil
}

// AccountShow returns one account's address, path, and metadata. Read-only; the
// QR rendering is a frontend concern (req.QR is render-only and never reaches
// keys).
func (s *Service) AccountShow(ctx context.Context, p domain.Principal, req domain.AccountShowRequest) (domain.AccountShowResult, error) {
	ref, err := domain.ParseAccountRef(req.Ref)
	if err != nil {
		return domain.AccountShowResult{}, err
	}
	a, err := s.keys.ShowAccount(ctx, ref)
	if err != nil {
		return domain.AccountShowResult{}, err
	}
	def := s.activeDefault(ctx)
	out := domain.AccountShowResult{
		Ref:     a.Ref,
		Address: a.Address.Hex(),
		Kind:    a.Kind,
		Wallet:  a.Wallet,
		Alias:   a.Alias,
		Path:    a.Path,
		Default: def != "" && a.Ref == def,
	}
	if a.Kind == "hd" {
		out.Index = uptr(a.Index)
	}
	return out, nil
}

// AccountExportInput carries the freshly-resolved passphrase channel (export never
// reuses a cached unlock, §3.9).
type AccountExportInput struct {
	PassphraseStdin bool
	PassphraseFile  string
}

// AccountExport prints a standalone account's raw private key (stdout only, never
// a file, never journaled, §3.9). HD accounts cannot export here — export the
// wallet mnemonic instead; keys returns ref.not_found / a usage error for an HD
// ref. The confirm ceremony (typed name / --yes) is the frontend's.
func (s *Service) AccountExport(ctx context.Context, p domain.Principal, req domain.AccountExportRequest, in AccountExportInput) (domain.AccountExportResult, error) {
	ref, err := domain.ParseAccountRef(req.Ref)
	if err != nil {
		return domain.AccountExportResult{}, err
	}
	pass, _, err := s.acquire(passphraseSpecWith(in.PassphraseStdin, in.PassphraseFile, false))
	if err != nil {
		return domain.AccountExportResult{}, err
	}
	defer pass.Zero()

	key, err := s.keys.ExportStandalone(ctx, ref, pass)
	if err != nil {
		return domain.AccountExportResult{}, err
	}
	defer key.Zero()

	// Resolve the address for the echo (no unlock needed).
	addr, _ := s.keys.AddressOf(ref)
	return domain.AccountExportResult{
		Ref:        req.Ref,
		Address:    addr.Hex(),
		PrivateKey: string(key.Reveal()),
		Sensitive:  true,
	}, nil
}

// AccountDelete forgets an HD index (the mnemonic still holds it) or removes a
// standalone key file; keys reports which mode it took. The confirm ceremony is
// the frontend's.
func (s *Service) AccountDelete(ctx context.Context, p domain.Principal, req domain.AccountDeleteRequest) (domain.AccountDeleteResult, error) {
	ref, err := domain.ParseAccountRef(req.Ref)
	if err != nil {
		return domain.AccountDeleteResult{}, err
	}
	mode, err := s.keys.DeleteAccount(ctx, ref)
	if err != nil {
		return domain.AccountDeleteResult{}, err
	}
	return domain.AccountDeleteResult{Ref: req.Ref, Mode: mode, Deleted: true}, nil
}

// ── shared helpers ───────────────────────────────────────────────────────────

// activeDefault resolves the §7.7 default-account precedence: the frontend's
// flag>env value (service.account) first, else meta.json default_account.
func (s *Service) activeDefault(ctx context.Context) string {
	if s.account != "" {
		return s.account
	}
	if d, ok := s.keys.DefaultAccount(ctx); ok {
		return d
	}
	return ""
}

// accountSummary maps a keys.AccountInfo into the wire summary.
func accountSummary(a keysAccountInfo) domain.AccountSummary {
	sum := domain.AccountSummary{
		Ref:       a.Ref,
		Address:   a.Address.Hex(),
		Kind:      a.Kind,
		Wallet:    a.Wallet,
		Alias:     a.Alias,
		CreatedAt: a.CreatedAt.UTC().Format(rfc3339),
	}
	if a.Kind == "hd" {
		sum.Index = uptr(a.Index)
	}
	return sum
}

// sortAccounts gives a stable display order: by wallet, then index, then name, so
// human + --json output is deterministic across runs (a map iteration in keys is
// not).
func sortAccounts(as []domain.AccountSummary) {
	sort.SliceStable(as, func(i, j int) bool {
		if as[i].Wallet != as[j].Wallet {
			return as[i].Wallet < as[j].Wallet
		}
		ii, ij := uint32(0), uint32(0)
		if as[i].Index != nil {
			ii = *as[i].Index
		}
		if as[j].Index != nil {
			ij = *as[j].Index
		}
		if ii != ij {
			return ii < ij
		}
		return as[i].Ref < as[j].Ref
	})
}

// utoa formats a uint32 as decimal without strconv (keeps the surface minimal and
// matches domain's tiny-itoa convention).
func utoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// uptr returns a pointer to a copy of n (for the *uint32 wire fields that
// distinguish "index 0" from "no index").
func uptr(n uint32) *uint32 { v := n; return &v }
