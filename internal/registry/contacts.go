package registry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/daxchain-io/daxie/internal/fsx"
	"github.com/ethereum/go-ethereum/common"
)

// contactsVersion is the on-disk schema version (§7.8). A file with a higher
// version is refused (a newer binary wrote it) — fail closed rather than silently
// drop a field a future schema added.
const contactsVersion = 1

// Contact is one address-book entry (§7.8). Name follows the §3.1 grammar, stored
// lowercase, matched case-insensitively. ENS + PinnedAt are the M7 pin half — the
// fields are present in the schema now (so an M7 binary reads/writes the same
// file shape) but an M3 contact is just name + address; ENS-backed adds are M7.
type Contact struct {
	Name     string         `json:"name"`
	Address  common.Address `json:"address"`
	ENS      string         `json:"ens,omitempty"`
	PinnedAt string         `json:"pinned_at,omitempty"`
}

// contactsFile is the on-disk envelope (§7.8): {"v":1,"contacts":[…]}.
type contactsFile struct {
	V        int       `json:"v"`
	Contacts []Contact `json:"contacts"`
}

// Contacts is the network-agnostic contacts store (state class). It holds no
// long-lived fd: every operation opens, (for mutations) locks, reads, writes,
// releases — so concurrent daxie processes serialize cleanly on the registry
// flock.
type Contacts struct {
	registryDir string
}

// OpenContacts binds to <registryDir>/contacts.json. Lazy: it creates nothing on
// disk; a missing file reads as empty (a fresh install). The registryDir is
// config.Paths.RegistryDir (DAXIE_REGISTRY_DIR or <State>/registry).
func OpenContacts(registryDir string) (*Contacts, error) {
	return &Contacts{registryDir: registryDir}, nil
}

// path is <registryDir>/contacts.json.
func (c *Contacts) path() string { return filepath.Join(c.registryDir, "contacts.json") }

// Add writes a name→address entry under the registry lock via fsx.WriteAtomic. It
// validates the §3.1 name grammar (usage.* exit 2 on a bad name); a duplicate
// name (case-insensitive) is usage.duplicate (exit 2); a read-only state mount
// fails with the state-class read-only sibling of config.read_only (exit 10,
// §7.8). The cross-namespace collision guard (contact vs wallet/standalone) is
// the AUTHORITATIVE responsibility of service's destination-context ref.ambiguous
// rule (§3.2) — this store enforces only the within-contacts duplicate; service
// layers the keystore-collision check on top at add time (best-effort, §3.2).
func (c *Contacts) Add(ctx context.Context, name string, addr common.Address) error {
	return c.add(ctx, name, addr, "", "")
}

// AddWithENS is the M7 ENS-backed add: it pins the resolved 0x address (the
// snapshot — §4.8: store the resolved address, never a bare name) AND records the
// source ENS name + resolved-at timestamp for display and the contact's half of the
// pin story. A later send to the contact re-resolves the contact (the snapshot) and
// the §4.3 stage-4 contact_drift check refuses if it moved. The ENS string is
// display/provenance only; the authoritative destination is always the pinned addr.
func (c *Contacts) AddWithENS(ctx context.Context, name string, addr common.Address, ens, pinnedAt string) error {
	return c.add(ctx, name, addr, ens, pinnedAt)
}

// add is the shared add path: canonicalize, lock, duplicate-guard, append, save.
func (c *Contacts) add(ctx context.Context, name string, addr common.Address, ens, pinnedAt string) error {
	canon, err := canonicalName(name)
	if err != nil {
		return err
	}
	return withRegistryLock(ctx, c.registryDir, func() error {
		f, lerr := c.load()
		if lerr != nil {
			return lerr
		}
		for _, existing := range f.Contacts {
			if existing.Name == canon {
				return domain.Newf(domain.CodeUsage+".duplicate",
					"a contact named %q already exists; remove it first or choose another name", canon)
			}
		}
		f.Contacts = append(f.Contacts, Contact{Name: canon, Address: addr, ENS: ens, PinnedAt: pinnedAt})
		return c.save(f)
	})
}

// List returns all contacts, name-sorted (backs `contacts list`). A missing file
// is an empty list. Reads are lock-free on POSIX (every write is atomic); on
// Windows fsx's RLock-on-read discipline lives in the shared read path — contacts
// reads go through os.ReadFile which the atomic-rename writer is compatible with
// (the writer uses MoveFileEx; readers tolerate the brief replace).
func (c *Contacts) List(ctx context.Context) ([]Contact, error) {
	_ = ctx
	f, err := c.load()
	if err != nil {
		return nil, err
	}
	out := append([]Contact(nil), f.Contacts...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Show returns one contact by name (case-insensitive), or ref.not_found (exit 10)
// (backs `contacts show`).
func (c *Contacts) Show(ctx context.Context, name string) (Contact, error) {
	_ = ctx
	canon, err := canonicalName(name)
	if err != nil {
		return Contact{}, err
	}
	f, err := c.load()
	if err != nil {
		return Contact{}, err
	}
	for _, ct := range f.Contacts {
		if ct.Name == canon {
			return ct, nil
		}
	}
	return Contact{}, notFound(canon)
}

// Remove deletes a contact by name (case-insensitive) under the registry lock, or
// ref.not_found (exit 10) (backs `contacts remove`).
func (c *Contacts) Remove(ctx context.Context, name string) error {
	canon, err := canonicalName(name)
	if err != nil {
		return err
	}
	return withRegistryLock(ctx, c.registryDir, func() error {
		f, lerr := c.load()
		if lerr != nil {
			return lerr
		}
		idx := -1
		for i, ct := range f.Contacts {
			if ct.Name == canon {
				idx = i
				break
			}
		}
		if idx < 0 {
			return notFound(canon)
		}
		f.Contacts = append(f.Contacts[:idx], f.Contacts[idx+1:]...)
		return c.save(f)
	})
}

// Resolve maps a --to contact name to its address (case-insensitive), reporting
// found. service's SendTx destination resolution tries, in order: 0x literal →
// contact name (this) → ENS (M7, fail-clean). A not-found here is NOT an error
// (found=false, nil) — the caller falls through to the next resolver; a name that
// matches NOTHING anywhere is service's error to raise (ref.not_found /
// ref.ambiguous, §3.2). A name that fails the grammar resolves as not-found
// rather than erroring, so an address or ENS input that was never a contact name
// still falls through cleanly.
func (c *Contacts) Resolve(ctx context.Context, name string) (common.Address, bool, error) {
	_ = ctx
	canon, err := canonicalName(name)
	if err != nil {
		// Not a valid contact name ⇒ it is not in the book; fall through (no error).
		return common.Address{}, false, nil
	}
	f, lerr := c.load()
	if lerr != nil {
		return common.Address{}, false, lerr
	}
	for _, ct := range f.Contacts {
		if ct.Name == canon {
			return ct.Address, true, nil
		}
	}
	return common.Address{}, false, nil
}

// load reads and parses contacts.json. A missing file is an empty, current-version
// envelope (lazy, fresh install). A higher on-disk version is refused (fail
// closed). A corrupt file is state.corrupt (exit 11). The caller need not hold the
// lock for a read, but mutations call load while holding it.
func (c *Contacts) load() (*contactsFile, error) {
	b, err := os.ReadFile(c.path())
	if err != nil {
		if os.IsNotExist(err) {
			return &contactsFile{V: contactsVersion}, nil
		}
		return nil, domain.Wrap("state.corrupt", "cannot read the contacts file", err)
	}
	var f contactsFile
	if jerr := json.Unmarshal(b, &f); jerr != nil {
		return nil, domain.Wrap("state.corrupt", "the contacts file is corrupt (not valid JSON)", jerr)
	}
	if f.V > contactsVersion {
		return nil, domain.Newf("state.corrupt",
			"the contacts file is schema version %d, newer than this binary supports (%d); upgrade daxie",
			f.V, contactsVersion)
	}
	return &f, nil
}

// save atomically writes contacts.json (0600) under the registry lock (the caller
// holds it). A read-only mount maps to the state-class read-only sibling (exit
// 10). It MkdirAll's the registry dir first (lazy creation, §7.3).
func (c *Contacts) save(f *contactsFile) error {
	f.V = contactsVersion
	if err := fsx.MkdirAll(c.registryDir, dirMode); err != nil {
		if fsx.IsReadOnly(err) {
			return errReadOnly()
		}
		return domain.Wrap("state.corrupt", "cannot create the registry directory", err)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return domain.Wrap("state.corrupt", "cannot encode the contacts file", err)
	}
	if werr := fsx.WriteAtomic(c.path(), b, fileMode); werr != nil {
		if fsx.IsReadOnly(werr) {
			return errReadOnly()
		}
		return domain.Wrap("state.corrupt", "cannot write the contacts file", werr)
	}
	return nil
}

// notFound is the ref.not_found error for a missing contact (exit 10).
func notFound(name string) error {
	return domain.Newf(domain.CodeRefNotFound, "no contact named %q", name)
}

// canonicalName lowercases and validates a contact name against the §3.1 grammar:
// [a-z0-9][a-z0-9_-]{0,63}, with '.', '#', '/' reserved (they are the
// reference-syntax separators), and a name matching the 0x+40-hex address shape
// rejected (it would be read as an address in a destination position). Stored
// lowercase, matched case-insensitively (default macOS/Windows filesystems are
// case-insensitive, §3.1). Returns a usage.* error (exit 2) for a bad name.
func canonicalName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", domain.New(domain.CodeUsage+".empty_name", "contact name is empty")
	}
	lower := strings.ToLower(trimmed)

	// Reject the address shape outright (a 0x+40-hex name would be ambiguous with a
	// raw address in a --to position, §3.1).
	if common.IsHexAddress(lower) {
		return "", domain.Newf(domain.CodeUsage+".bad_name",
			"contact name %q looks like an address; choose a name", name)
	}

	if len(lower) > 64 {
		return "", domain.Newf(domain.CodeUsage+".bad_name",
			"contact name %q is too long (max 64 characters)", name)
	}

	for i := 0; i < len(lower); i++ {
		ch := lower[i]
		isLowerAlnum := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
		if i == 0 {
			// First char must be alphanumeric (no leading '-'/'_', no reserved char).
			if !isLowerAlnum {
				return "", domain.Newf(domain.CodeUsage+".bad_name",
					"contact name %q must start with a letter or digit", name)
			}
			continue
		}
		if isLowerAlnum || ch == '-' || ch == '_' {
			continue
		}
		// '.', '#', '/' (and anything else) are reserved/invalid.
		return "", domain.Newf(domain.CodeUsage+".bad_name",
			"contact name %q contains an invalid character %q (allowed: letters, digits, '-', '_')", name, string(ch))
	}
	return lower, nil
}
