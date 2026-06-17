package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

func newContacts(t *testing.T) (*Contacts, string) {
	t.Helper()
	dir := t.TempDir()
	c, err := OpenContacts(dir)
	if err != nil {
		t.Fatalf("OpenContacts: %v", err)
	}
	return c, dir
}

var (
	addrExchange = common.HexToAddress("0xABC0000000000000000000000000000000000DEF")
	addrVitalik  = common.HexToAddress("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")
)

// TestAddListShowRemoveRoundTrip walks the full CRUD lifecycle.
func TestAddListShowRemoveRoundTrip(t *testing.T) {
	c, _ := newContacts(t)
	ctx := context.Background()

	// Empty store: List is empty, Show/Remove are not_found.
	list, err := c.List(ctx)
	if err != nil {
		t.Fatalf("List (empty): %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("fresh store should be empty, got %d", len(list))
	}
	if _, err := c.Show(ctx, "nobody"); !isCode(err, domain.CodeRefNotFound) {
		t.Fatalf("Show on empty store: want ref.not_found, got %v", err)
	}

	if err := c.Add(ctx, "exchange", addrExchange); err != nil {
		t.Fatalf("Add exchange: %v", err)
	}
	if err := c.Add(ctx, "vitalik", addrVitalik); err != nil {
		t.Fatalf("Add vitalik: %v", err)
	}

	// List is name-sorted.
	list, err = c.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 || list[0].Name != "exchange" || list[1].Name != "vitalik" {
		t.Fatalf("List not name-sorted: %+v", list)
	}

	// Show returns the entry.
	got, err := c.Show(ctx, "exchange")
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if got.Address != addrExchange {
		t.Fatalf("Show address = %s, want %s", got.Address, addrExchange)
	}

	// Remove drops it; the other survives.
	if err := c.Remove(ctx, "exchange"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := c.Show(ctx, "exchange"); !isCode(err, domain.CodeRefNotFound) {
		t.Fatalf("Show after Remove: want ref.not_found, got %v", err)
	}
	list, err = c.List(ctx)
	if err != nil {
		t.Fatalf("List after Remove: %v", err)
	}
	if len(list) != 1 || list[0].Name != "vitalik" {
		t.Fatalf("List after Remove wrong: %+v", list)
	}

	// Remove of a missing contact is not_found.
	if err := c.Remove(ctx, "exchange"); !isCode(err, domain.CodeRefNotFound) {
		t.Fatalf("Remove missing: want ref.not_found, got %v", err)
	}
}

// TestDurableAcrossReopen confirms contacts persist across a re-Open (a fresh
// process sees a previously-added contact).
func TestDurableAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	c1, err := OpenContacts(dir)
	if err != nil {
		t.Fatalf("OpenContacts c1: %v", err)
	}
	if err := c1.Add(ctx, "exchange", addrExchange); err != nil {
		t.Fatalf("Add: %v", err)
	}

	c2, err := OpenContacts(dir)
	if err != nil {
		t.Fatalf("OpenContacts c2: %v", err)
	}
	got, err := c2.Show(ctx, "exchange")
	if err != nil {
		t.Fatalf("Show after re-Open: %v", err)
	}
	if got.Address != addrExchange {
		t.Fatalf("re-Open lost the address: %s", got.Address)
	}
}

// TestCaseFoldMatching confirms names are stored lowercase and matched
// case-insensitively (add "Exchange", show "EXCHANGE").
func TestCaseFoldMatching(t *testing.T) {
	c, _ := newContacts(t)
	ctx := context.Background()

	if err := c.Add(ctx, "Exchange", addrExchange); err != nil {
		t.Fatalf("Add Exchange: %v", err)
	}
	got, err := c.Show(ctx, "EXCHANGE")
	if err != nil {
		t.Fatalf("Show EXCHANGE: %v", err)
	}
	if got.Name != "exchange" {
		t.Fatalf("stored name = %q, want lowercase %q", got.Name, "exchange")
	}
	if got.Address != addrExchange {
		t.Fatalf("address mismatch")
	}

	// Resolve is also case-insensitive.
	addr, found, err := c.Resolve(ctx, "ExChAnGe")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !found || addr != addrExchange {
		t.Fatalf("Resolve mixed-case failed: found=%v addr=%s", found, addr)
	}
}

// TestDuplicateNameRejected confirms a duplicate name (case-insensitive) is a
// usage error (exit 2).
func TestDuplicateNameRejected(t *testing.T) {
	c, _ := newContacts(t)
	ctx := context.Background()

	if err := c.Add(ctx, "exchange", addrExchange); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Same name, different case ⇒ duplicate.
	err := c.Add(ctx, "Exchange", addrVitalik)
	if !isExit(err, domain.ExitUsage) {
		t.Fatalf("duplicate add: want exit 2 (usage), got %v", err)
	}
	if !isCodePrefix(err, "usage") {
		t.Fatalf("duplicate add code should be usage.*, got %v", err)
	}

	// The original is untouched.
	got, err := c.Show(ctx, "exchange")
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if got.Address != addrExchange {
		t.Fatalf("duplicate add corrupted the original address: %s", got.Address)
	}
}

// TestNameGrammar exercises the §3.1 grammar: valid names accepted, reserved
// chars / leading punctuation / address-shape / empty / too-long rejected.
func TestNameGrammar(t *testing.T) {
	ctx := context.Background()

	valid := []string{"a", "exchange", "cold-wallet", "vault_2", "x1", "alice-bob_99"}
	for _, name := range valid {
		c, _ := newContacts(t)
		if err := c.Add(ctx, name, addrExchange); err != nil {
			t.Fatalf("valid name %q rejected: %v", name, err)
		}
	}

	invalid := []string{
		"",            // empty
		"   ",         // whitespace only
		"-leading",    // leading '-'
		"_leading",    // leading '_'
		"has.dot",     // '.' reserved (ENS separator)
		"has#hash",    // '#' reserved
		"has/slash",   // '/' reserved (HD separator)
		"vitalik.eth", // ENS-shaped (the '.' rule covers it)
		"wallet/0",    // HD ref shape
		"has space",   // whitespace inside
		"0xABC0000000000000000000000000000000000DEF", // address shape
	}
	for _, name := range invalid {
		c, _ := newContacts(t)
		err := c.Add(ctx, name, addrExchange)
		if err == nil {
			t.Fatalf("invalid name %q was accepted", name)
		}
		if !isExit(err, domain.ExitUsage) {
			t.Fatalf("invalid name %q: want exit 2 (usage), got %v", name, err)
		}
	}

	// Too long (65 chars).
	c, _ := newContacts(t)
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	if err := c.Add(ctx, string(long), addrExchange); !isExit(err, domain.ExitUsage) {
		t.Fatalf("65-char name: want exit 2, got %v", err)
	}
	// Exactly 64 is allowed.
	c2, _ := newContacts(t)
	if err := c2.Add(ctx, string(long[:64]), addrExchange); err != nil {
		t.Fatalf("64-char name should be valid: %v", err)
	}
}

// TestResolveFallsThrough confirms Resolve returns found=false (NOT an error) for
// a name not in the book and for non-name inputs (an address / ENS literal), so
// service's resolver chain (0x → contact → ENS) can fall through cleanly.
func TestResolveFallsThrough(t *testing.T) {
	c, _ := newContacts(t)
	ctx := context.Background()

	for _, in := range []string{
		"nobody", // valid name, not in the book
		"0xABC0000000000000000000000000000000000DEF", // an address literal
		"vitalik.eth", // an ENS literal
		"",            // empty
	} {
		addr, found, err := c.Resolve(ctx, in)
		if err != nil {
			t.Fatalf("Resolve(%q) returned an error; it must fall through: %v", in, err)
		}
		if found {
			t.Fatalf("Resolve(%q) reported found=true on an empty book", in)
		}
		if addr != (common.Address{}) {
			t.Fatalf("Resolve(%q) returned a non-zero address while not found", in)
		}
	}
}

// TestPerStoreIsolation confirms two contacts stores on different registry dirs do
// not see each other's entries (per-directory isolation; the network-agnostic
// contacts file is keyed by the registry dir / DAXIE_REGISTRY_DIR).
func TestPerStoreIsolation(t *testing.T) {
	ctx := context.Background()
	dirA := t.TempDir()
	dirB := t.TempDir()

	ca, err := OpenContacts(dirA)
	if err != nil {
		t.Fatalf("OpenContacts A: %v", err)
	}
	cb, err := OpenContacts(dirB)
	if err != nil {
		t.Fatalf("OpenContacts B: %v", err)
	}

	if err := ca.Add(ctx, "exchange", addrExchange); err != nil {
		t.Fatalf("Add to A: %v", err)
	}

	// B must not see A's contact.
	if _, err := cb.Show(ctx, "exchange"); !isCode(err, domain.CodeRefNotFound) {
		t.Fatalf("store B saw store A's contact: %v", err)
	}
	listB, err := cb.List(ctx)
	if err != nil {
		t.Fatalf("List B: %v", err)
	}
	if len(listB) != 0 {
		t.Fatalf("store B should be empty, got %d", len(listB))
	}
}

// TestOnDiskSchema confirms the §7.8 on-disk shape: {"v":1,"contacts":[{name,address}]}
// with the address as a 0x string.
func TestOnDiskSchema(t *testing.T) {
	c, dir := newContacts(t)
	ctx := context.Background()
	if err := c.Add(ctx, "exchange", addrExchange); err != nil {
		t.Fatalf("Add: %v", err)
	}

	b, err := os.ReadFile(filepath.Join(dir, "contacts.json"))
	if err != nil {
		t.Fatalf("read contacts.json: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"v": 1`, `"name": "exchange"`, `"address": "0x`} {
		if !contains(s, want) {
			t.Fatalf("contacts.json missing %q; got:\n%s", want, s)
		}
	}
}

// TestCorruptFileIsStateError confirms a non-JSON contacts file fails closed as a
// state error (not a panic, not silent loss).
func TestCorruptFileIsStateError(t *testing.T) {
	c, dir := newContacts(t)
	ctx := context.Background()
	if err := os.WriteFile(filepath.Join(dir, "contacts.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if _, err := c.List(ctx); !isCode(err, "state.corrupt") {
		t.Fatalf("corrupt file: want state.corrupt, got %v", err)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func isCode(err error, code string) bool {
	var de *domain.Error
	return errors.As(err, &de) && de.Code == code
}

func isCodePrefix(err error, prefix string) bool {
	var de *domain.Error
	if !errors.As(err, &de) {
		return false
	}
	return de.Code == prefix || (len(de.Code) > len(prefix) && de.Code[:len(prefix)+1] == prefix+".")
}

func isExit(err error, exit domain.ExitCode) bool {
	var de *domain.Error
	return errors.As(err, &de) && de.Exit == exit
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
