package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// contacts_test.go drives the `daxie contacts` surface through the real Execute
// funnel. Contacts are network-agnostic local state (no RPC needed), so the full
// add/list/show/remove round-trip runs against an isolated state dir — exercising
// the cli host, the service use cases, and the registry store together.

const testAddr = "0x52908400098527886E0F7030069857D2E4169EE7"

// add → list → show → remove round-trips with the address echoed.
func TestContactsRoundTrip(t *testing.T) {
	isolateEnv(t)

	if _, _, code := execCLI(t, "contacts", "add", "exchange", testAddr); code != int(domain.ExitOK) {
		t.Fatalf("contacts add exit = %d, want 0", code)
	}

	out, _, code := execCLI(t, "contacts", "list", "--json")
	if code != int(domain.ExitOK) {
		t.Fatalf("contacts list exit = %d, want 0", code)
	}
	var lr domain.ContactListResult
	if err := json.Unmarshal([]byte(out), &lr); err != nil {
		t.Fatalf("contacts list --json not valid JSON: %v (%q)", err, out)
	}
	found := false
	for _, c := range lr.Contacts {
		if c.Name == "exchange" {
			found = true
		}
	}
	if !found {
		t.Errorf("contacts list missing the added 'exchange' contact: %q", out)
	}

	out, _, code = execCLI(t, "contacts", "show", "exchange", "--json")
	if code != int(domain.ExitOK) {
		t.Fatalf("contacts show exit = %d, want 0", code)
	}
	var sr domain.ContactResult
	if err := json.Unmarshal([]byte(out), &sr); err != nil {
		t.Fatalf("contacts show --json not valid JSON: %v (%q)", err, out)
	}
	if !strings.EqualFold(sr.Contact.Address, testAddr) {
		t.Errorf("contacts show address = %q, want %q", sr.Contact.Address, testAddr)
	}

	// remove needs --yes (non-interactive); then show fails not-found.
	if _, _, code := execCLI(t, "contacts", "remove", "exchange", "--yes"); code != int(domain.ExitOK) {
		t.Fatalf("contacts remove exit = %d, want 0", code)
	}
	if _, _, code := execCLI(t, "contacts", "show", "exchange"); code != int(domain.ExitNotFound) {
		t.Fatalf("contacts show after remove: exit = %d, want %d (NOT_FOUND)", code, domain.ExitNotFound)
	}
}

// show / remove of an unknown contact → exit 10 (ref.not_found).
func TestContactsShowUnknown(t *testing.T) {
	isolateEnv(t)
	if _, _, code := execCLI(t, "contacts", "show", "ghost"); code != int(domain.ExitNotFound) {
		t.Fatalf("exit = %d, want %d (NOT_FOUND)", code, domain.ExitNotFound)
	}
}

// A duplicate add is a usage error (exit 2).
func TestContactsDuplicateAdd(t *testing.T) {
	isolateEnv(t)
	if _, _, code := execCLI(t, "contacts", "add", "dup", testAddr); code != int(domain.ExitOK) {
		t.Fatalf("first add exit = %d, want 0", code)
	}
	if _, _, code := execCLI(t, "contacts", "add", "dup", testAddr); code != int(domain.ExitUsage) {
		t.Fatalf("duplicate add exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// add requires exactly two args (name + address).
func TestContactsAddArgCount(t *testing.T) {
	isolateEnv(t)
	if _, _, code := execCLI(t, "contacts", "add", "onlyname"); code != int(domain.ExitUsage) {
		t.Fatalf("one-arg add exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// The contacts tree exposes the documented subcommands.
func TestContactsHelp(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "contacts", "--help")
	if code != int(domain.ExitOK) {
		t.Fatalf("contacts --help exit = %d, want 0", code)
	}
	for _, sub := range []string{"add", "list", "show", "remove"} {
		if !strings.Contains(out, sub) {
			t.Errorf("contacts --help missing subcommand %q:\n%s", sub, out)
		}
	}
}
