package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// In human mode, send/wait progress events render as short lines on the stderr
// writer (never stdout) — the §5.9 routing rule.
func TestStderrProgressHuman(t *testing.T) {
	var stderr bytes.Buffer
	sink := StderrProgress(&stderr, false)
	if sink == nil {
		t.Fatal("StderrProgress returned nil for a non-nil writer")
	}
	sink(domain.Event{Kind: domain.EvBroadcast, Hash: "0xabc"})
	sink(domain.Event{Kind: domain.EvConfirmation, Conf: 1, Target: 2})
	sink(domain.Event{Kind: domain.EvConfirmation, Conf: 2, Target: 2})

	out := stderr.String()
	for _, want := range []string{"broadcast: 0xabc", "confirmation 1/2", "confirmation 2/2"} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr progress missing %q in:\n%s", want, out)
		}
	}
}

// In --json mode, interim progress is SUPPRESSED entirely: the single JSON result
// object on stdout is the only machine output, and stderr stays quiet for the
// progress kinds (errors still flow through mapError, not this sink).
func TestStderrProgressJSONSuppressesInterim(t *testing.T) {
	var stderr bytes.Buffer
	sink := StderrProgress(&stderr, true)
	sink(domain.Event{Kind: domain.EvResolved, Detail: "exchange"})
	sink(domain.Event{Kind: domain.EvBroadcast, Hash: "0xabc"})
	sink(domain.Event{Kind: domain.EvConfirmation, Conf: 1, Target: 2})
	if stderr.Len() != 0 {
		t.Errorf("--json progress must suppress interim events; stderr = %q", stderr.String())
	}
}

// A nil writer yields a nil (no-op) sink so the core's nil-tolerant Emit contract
// is satisfied.
func TestStderrProgressNilWriter(t *testing.T) {
	if StderrProgress(nil, false) != nil {
		t.Error("StderrProgress(nil, …) must return a nil sink")
	}
}

// An unrecognized event kind is skipped (no noise) so a future milestone's event
// never prints a garbage line.
func TestStderrProgressUnknownKindSkipped(t *testing.T) {
	var stderr bytes.Buffer
	sink := StderrProgress(&stderr, false)
	sink(domain.Event{Kind: domain.EvListening}) // a receive kind, not a send/wait kind
	if stderr.Len() != 0 {
		t.Errorf("unknown send/wait kind must not print; stderr = %q", stderr.String())
	}
}

// The resolved event echoes the contact/ENS detail (the "echo resolved address
// before signing" rule, §5.10).
func TestStderrProgressResolvedEcho(t *testing.T) {
	var stderr bytes.Buffer
	sink := StderrProgress(&stderr, false)
	sink(domain.Event{Kind: domain.EvResolved, Detail: "exchange -> 0xabc"})
	if !strings.Contains(stderr.String(), "resolved: exchange -> 0xabc") {
		t.Errorf("resolved echo missing: %q", stderr.String())
	}
}
