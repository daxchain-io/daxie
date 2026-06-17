package service

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/daxchain-io/daxie/internal/domain"
)

// The resolved-destination echo must print the 0x address exactly once. The
// regression: destLabel already embeds the address for a named dest (contact/ENS),
// so the old emitResolved call appended it a SECOND time — "to payee.eth (0x…)
// (0x…)". emitResolvedDest carries the address through destLabel only and populates
// the structured Address field, so it appears once on the human line.
func TestEmitResolvedDestAddressOnce(t *testing.T) {
	addr := common.HexToAddress("0x52908400098527886E0F7030069857D2E4169EE7")
	hex := addr.Hex()

	cases := []struct {
		name   string
		prefix string
		dest   domain.Dest
	}{
		{
			name:   "contact",
			prefix: "to ",
			dest:   domain.Dest{Address: addr, Name: "alice", Via: "contact"},
		},
		{
			name:   "ens",
			prefix: "to ",
			dest:   domain.Dest{Address: addr, Name: "payee.eth", Via: "ens", ENSName: "payee.eth"},
		},
		{
			name:   "literal",
			prefix: "to ",
			dest:   domain.Dest{Address: addr, Via: "literal"},
		},
		{
			name:   "spender-contact",
			prefix: "spender ",
			dest:   domain.Dest{Address: addr, Name: "router", Via: "contact"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c collectSink
			emitResolvedDest(c.sink(), tc.prefix, tc.dest)

			if len(c.ev) != 1 {
				t.Fatalf("expected exactly one event, got %d", len(c.ev))
			}
			ev := c.ev[0]
			if ev.Kind != domain.EvResolved {
				t.Fatalf("kind = %v, want EvResolved", ev.Kind)
			}
			// The address must appear exactly once on the echo (humanEventLine renders
			// "resolved: " + Detail verbatim, so counting in Detail is the echo line).
			if n := strings.Count(ev.Detail, hex); n != 1 {
				t.Errorf("address %s appears %d times in echo detail %q, want exactly 1", hex, n, ev.Detail)
			}
			if !strings.HasPrefix(ev.Detail, tc.prefix) {
				t.Errorf("detail %q missing prefix %q", ev.Detail, tc.prefix)
			}
			// The structured Address field stays populated for any consumer that prefers
			// it to parsing Detail.
			if ev.Address != addr {
				t.Errorf("Address field = %s, want %s", ev.Address.Hex(), hex)
			}
		})
	}
}

// emitResolvedDest is nil-tolerant like emitResolved (the core's nil-sink Emit
// contract): a nil sink is a no-op, not a panic.
func TestEmitResolvedDestNilSink(t *testing.T) {
	emitResolvedDest(nil, "to ", domain.Dest{Address: common.HexToAddress("0x1")})
}
