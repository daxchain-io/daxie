package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDurationRoundTrip(t *testing.T) {
	cases := []struct {
		in       Duration
		wantJSON string
	}{
		{Duration{5 * time.Minute}, `"5m0s"`},
		{Duration{90 * time.Minute}, `"1h30m0s"`},
		{Duration{0}, `"0s"`},
		{Duration{4 * time.Second}, `"4s"`},
		{Duration{30 * time.Second}, `"30s"`},
	}
	for _, c := range cases {
		b, err := json.Marshal(c.in)
		if err != nil {
			t.Fatalf("marshal %v: %v", c.in, err)
		}
		if string(b) != c.wantJSON {
			t.Errorf("Marshal(%v) = %s, want %s", c.in.D, b, c.wantJSON)
		}
		var back Duration
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if back.D != c.in.D {
			t.Errorf("round-trip mismatch: %v -> %s -> %v", c.in.D, b, back.D)
		}
	}
}

// TestDurationAcceptsHumanForms: the unmarshaler accepts the short forms a user
// or config writes, not just the canonical String() output.
func TestDurationAcceptsHumanForms(t *testing.T) {
	cases := []struct {
		json string
		want time.Duration
	}{
		{`"5m"`, 5 * time.Minute},
		{`"1h30m"`, 90 * time.Minute},
		{`"0"`, 0},
		{`"10m"`, 10 * time.Minute},
	}
	for _, c := range cases {
		var d Duration
		if err := json.Unmarshal([]byte(c.json), &d); err != nil {
			t.Fatalf("unmarshal %s: %v", c.json, err)
		}
		if d.D != c.want {
			t.Errorf("Unmarshal(%s) = %v, want %v", c.json, d.D, c.want)
		}
	}
}

// TestDurationRejectsNanosInt: a bare JSON number (nanoseconds) is rejected — the
// wire form is always a string (§2.5 drift hazard).
func TestDurationRejectsNanosInt(t *testing.T) {
	for _, bad := range []string{`300000000000`, `0`, `true`, `null`, `{}`, `"nope"`, `"5"`} {
		var d Duration
		if err := json.Unmarshal([]byte(bad), &d); err == nil {
			t.Errorf("Unmarshal(%s) should error, got d=%v", bad, d.D)
		}
	}
}
