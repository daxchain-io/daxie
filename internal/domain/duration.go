package domain

import (
	"encoding/json"
	"errors"
	"time"
)

// Duration wraps time.Duration so it marshals as a human string ("5m") instead
// of int64 nanoseconds (§2.5). Every wire-facing use carries
// jsonschema:"type=string,format=duration" matching this marshaler, proven by
// the round-trip contract test (§2.9).
type Duration struct{ D time.Duration }

// MarshalJSON emits the Go duration string, e.g. "5m0s"-style canonicalized to
// time.Duration.String(). A zero duration emits "0s".
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.D.String())
}

// UnmarshalJSON accepts a JSON string parsed by time.ParseDuration ("5m",
// "1h30m", "0"). A bare JSON number (nanoseconds) is rejected — the wire form is
// always a string, so an int would mean a producer disagreeing with the schema.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		// Not a JSON string. Reject numbers (and everything else) explicitly so
		// a nanoseconds int can never silently parse.
		return errors.New("domain: duration must be a JSON string like \"5m\"")
	}
	// time.ParseDuration accepts "0" (no unit) as a special case.
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.D = parsed
	return nil
}

// String returns the duration's string form (delegates to time.Duration).
func (d Duration) String() string { return d.D.String() }
