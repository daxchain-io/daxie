package service

import (
	"testing"
	"time"
)

// floorPoll guards the poll loops against a non-positive (or sub-floor) cadence
// reaching the ctx-aware sleeper, which treats d<=0 as an immediate yield and
// would busy-spin the receive/tx-wait loops. A value from env or a hand-edited
// config.toml bypasses the `config set` bounds check, so this use-time floor is the
// backstop.
func TestFloorPoll(t *testing.T) {
	cases := []struct {
		in, want time.Duration
	}{
		{-5 * time.Second, minPollInterval}, // negative → floored
		{0, minPollInterval},                // zero (the busy-loop trigger) → floored
		{50 * time.Millisecond, minPollInterval},
		{minPollInterval, minPollInterval}, // exactly the floor passes through
		{4 * time.Second, 4 * time.Second}, // a normal cadence is unchanged
		{2 * time.Minute, 2 * time.Minute},
	}
	for _, c := range cases {
		if got := floorPoll(c.in); got != c.want {
			t.Errorf("floorPoll(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
