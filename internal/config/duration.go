package config

import "time"

// mustDur parses a duration literal known at compile time (the built-in
// defaults). A bad literal is a programming error, so it panics — these strings
// are constants in this package, never user input.
func mustDur(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic("config: bad built-in duration literal " + s + ": " + err.Error())
	}
	return d
}
