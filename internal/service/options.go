package service

import (
	"time"

	"github.com/daxchain-io/daxie/internal/config"
)

// Options is what Open consumes. The cli frontend builds it from its own global
// flags and hands it in. It carries the resolved path/network flag subset
// DIRECTLY (not a nested config.FlagValues) so the frontend never has to import
// internal/config — the arch matrix forbids any frontend→provider edge, and
// config is a provider. Open translates these fields into config.FlagValues
// internally (config is the only package that touches Viper, §2.2 rule 5).
//
// The design (§2.4) calls the composition input config.Options; the plan's
// signature contract makes the service-owned Options the wire-able shape so the
// frontend stays config-free. M0 keeps it minimal; later milestones grow it with
// provider wiring knobs.
type Options struct {
	// Path/network flag subset (the five resolved-outside-Viper vars, §7.3).
	// Empty strings mean "use the platform/env default".
	Config   string // --config (file or dir)
	Keystore string // --keystore
	StateDir string // --state-dir
	Network  string // --network (default-network override; inert wrt I/O in M0)

	// Clock is the single injected time source (§2.3 determinism guard). The
	// core never calls time.Now directly; it reads wall time only through this
	// function. A nil Clock is replaced inside Open with a determinism-safe
	// fallback (zero clock) — production hosts (cli) always inject time.Now.
	Clock func() time.Time
}

// configFlags projects the path/network subset into the config package's input
// shape. This is the ONLY translation point; it keeps config.FlagValues an
// internal detail of the service↔config edge.
func (o Options) configFlags() config.FlagValues {
	return config.FlagValues{
		Config:   o.Config,
		Keystore: o.Keystore,
		StateDir: o.StateDir,
		Network:  o.Network,
	}
}
