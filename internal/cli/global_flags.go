package cli

import (
	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/service"
)

// FlagValues holds the global persistent flags bound on the root command. It is
// the cli frontend's own struct (the frontend imports only service + domain +
// render + version, never the config provider — the arch matrix forbids that
// edge). The path/network subset is projected into service.Options, which is the
// only thing service.Open consumes; Viper never escapes internal/config
// (§2.2 rule 5).
type FlagValues struct {
	JSON     bool   // --json: machine output
	Quiet    bool   // --quiet: suppress non-essential human lines
	Network  string // --network: default-network override (the per-call chain)
	RPC      string // --rpc: per-invocation endpoint override (selects an ENDPOINT, never a network)
	Config   string // --config: config file or dir
	Keystore string // --keystore: keystore dir
	StateDir string // --state-dir: mutable state dir
	Yes      bool   // --yes: skip confirmations (required for mutating ops non-interactively)

	// Account is the §7.7 active-account override (--from/--account). M1 binds no
	// command-level --from yet (its first consumer is tx, M3); open.go fills the
	// service Account slot from this plus DAXIE_ACCOUNT so the default-account
	// precedence (flag>env>meta.json) is wired from M1. Empty in M1 unless
	// DAXIE_ACCOUNT is set.
	Account string
}

// ServiceOptions projects the path/network subset (plus a clock the caller fills)
// into the service composition input. The output flags (--json/--quiet/--yes) are
// frontend-only and never cross into the core.
func (f FlagValues) ServiceOptions() service.Options {
	return service.Options{
		Config:   f.Config,
		Keystore: f.Keystore,
		StateDir: f.StateDir,
		Network:  f.Network,
		RPC:      f.RPC,
	}
}

// Mode projects the output-style subset the render package threads.
func (f FlagValues) Mode() render.Mode {
	return render.Mode{JSON: f.JSON, Quiet: f.Quiet}
}
