package cli

import (
	"context"
	"os"
)

// Execute is the single entrypoint cmd/daxie/main calls. It builds the Cobra
// tree, runs it with the cancellable context, funnels any returned error through
// the §5.7 registry (mapError), and returns the process exit code. It never
// calls os.Exit itself — main owns that, so Execute stays testable.
//
// service.Open is LAZY and per-command (each command that needs the service opens
// it in its RunE and Closes it). Execute does not open the service up front so an
// empty environment still runs version/completion/config-list without provisioning.
func Execute(ctx context.Context) int {
	rs := &rootState{}
	root := newRootCmd(ctx, rs)

	// Cobra reads os.Args; stdout/stderr default to the process streams. Tests
	// override via ExecuteWith.
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)

	err := root.ExecuteContext(ctx)
	return mapError(os.Stderr, rs.flags.Mode(), err)
}
