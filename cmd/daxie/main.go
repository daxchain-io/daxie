// Command daxie is the agent-first Ethereum CLI wallet.
//
// main() is intentionally tiny (§2.1): it installs a SIGTERM/SIGINT-cancellable
// context so a killed container exits resumably, hands control to the cli
// frontend, and exits with the process code the §5.7 registry returns. The
// version build-stamp is injected by -ldflags into internal/version (read there,
// not here). main reads nothing else.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/daxchain-io/daxie/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(cli.Execute(ctx))
}
