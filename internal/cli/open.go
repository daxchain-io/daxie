package cli

import (
	"context"
	"time"

	"github.com/daxchain-io/daxie/internal/service"
)

// openService composes the core for a command that needs it. The cli frontend is
// the host that supplies the real wall clock (frontends may read time.Now; the
// core may not — §2.3). It returns the service and a cleanup func the caller
// defers. service.Open is lazy: it provisions nothing and dials nothing in M0.
func openService(ctx context.Context, rs *rootState) (*service.Service, func(), error) {
	opts := rs.flags.ServiceOptions()
	opts.Clock = time.Now // the ONE real clock injection; the core reads it via s.Now()

	svc, err := service.Open(ctx, opts)
	if err != nil {
		return nil, func() {}, err
	}
	return svc, func() { _ = svc.Close() }, nil
}
