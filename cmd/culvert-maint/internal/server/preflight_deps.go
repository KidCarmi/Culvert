package server

import (
	"context"
	"fmt"
	"strings"

	"culvert-maint/internal/runner"
)

// preflightDependencies refuses an image change while a service the proxy
// depends on reports "unhealthy". `docker compose up -d` against an
// unhealthy `depends_on: service_healthy` dependency removes the running
// proxy, creates the new one and leaves it STOPPED, and an inline
// rollback runs the same `up` — so the op would turn a ClamAV outage into
// a proxy outage (measured, see runner.UnhealthyDependencies). Refusing
// here is a no-op for the stack.
//
// Best-effort in the other direction: when `compose ps` cannot answer,
// the op proceeds as it always did (capture_before has the same rule);
// only an explicit "unhealthy" refuses.
func (s *Server) preflightDependencies() stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		res, err := s.opts.Runner.ComposeStatus(ctx)
		if err != nil || res == nil {
			return []byte("preflight_dependencies: compose ps unavailable (" + errString(err) + "); proceeding"), nil, nil
		}
		bad, perr := runner.UnhealthyDependencies(res.Stdout)
		if perr != nil {
			return []byte("preflight_dependencies: compose ps unparseable (" + perr.Error() + "); proceeding"), nil, nil
		}
		if len(bad) > 0 {
			msg := fmt.Sprintf("preflight_dependencies: REFUSED — unhealthy: %s. `docker compose up` would remove the running proxy and leave the new one stopped; nothing was changed. Fix the dependency (e.g. `docker compose restart %s`), then retry",
				strings.Join(bad, ","), bad[0])
			return []byte(msg), nil, fmt.Errorf("dependency_unhealthy: %s", strings.Join(bad, ","))
		}
		return []byte("preflight_dependencies: no unhealthy dependency"), nil, nil
	}
}
