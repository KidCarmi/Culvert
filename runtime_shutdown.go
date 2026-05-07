package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// shutdownHook is one entry in shutdownRegistry. Created via Register; the
// type is unexported because the registry is the only legitimate constructor.
type shutdownHook struct {
	name  string
	order int
	stop  func(context.Context) error
}

// shutdownRegistry collects ordered, named shutdown hooks and runs them as
// a single batch via RunAll. The contract:
//
//   - Hooks run in ascending order. Hooks with the same order run in
//     registration order (sort.SliceStable preserves the tie-break).
//   - All hooks run even if one returns an error. Failures are aggregated
//     via errors.Join into a single returned error; each wrapped error is
//     prefixed with its hook name.
//   - RunAll is idempotent: a second call returns nil without re-running
//     any hook.
//   - Register panics if stop is nil — registering a no-op hook is a
//     programming error and should fail fast at wire-up time.
//
// Concurrency: Register and RunAll are mutex-protected. The hook list is
// snapshotted before the lock is released, so user-provided stop functions
// run without the registry lock held.
//
// P2.1 / S5. This PR introduces the type and its tests only — there are no
// production call sites yet. P2.2 will wire it into runProxyUntilShutdown
// and register the existing teardown calls (Phase 1 owners + the existing
// HA / gRPC / scan-svc / proxy / log-closer steps).
type shutdownRegistry struct {
	mu    sync.Mutex
	hooks []shutdownHook
	ran   bool
}

// Register adds a hook. name is a human-readable identifier used in error
// messages and logs. order determines execution order (lower runs first).
// Hooks with the same order run in registration order. Panics if stop is
// nil, or if Register is called after RunAll has executed — silently
// dropping a late registration would let a wiring mistake (e.g. P2.2
// registering a hook after the shutdown path already ran in tests) skip
// shutdown logic without warning.
func (r *shutdownRegistry) Register(name string, order int, stop func(context.Context) error) {
	if stop == nil {
		panic(fmt.Sprintf("shutdownRegistry: nil stop function for hook %q", name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ran {
		panic(fmt.Sprintf("shutdownRegistry: register after RunAll for hook %q", name))
	}
	r.hooks = append(r.hooks, shutdownHook{name: name, order: order, stop: stop})
}

// RunAll executes all registered hooks in (order, registration-index)
// ascending order, passing ctx to each. All hooks run even if one returns
// an error; failures are aggregated via errors.Join and each wrapped error
// is labelled with its hook name. Idempotent: a second call returns nil
// without re-running.
func (r *shutdownRegistry) RunAll(ctx context.Context) error {
	r.mu.Lock()
	if r.ran {
		r.mu.Unlock()
		return nil
	}
	r.ran = true
	snapshot := make([]shutdownHook, len(r.hooks))
	copy(snapshot, r.hooks)
	r.mu.Unlock()

	sort.SliceStable(snapshot, func(i, j int) bool {
		return snapshot[i].order < snapshot[j].order
	})

	var errs []error
	for _, h := range snapshot {
		if err := h.stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", h.name, err))
		}
	}
	return errors.Join(errs...)
}

// hooksSnapshot returns a copy of the registered hooks in registration
// order (NOT execution order — execution sorts by `order`). Intended for
// test inspection of wiring; not part of the production contract.
func (r *shutdownRegistry) hooksSnapshot() []shutdownHook {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]shutdownHook, len(r.hooks))
	copy(out, r.hooks)
	return out
}
