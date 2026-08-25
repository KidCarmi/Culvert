package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
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

// shutdownHookGrace is the extra time a phase may overrun its own deadline
// while hooks unwind. A hook that observes ctx returns as soon as the phase
// deadline passes; this grace exists for the hooks that CANNOT observe it —
// an fsync inside a durable close, a badger compaction, a write(2) into a
// wedged NFS mount. Past it the hook is abandoned so the hooks AFTER it still
// run: at shutdown, leaking one goroutine is free (the process is exiting)
// and a stalled hook that blocks the flush hooks behind it is not.
//
// CHAOS-56. Small on purpose — it is a per-phase overrun, not a per-hook one
// (see the `hard` deadline in RunAll), so it is added to the shutdown envelope
// exactly twice: once for the drain phase, once for the flush phase.
//
// A var, not a const, so the wedged-hook tests can lower it instead of each
// spending the full grace — the same seam internal/logsink uses for its own
// close timeout. Production never writes it.
var shutdownHookGrace = 3 * time.Second

// errShutdownHookAbandoned marks a hook the watchdog gave up waiting for. It
// is aggregated into RunAll's error like any other hook failure, but the
// operator-visible record is the log line emitted at the point of
// abandonment — the aggregate is returned to the caller AFTER the phase, and
// on the flush phase that is after the log sink has been closed.
var errShutdownHookAbandoned = errors.New("exceeded the shutdown budget and was abandoned")

// RunAll executes all registered hooks in (order, registration-index)
// ascending order, passing ctx to each. All hooks run even if one returns
// an error; failures are aggregated via errors.Join and each wrapped error
// is labelled with its hook name. Idempotent: a second call returns nil
// without re-running.
//
// CHAOS-56 — each hook runs under a WATCHDOG bounded by ctx's deadline plus
// shutdownHookGrace, and PANICS are contained. Before this, `ctx` was purely
// advisory: RunAll called every hook synchronously and several of them ignore
// the parameter entirely (the tunnel drain ran its own independent 15s timer;
// the badger/syslog/reqlog closers take no ctx at all), so a single hook that
// did not return — a gRPC GracefulStop behind a handler blocked on a wedged
// volume, a close on that same volume — stalled every hook after it for as
// long as the fault lasted. The hooks after it are the ones that make the NEXT
// boot clean, and the container's stop grace was the only thing bounding the
// sequence: the fault was resolved by SIGKILL, which abandons the stalled hook
// anyway and takes the durable flushes with it. Abandoning one hook is
// therefore never worse than the SIGKILL it replaces, and is usually much
// better.
//
// The watchdog deadline is derived with context.WithoutCancel so a phase whose
// ctx is CANCELLED (rather than expired) still gives its hooks the grace
// window; hooks continue to receive the honest, un-extended ctx.
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

	hard := context.WithoutCancel(ctx)
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		hard, cancel = context.WithDeadline(hard, dl.Add(shutdownHookGrace))
		defer cancel()
	}

	var errs []error
	for _, h := range snapshot {
		if err := runShutdownHook(ctx, hard, h); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", h.name, err))
		}
	}
	return errors.Join(errs...)
}

// runShutdownHook executes one hook, contained against panics and bounded by
// the phase-wide `hard` deadline. `ctx` — the hook's honest budget, without
// the grace — is what the hook itself receives.
//
// A phase with no deadline (the pre-CHAOS-56 early phase shape, still used by
// tests and by runShutdownSequence when a budget is zero) has `hard` with no
// deadline either, so the watchdog waits indefinitely and the behaviour is
// byte-identical to a direct call apart from panic containment.
//
// Panic containment lands the same way it does in CHAOS-55's recovery loop and
// the opposite way from CHAOS-24's HA keepalive: a panicking shutdown hook
// holds no authority that containing it would extend. Letting it escape kills
// the process mid-sequence — losing the queued log lines that name it, the
// durable flushes behind it, and a clean badger close, which CHAOS-50 showed
// is what manufactures a quarantined category store on the next boot.
func runShutdownHook(ctx, hard context.Context, h shutdownHook) (err error) {
	done := make(chan error, 1) // buffered: the goroutine must never block on an abandoned hook
	started := time.Now()
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				done <- fmt.Errorf("panic: %v", rec)
			}
		}()
		done <- h.stop(ctx)
	}()

	select {
	case err = <-done:
		return err
	case <-hard.Done():
	}

	// Log HERE, not from the aggregated error at the end of the phase: the
	// last flush hook closes the log sink, so anything the caller logs after
	// the phase returns is enqueued into a sink nobody drains.
	logger.Printf("Shutdown: hook %q did not return after %s — abandoning it and continuing",
		h.name, time.Since(started).Round(time.Millisecond))
	return errShutdownHookAbandoned
}

// partitionAt splits the registry into two registries by hook order: `at or
// below` receives every hook whose order <= boundary, `above` the rest. Both
// carry the hooks in registration order, so RunAll's (order, registration)
// sort produces exactly the sequence the undivided registry would have.
//
// CHAOS-56 — this is how the late phase gets a RESERVE. The late hooks fall
// into two classes with opposite failure costs: drain hooks (stop accepting,
// let in-flight work finish) are best-effort and their loss costs a retry,
// while flush hooks (cluster store, syslog, badger, request log, audit, log
// sink) are what make the next boot clean and their loss costs durability or
// a corrupt store. Sharing one budget lets a stuck drain consume the whole
// envelope and starve every flush behind it; partitioning gives the flush
// hooks a slice that a drain cannot spend.
//
// Registering into a partition after RunAll ran on it panics, as on any
// registry — the split is done once, immediately before the phases run.
func (r *shutdownRegistry) partitionAt(boundary int) (atOrBelow, above *shutdownRegistry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	atOrBelow, above = &shutdownRegistry{}, &shutdownRegistry{}
	for _, h := range r.hooks {
		if h.order <= boundary {
			atOrBelow.hooks = append(atOrBelow.hooks, h)
		} else {
			above.hooks = append(above.hooks, h)
		}
	}
	return atOrBelow, above
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
