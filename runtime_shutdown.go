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
// CHAOS-56. It is charged PER HOOK, but only by a hook that actually overruns,
// and hookBudget hands the unused remainder of an overrunning hook's slice to
// the hooks behind it — so a phase in which every hook stalls still finishes
// within its own deadline plus one grace, and the envelope in main_shutdown.go
// adds it exactly twice: once for the drain phase, once for the flush phase.
//
// A var, not a const, so the wedged-hook tests can lower it instead of each
// spending the full grace — the same seam internal/logsink uses for its own
// close timeout. Production never writes it.
var shutdownHookGrace = 3 * time.Second

// shutdownHookMinSlice is the watchdog budget every hook is guaranteed however
// much of the phase the hooks before it consumed. See hookBudget — this is what
// stops one stalled durable close from starving the closers behind it, which is
// the flush reserve's own argument applied within a phase.
//
// A var for the same reason as shutdownHookGrace: tests lower it. Production
// never writes it.
var shutdownHookMinSlice = 1 * time.Second

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

	phaseEnd, bounded := ctx.Deadline()

	var errs []error
	for i, h := range snapshot {
		hookCtx, cancel := hookBudget(ctx, phaseEnd, bounded, len(snapshot)-i-1)
		err := runShutdownHook(hookCtx, h)
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", h.name, err))
		}
	}
	return errors.Join(errs...)
}

// hookBudget derives the next hook's context from the phase's. The hook may
// take as much of the phase as is left MINUS shutdownHookMinSlice for each hook
// still behind it, so one hook that never returns cannot consume the whole
// phase. An unbounded phase yields an unbounded hook budget.
//
// CHAOS-56 review (Codex P1). The first shipped shape gave the WHOLE PHASE one
// watchdog deadline, and the rationale for that — "a stalled hook is abandoned,
// and the flush hooks are safe because they have their own reserved phase" —
// was wrong in a way worth spelling out, because it is the same error this PR
// exists to fix, one level down. The flush RESERVE protects flush hooks from a
// stuck DRAIN. It does nothing to protect them from EACH OTHER: with a single
// phase-wide deadline, `syslog-close` or `community-db-close` stalling on a
// wedged volume burned the entire reserve plus the grace, and every hook behind
// it — `request-log-close`, `audit-log-close`, `log-closer` — was started and
// then abandoned against an already-expired deadline. Those three are the
// durable compliance record, the audit FD, and the log flush holding the
// evidence: exactly what the reserve was carved out to protect, starved by
// exactly the fault (a hung close on a wedged volume) the reserve was carved
// out for.
//
// So the reserve principle applies recursively: a phase reserves for its flush
// hooks, and within a phase each hook reserves for the hooks behind it. Nothing
// is taken from the healthy case — a hook that returns quickly hands its unused
// share straight to the next one, so a legitimately slow close can still use
// almost the whole phase when its neighbours are fast.
func hookBudget(ctx context.Context, phaseEnd time.Time, bounded bool, behind int) (context.Context, context.CancelFunc) {
	if !bounded {
		return context.WithCancel(ctx)
	}
	remaining := time.Until(phaseEnd)
	reserved := time.Duration(behind) * shutdownHookMinSlice
	slice := remaining - reserved
	if slice < shutdownHookMinSlice {
		// Not enough left to give every remaining hook a full minimum slice:
		// share what is left evenly instead, so the hooks behind this one still
		// get a turn rather than being abandoned at a deadline already past.
		slice = remaining / time.Duration(behind+1)
	}
	return context.WithTimeout(context.WithoutCancel(ctx), slice)
}

// runShutdownHook executes one hook under its own budget, contained against
// panics. The hook RECEIVES the same ctx the watchdog enforces, so a hook that
// observes ctx winds itself down instead of being abandoned; the watchdog waits
// one shutdownHookGrace past it for the hooks that cannot observe it at all —
// an fsync inside a durable close, a badger compaction, a write(2) into a
// wedged NFS mount.
//
// A hook whose ctx carries no deadline (an unbounded phase — the pre-CHAOS-56
// early shape, still used by tests and by runShutdownSequence when a budget is
// zero) is waited for indefinitely, so the behaviour is byte-identical to a
// direct call apart from panic containment.
//
// Panic containment lands the same way it does in CHAOS-55's recovery loop and
// the opposite way from CHAOS-24's HA keepalive: a panicking shutdown hook
// holds no authority that containing it would extend. Letting it escape kills
// the process mid-sequence — losing the queued log lines that name it, the
// durable flushes behind it, and a clean badger close, which CHAOS-50 showed
// is what manufactures a quarantined category store on the next boot.
func runShutdownHook(ctx context.Context, h shutdownHook) (err error) {
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

	var abandon <-chan time.Time
	if dl, ok := ctx.Deadline(); ok {
		t := time.NewTimer(time.Until(dl) + shutdownHookGrace)
		defer t.Stop()
		abandon = t.C
	}

	select {
	case err = <-done:
		return err
	case <-abandon:
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
// The split CONSUMES the source registry: it is marked as run, so a later
// RunAll on it is the documented idempotent no-op rather than a second
// execution of every hook, and a later Register panics exactly as it would
// after a RunAll. Without that, a caller that partitioned and then ran the
// original would close every store twice.
func (r *shutdownRegistry) partitionAt(boundary int) (atOrBelow, above *shutdownRegistry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ran = true
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
