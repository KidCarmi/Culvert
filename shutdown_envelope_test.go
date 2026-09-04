package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

// CHAOS-56 follow-up — the watchdog grace is SHARED BY A PHASE, not charged per
// hook.
//
// shutdownHookGrace is the extra time a phase may overrun its deadline while a
// hook that cannot observe ctx unwinds (an fsync in a durable close, a badger
// compaction, a write(2) into a wedged mount). runShutdownHook armed that grace
// against each HOOK's own deadline, and hookBudget only ever redistributes an
// abandoned hook's unused SLICE — the grace is added on top and is never charged
// against the phase's remaining time. So every stalled hook extended the phase
// by a further full grace, and the overrun grew with the number of hooks rather
// than staying at the one grace runtime_shutdown.go documents and
// TestChaos56_EnvelopeFitsTheContainerStopGrace's Total+2*grace arithmetic
// assumes.
//
// Measured on the shipped constants with every hook stalled, the full sequence
// took 59.2s against a claimed 51s worst case and docker-compose.yml's 60s
// stop_grace_period; adding one further durable closer took it to 60.0s. Past
// the stop grace it is SIGKILL, which skips request-log-close, audit-log-close
// and log-closer — the durable compliance record, the audit FD, and the flush
// holding the lines that say why the process is going down. That is precisely
// the loss the three-phase split and the flush reserve exist to prevent, so the
// bound has to hold in hook count, not just on paper.
//
// These gates are written to FAIL against the pre-fix shape (grace armed per
// hook) and are structural rather than absolute: they assert the overrun stays
// FLAT as hooks are added, so they do not encode this machine's speed.

// phaseGraceTestConstants scales the watchdog constants down so a gate that must
// exercise real wall-clock waits stays fast, and restores them on cleanup.
func phaseGraceTestConstants(t *testing.T, grace, minSlice time.Duration) {
	t.Helper()
	oldGrace, oldMin := shutdownHookGrace, shutdownHookMinSlice
	shutdownHookGrace, shutdownHookMinSlice = grace, minSlice
	t.Cleanup(func() { shutdownHookGrace, shutdownHookMinSlice = oldGrace, oldMin })
}

// runStalledPhase registers n hooks that never return and reports how long the
// bounded phase actually took.
func runStalledPhase(n int, budget time.Duration) time.Duration {
	reg := &shutdownRegistry{}
	for i := 0; i < n; i++ {
		reg.Register("stalled", i*10, func(context.Context) error {
			select {} // never returns; only a watchdog ends this hook
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	start := time.Now()
	_ = reg.RunAll(ctx)
	return time.Since(start)
}

// TestChaos56_PhaseGraceIsSharedNotPerHook is the REGRESSION gate. A phase in
// which EVERY hook stalls must finish within its deadline plus ONE grace,
// however many hooks it holds.
//
// Pre-fix this measured budget + 1.0/1.4/2.4/3.4/3.7 graces at 1/3/6/9/10 hooks.
func TestChaos56_PhaseGraceIsSharedNotPerHook(t *testing.T) {
	phaseGraceTestConstants(t, 100*time.Millisecond, 10*time.Millisecond)
	const budget = 100 * time.Millisecond
	// One grace of overrun is the contract; allow a further half grace for
	// scheduler jitter on a shared runner. The pre-fix shape overran by 2.4
	// graces at six hooks, so this tolerance cannot hide the defect.
	ceiling := budget + shutdownHookGrace + shutdownHookGrace/2

	for _, n := range []int{1, 2, 3, 6, 9, 10} {
		got := runStalledPhase(n, budget)
		if got > ceiling {
			t.Errorf("phase with %d stalled hooks took %v, exceeding budget+grace ceiling %v — "+
				"the grace is being charged per hook, so the phase overrun grows with hook count "+
				"and the Total+2*grace envelope no longer fits the container stop grace", n, got, ceiling)
		}
	}
}

// TestChaos56_PhaseOverrunIsFlatInHookCount is the same invariant stated as a
// RATIO, so it holds on any hardware and under -race: ten stalled hooks must
// not cost materially more wall time than two. Pre-fix this ratio was ~2.3x.
func TestChaos56_PhaseOverrunIsFlatInHookCount(t *testing.T) {
	phaseGraceTestConstants(t, 100*time.Millisecond, 10*time.Millisecond)
	const budget = 100 * time.Millisecond

	few := runStalledPhase(2, budget)
	many := runStalledPhase(10, budget)
	if ratio := float64(many) / float64(few); ratio > 1.5 {
		t.Errorf("ten stalled hooks took %v vs two at %v (%.2fx) — the phase overrun scales with "+
			"hook count, so the grace is per-hook rather than shared by the phase", many, few, ratio)
	}
}

// TestChaos56_SharedGraceStillRunsEveryHook is the CONTROL. A bound that simply
// stopped running the hooks behind a stalled one would pass both gates above
// while being far worse than the defect: the flush hooks are the durable
// closers. Every hook must still be STARTED, and the clamp must not convert the
// phase into an early return.
func TestChaos56_SharedGraceStillRunsEveryHook(t *testing.T) {
	phaseGraceTestConstants(t, 100*time.Millisecond, 10*time.Millisecond)

	closers := []string{"syslog", "community-db", "request-log", "audit-log", "log-closer"}

	// A hook the watchdog abandons still RUNS — RunAll stops waiting for it, it
	// does not unschedule it — so a hook reached on an already-spent phase may
	// record itself after RunAll has returned. Collect under a mutex and wait
	// for the set to fill rather than closing a channel the hook goroutines may
	// still be about to send on (which would be a send-on-closed panic, not a
	// flake).
	var mu sync.Mutex
	seen := map[string]bool{}

	reg := &shutdownRegistry{}
	// A stalled hook first, then five that must still be reached.
	reg.Register("stalled", 10, func(context.Context) error { select {} })
	for _, name := range closers {
		reg.Register(name, 20, func(context.Context) error {
			mu.Lock()
			seen[name] = true
			mu.Unlock()
			return nil
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = reg.RunAll(ctx)

	missing := func() []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, name := range closers {
			if !seen[name] {
				out = append(out, name)
			}
		}
		return out
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(missing()) > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if left := missing(); len(left) > 0 {
		t.Errorf("hooks %v were never started — a stalled hook ahead of them must not skip the "+
			"durable closers behind it", left)
	}
}

// TestChaos56_HealthyPhaseIsUnaffected is the second CONTROL: when nothing
// stalls, the clamp is unreachable and every hook runs to completion well
// inside the budget with no abandonment error.
func TestChaos56_HealthyPhaseIsUnaffected(t *testing.T) {
	phaseGraceTestConstants(t, 100*time.Millisecond, 10*time.Millisecond)

	var ran int
	reg := &shutdownRegistry{}
	for i := 0; i < 8; i++ {
		reg.Register("fast", i, func(context.Context) error {
			ran++
			return nil
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if err := reg.RunAll(ctx); err != nil {
		t.Fatalf("healthy phase returned an error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("healthy phase took %v — the clamp must not cost anything when nothing stalls", elapsed)
	}
	if ran != 8 {
		t.Errorf("ran %d hooks, want 8", ran)
	}
}

// TestChaos56_UnboundedPhaseStillWaitsIndefinitely pins the un-budgeted shape:
// with no deadline there is no phaseAbandonBy, and a slow hook must still be
// waited for rather than clamped at the zero value (which would abandon every
// hook instantly — a fail-open on durability dressed as a bound).
func TestChaos56_UnboundedPhaseStillWaitsIndefinitely(t *testing.T) {
	phaseGraceTestConstants(t, 10*time.Millisecond, time.Millisecond)

	done := make(chan struct{})
	reg := &shutdownRegistry{}
	reg.Register("slow-durable-close", 10, func(context.Context) error {
		time.Sleep(80 * time.Millisecond) // far beyond the (tiny) grace
		close(done)
		return nil
	})
	if err := reg.RunAll(context.Background()); err != nil { // no deadline
		t.Fatalf("unbounded phase returned an error: %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("an unbounded phase abandoned a slow hook — it must wait indefinitely")
	}
}

// TestChaos56_FullSequenceFitsTheStopGraceInHookCount is the end-to-end gate,
// scaled. It runs the REAL runShutdownSequence with every hook stalled, at the
// shipped phase proportions, and requires the total to stay flat when a further
// durable closer joins the flush phase.
//
// Pre-fix, at production constants, this pairing measured 59.2s and 60.0s
// against a 60s stop_grace_period: the second crossed it, so ordinary growth in
// the flush registry silently converted a bounded shutdown into a SIGKILL.
func TestChaos56_FullSequenceFitsTheStopGraceInHookCount(t *testing.T) {
	phaseGraceTestConstants(t, 60*time.Millisecond, 20*time.Millisecond)
	// Same proportions as defaultShutdownBudget (45s/12s/10s), scaled 1:50.
	budget := shutdownBudget{
		Total: 900 * time.Millisecond,
		Early: 240 * time.Millisecond,
		Flush: 200 * time.Millisecond,
	}
	stall := func(context.Context) error { select {} }

	run := func(flushHooks int) time.Duration {
		early := &shutdownRegistry{}
		for i := 0; i < 6; i++ {
			early.Register("early", i, stall)
		}
		late := &shutdownRegistry{}
		for i := 0; i < 9; i++ { // drain hooks, at or below the flush boundary
			late.Register("drain", 60+i, stall)
		}
		for i := 0; i < flushHooks; i++ { // durable closers, above it
			late.Register("flush", shutdownFlushBoundary+5+i, stall)
		}
		start := time.Now()
		runShutdownSequence(early, late, budget)
		return time.Since(start)
	}

	shipped := run(6) // syslog, community-db, log-store, request-log, audit-log, log-closer
	oneMore := run(7) // one further durable closer
	envelope := budget.Total + 2*shutdownHookGrace

	// Total + 2*grace is what TestChaos56_EnvelopeFitsTheContainerStopGrace
	// compares against stop_grace_period; allow half a grace for jitter.
	ceiling := envelope + shutdownHookGrace/2
	if shipped > ceiling {
		t.Errorf("full sequence took %v, exceeding the Total+2*grace envelope ceiling %v that the "+
			"cross-artifact stop_grace_period gate assumes", shipped, ceiling)
	}
	if oneMore > ceiling {
		t.Errorf("adding ONE durable closer took the sequence to %v, past the envelope ceiling %v — "+
			"the envelope must not depend on how many hooks are registered", oneMore, ceiling)
	}
}
