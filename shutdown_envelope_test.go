package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

// CHAOS-56 follow-up — the watchdog grace is SHARED BY A PHASE, not charged per
// hook, and sharing it must not starve the hooks behind.
//
// shutdownHookGrace is the extra time a phase may overrun its deadline while a
// hook that cannot observe ctx unwinds (an fsync in a durable close, a badger
// compaction, a write(2) into a wedged mount). Two shapes were wrong before
// this, in opposite directions, and each gate below has to separate them:
//
//   - Charging the grace PER HOOK (the original). hookBudget only ever
//     redistributes an abandoned hook's unused SLICE; the grace is added on top
//     of each hook's deadline and is never charged against the phase's
//     remaining time, so every stalled hook extended the phase by a further
//     full grace. On the shipped constants the full sequence took 59.2s against
//     the 51s runtime_shutdown.go documents and docker-compose.yml's 60s
//     stop_grace_period; one more durable closer took it to 60.0s. Past the
//     stop grace it is SIGKILL, which skips request-log-close, audit-log-close
//     and log-closer — the durable compliance record, the audit FD, and the
//     flush holding the lines that say why the process is going down.
//
//   - CLAMPING the abandon instant at phaseEnd+grace (the first repair). That
//     bounded the total but handed every later hook an ALREADY-EXPIRED
//     watchdog, so it could be abandoned before its goroutine entered h.stop —
//     and since main exits as soon as the sequence returns, those bodies never
//     ran at all. The bound was achieved by not doing the work (Codex P1).
//
// So the bound and the work are SEPARATE properties and neither shape satisfies
// both. The gates are written to fail against one shape each.
//
// THEY ARE STRUCTURAL, NOT TIMING-BASED, and that is deliberate: this file's
// first draft asserted wall-clock phase durations against ceilings, which is
// the shape this repository has already rejected twice for
// internal/connlimit's and metrics.go's benchgates — "its margin is too thin
// under -race on a shared runner, and a gate that can flake gets muted". It
// duly flaked on the PR runner. The invariant lives in hookBudget's
// arithmetic, so it is asserted there: the simulation below drives the budget
// exactly as RunAll does, with each hook consuming its whole slice (the worst
// case), and never waits on a timer or a goroutine.

// phaseGraceTestConstants scales the watchdog constants for a test and restores
// them on cleanup.
func phaseGraceTestConstants(t *testing.T, grace, minSlice time.Duration) {
	t.Helper()
	oldGrace, oldMin := shutdownHookGrace, shutdownHookMinSlice
	shutdownHookGrace, shutdownHookMinSlice = grace, minSlice
	t.Cleanup(func() { shutdownHookGrace, shutdownHookMinSlice = oldGrace, oldMin })
}

// TestChaos56_BudgetArithmeticHoldsBothInvariants is the REGRESSION gate for
// both shapes, and it uses the SHIPPED constants and the real per-phase budgets.
//
// It replays a phase the way RunAll does — hook i is granted hookBudget's slice
// and, in the worst case, consumes all of it — and asserts the two properties
// that must hold together:
//
//	BOUNDED:      the phase never runs past phaseEnd + one grace, however many
//	              hooks stall. Fails against the per-hook grace.
//	NON-STARVING: every hook is granted a strictly positive slice. Fails against
//	              the clamp-only shape, where late hooks get a non-positive one.
//
// The only wall-clock dependence is the few microseconds between the time.Now()
// inside hookBudget and the one here, so the tolerance is generous by four
// orders of magnitude against defects measured in seconds. It is deterministic
// on any hardware, under any load, with or without -race.
func TestChaos56_BudgetArithmeticHoldsBothInvariants(t *testing.T) {
	// The shipped values, not scaled: this gate costs no wall-clock time, so it
	// can afford to assert against exactly what production runs.
	phaseGraceTestConstants(t, 3*time.Second, 1*time.Second)

	// The real phases and a hook count for each at or above the shipped
	// registry's (8 early / 12 drain / 10 flush covers growth headroom).
	phases := []struct {
		name   string
		budget time.Duration
		hooks  int
	}{
		{"early", defaultShutdownBudget.Early, 8},
		{"drain", defaultShutdownBudget.Total - defaultShutdownBudget.Early - defaultShutdownBudget.Flush, 12},
		{"flush", defaultShutdownBudget.Flush, 10},
	}
	const drift = 100 * time.Millisecond // clock drift only; defects are seconds

	for _, p := range phases {
		for _, n := range []int{1, 2, 3, 6, 10, 20} {
			if n > p.hooks {
				continue
			}
			// remaining is the distance from the simulated "now" to the phase
			// HORIZON, which is what RunAll hands hookBudget.
			remaining := p.budget + shutdownHookGrace
			for i := 0; i < n; i++ {
				horizon := time.Now().Add(remaining)
				_, cancel, abandonAt := hookBudget(context.Background(), horizon, true, n-i-1)
				slice := time.Until(abandonAt)
				cancel()

				if slice <= 0 {
					t.Errorf("%s phase, %d hooks: hook %d was granted a non-positive slice (%v) — "+
						"its watchdog is already expired when it starts, so a durable closer is "+
						"abandoned before it can flush", p.name, n, i, slice)
					break
				}
				if abandonAt.After(horizon.Add(drift)) {
					t.Errorf("%s phase, %d hooks: hook %d may run until %v past the phase horizon — "+
						"the grace is being charged per hook", p.name, n, i, abandonAt.Sub(horizon))
					break
				}
				remaining -= slice // worst case: the hook consumes its whole slice
			}
			if remaining < -drift {
				t.Errorf("%s phase with %d stalled hooks overran its horizon (phaseEnd + one grace) "+
					"by %v — the Total+2*grace envelope that the cross-artifact stop_grace_period "+
					"gate assumes no longer holds", p.name, n, -remaining)
			}
		}
	}
}

// TestChaos56_SharedGraceStillRunsEveryHook is the behavioural CONTROL, and it
// is what stops the bound from being "achieved" by simply not running the
// durable closers. It asserts COMPLETION, and asserts it SYNCHRONOUSLY —
// everything must have finished by the time RunAll returns, because production
// waits for nothing after the sequence returns (an earlier draft collected the
// set afterwards behind a two-second wait, which is exactly the masking Codex
// called out).
//
// Constants are deliberately roomy: each late hook is guaranteed a 50ms slice
// and needs ~1ms of it, so the assertion does not depend on a loaded runner
// meeting a tight deadline.
func TestChaos56_SharedGraceStillRunsEveryHook(t *testing.T) {
	phaseGraceTestConstants(t, 300*time.Millisecond, 50*time.Millisecond)

	closers := []string{"syslog", "community-db", "request-log", "audit-log", "log-closer"}

	var mu sync.Mutex
	completed := map[string]bool{}

	reg := &shutdownRegistry{}
	// THREE stalled hooks ahead of them, enough to spend the phase deadline and
	// its whole grace, which is the state in which the defect appeared.
	for i := 0; i < 3; i++ {
		reg.Register("stalled", 10+i, func(context.Context) error { select {} })
	}
	for _, name := range closers {
		reg.Register(name, 20, func(context.Context) error {
			time.Sleep(time.Millisecond) // real work, not just "the goroutine ran"
			mu.Lock()
			completed[name] = true
			mu.Unlock()
			return nil
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = reg.RunAll(ctx)

	mu.Lock()
	defer mu.Unlock()
	for _, name := range closers {
		if !completed[name] {
			t.Errorf("durable closer %q had not completed when RunAll returned — stalled hooks ahead "+
				"of it consumed the phase horizon, so it was abandoned before (or as) it began. "+
				"main exits immediately after the sequence, so in production its body never runs", name)
		}
	}
}

// TestChaos56_HealthyPhaseIsUnaffected is the second CONTROL: with nothing
// stalled the sharing arithmetic is unreachable, every hook runs to completion,
// and the phase returns no error.
func TestChaos56_HealthyPhaseIsUnaffected(t *testing.T) {
	phaseGraceTestConstants(t, 300*time.Millisecond, 50*time.Millisecond)

	var ran int
	reg := &shutdownRegistry{}
	for i := 0; i < 8; i++ {
		reg.Register("fast", i, func(context.Context) error {
			ran++
			return nil
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := reg.RunAll(ctx); err != nil {
		t.Fatalf("healthy phase returned an error: %v", err)
	}
	if ran != 8 {
		t.Errorf("ran %d hooks, want 8", ran)
	}
}

// TestChaos56_UnboundedPhaseStillWaitsIndefinitely pins the un-budgeted shape:
// with no deadline there is no horizon and no watchdog, so a slow hook must
// still be waited for rather than abandoned at the zero value — which would be
// a fail-open on durability dressed as a bound.
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
