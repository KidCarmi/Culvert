package shutdown

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func blockUntil(stop <-chan struct{}, started *atomic.Bool) func(context.Context) error {
	return func(context.Context) error { started.Store(true); <-stop; return nil }
}

// TestChaos56_EveryHookGetsItsMinimumSlice is the control for the gate above:
// reserving a slice per hook must not turn into a per-hook budget so small that
// a legitimately slow close is abandoned while the phase still had time. A hook
// whose neighbours are fast must still be able to use most of the phase.
func TestChaos56_EveryHookGetsItsMinimumSlice(t *testing.T) {
	reg := New(Options{MinSlice: 20 * time.Millisecond})
	var slowRan atomic.Bool
	reg.Register("test-fast", 1, func(context.Context) error { return nil })
	reg.Register("test-slow-but-fine", 2, func(context.Context) error {
		time.Sleep(300 * time.Millisecond)
		slowRan.Store(true)
		return nil
	})
	reg.Register("test-after", 3, func(context.Context) error { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := reg.RunAll(ctx); err != nil {
		t.Errorf("RunAll error = %v; a slow hook with fast neighbours must not be abandoned", err)
	}
	if !slowRan.Load() {
		t.Error("the slow hook did not complete — the per-hook reserve is starving legitimate work")
	}
}

// TestChaos56_HookPanicDoesNotAbortTheSequence is the SD-4 gate. RunAll's
// contract says "all hooks run even if one returns an error", which was only
// ever true for ERRORS: an unrecovered panic (badger's Close can panic; so can
// any hook a future PR adds) unwound the whole sequence and killed the process
// before the durable flushes and the log-sink flush.
//
// Containment lands the opposite way from CHAOS-24's HA keepalive for the
// reason recorded there: a shutdown hook holds no authority that containing it
// would extend.
func TestChaos56_HookPanicDoesNotAbortTheSequence(t *testing.T) {
	var reg Registry
	var after atomic.Bool
	reg.Register("test-panics", 1, func(context.Context) error { panic("boom") })
	reg.Register("test-after", 2, func(context.Context) error { after.Store(true); return nil })

	err := reg.RunAll(context.Background())
	if !after.Load() {
		t.Fatal("hook after the panicking one did not run — a panic still aborts the sequence")
	}
	if err == nil || !strings.Contains(err.Error(), "test-panics") {
		t.Errorf("RunAll error = %v; must name the panicking hook", err)
	}
	if err != nil && !strings.Contains(err.Error(), "boom") {
		t.Errorf("RunAll error = %v; must carry the panic value", err)
	}
}

// TestChaos56_AbandonedHookIsReportedByName pins the operator-visible half:
// the watchdog names the hook it gave up on, and does so at the point of
// abandonment rather than only in the aggregated error — the last flush hook
// closes the log sink, so anything logged after a phase returns is enqueued
// into a channel nobody drains.
func TestChaos56_AbandonedHookIsReportedByName(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)

	var logs bytes.Buffer
	reg := New(Options{Grace: 100 * time.Millisecond, Logf: log.New(&logs, "", 0).Printf})
	var started atomic.Bool
	var err error
	reg.Register("test-wedged", 1, blockUntil(stop, &started))

	func() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err = reg.RunAll(ctx)
	}()
	out := logs.String()

	if !errors.Is(err, ErrAbandoned) {
		t.Errorf("RunAll error = %v; want ErrAbandoned", err)
	}
	if !strings.Contains(out, `"test-wedged"`) {
		t.Errorf("log did not name the abandoned hook; got %q", out)
	}
}

// TestChaos56_HealthyHooksAreNotAbandonedEarly is the control for the two
// gates above: the watchdog must not turn a hook that simply takes a moment
// into an abandonment. A gate that passes because hooks stopped running at
// all would be worse than the defect.
func TestChaos56_HealthyHooksAreNotAbandonedEarly(t *testing.T) {
	var reg Registry
	var ran atomic.Bool
	reg.Register("test-slow-but-fine", 1, func(context.Context) error {
		time.Sleep(120 * time.Millisecond)
		ran.Store(true)
		return nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := reg.RunAll(ctx); err != nil {
		t.Errorf("RunAll error = %v; a hook well inside its budget must not be abandoned", err)
	}
	if !ran.Load() {
		t.Error("hook did not complete")
	}
}
