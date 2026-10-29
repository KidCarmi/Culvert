package main

// chaos105_worker_guard_test.go — CHAOS-105: the background workers that were
// still outside CHAOS-24's per-round panic guard.
//
// Go terminates the process on an unrecovered panic in ANY goroutine, and all
// five of these workers are `go`-detached, so a fault in one round of any of
// them was a total outage of an in-line security gateway — the proxy data plane
// included. The inversion is the point: four of the five exist for
// OBSERVABILITY or housekeeping (a live dashboard, an audit chart, a support
// bundle sweep, a capture-level auto-revert), so a non-essential feature could
// kill the thing it reports on. The fifth, the debug-level watchdog, is the
// active auto-stop for an elevated capture level.
//
// The guard is per-ROUND, never per-goroutine, for the reason runGuarded's own
// comment records: a recover at the top of the worker would let it RETURN on a
// panic, converting a loud crash into a silent permanent stall with every
// dashboard still green.
//
// Coverage is in two halves:
//
//  1. containment, driven behaviourally through the widest of the five (the SSE
//     broadcaster, whose round reads the broadest set of mutable globals in the
//     binary): a failing round is contained AND recorded, the loop keeps
//     ticking, and it self-heals on the next round;
//  2. an inventory gate over the five loops' source. A reintroduced
//     `b.tick()` in place of the guarded call cannot be caught behaviourally
//     without a fault injected into each worker's production dependencies, so
//     the registry is pinned at the source level — the same technique
//     cp_grpc_bind_chaos_test.go uses for its logFatalf ban.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ── 1. containment, end to end ──────────────────────────────────────────────

func TestCHAOS105_SSEBroadcastLoop_ContainsAndSurvivesAFailingRound(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	var rounds, healthy int64
	fail := make(chan struct{})
	b := newSSEBroadcaster(time.Millisecond)
	b.round = func() {
		atomic.AddInt64(&rounds, 1)
		select {
		case <-fail: // the fault has been cleared
			atomic.AddInt64(&healthy, 1)
		default:
			panic("dashboard round exploded")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.run(ctx)

	// The loop must keep ticking THROUGH the failures: a deterministic fault
	// costs one interval each time, not the worker and not the process.
	chaos105WaitFor(t, func() bool { return atomic.LoadInt64(&rounds) >= 3 },
		"the broadcaster loop stopped after a panicking round — a contained panic must cost one tick, not the worker")

	if got := atomic.LoadInt64(&statCrashRecords); got < 3 {
		t.Errorf("crash records = %d, want >= 3 — a contained panic must stay observable", got)
	}
	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record stored for the contained broadcaster panic")
	}
	if rec.Component != crashComponentSSEBroadcast {
		t.Errorf("component = %q, want %q", rec.Component, crashComponentSSEBroadcast)
	}
	if rec.Category != "crash" {
		t.Errorf("category = %q, want %q", rec.Category, "crash")
	}

	// Self-heal: clear the fault and the very next round must do real work.
	close(fail)
	chaos105WaitFor(t, func() bool { return atomic.LoadInt64(&healthy) >= 1 },
		"the broadcaster did not resume once the fault cleared — the guard turned a transient fault into a permanent stall")

	// And the loop still honours its only production stop signal.
	cancel()
	select {
	case <-b.Done():
	case <-time.After(5 * time.Second):
		t.Error("run did not return after ctx cancellation")
	}
}

// chaos105WaitFor polls cond until it holds, failing with msg on timeout. Polling (not
// a fixed sleep) keeps the gate fast on a healthy tree and tolerant of a loaded
// shared CI runner, where a 1 ms ticker can be starved for a while.
func chaos105WaitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(msg)
}

// ── 2. the registry, pinned at the source ───────────────────────────────────

// chaos105Workers is the inventory this round closed: the function that owns
// each loop, and the crash-component id its round must be guarded under.
var chaos105Workers = []struct {
	file      string
	fn        string
	component string
}{
	{"events.go", "run", "crashComponentSSEBroadcast"},
	{"decryption_trend.go", "startDecCoverageSampler", "crashComponentDecryptionTrend"},
	{"support_upload_worker.go", "startSupportUploadWorker", "crashComponentSupportUpload"},
	{"support_debug_level.go", "startDebugLevelWatchdog", "crashComponentSupportDebugLevel"},
	{"ui_support.go", "startSupportRetentionJanitor", "crashComponentSupportRetention"},
}

func TestCHAOS105_EveryRegisteredWorkerRoundIsGuarded(t *testing.T) {
	for _, w := range chaos105Workers {
		t.Run(w.fn, func(t *testing.T) {
			body := funcSource(t, w.file, w.fn)
			if !strings.Contains(body, "runGuarded(") {
				t.Fatalf("%s/%s runs its round unguarded: an unrecovered panic in ANY goroutine "+
					"terminates the gateway, so every background round goes through runGuarded", w.file, w.fn)
			}
			if !strings.Contains(body, w.component) {
				t.Errorf("%s/%s does not guard under %s — the crash record must name the worker "+
					"so an operator can tell which round failed", w.file, w.fn, w.component)
			}
		})
	}
}

// The janitor is the one worker whose first round is NOT behind a ticker, so it
// needs its own assertion: pre-fix the boot sweep ran bare and a panic there
// killed the process during startup.
func TestCHAOS105_RetentionJanitorBootSweepIsGuarded(t *testing.T) {
	body := funcSource(t, "ui_support.go", "startSupportRetentionJanitor")
	if n := strings.Count(body, "runGuarded("); n < 2 {
		t.Errorf("startSupportRetentionJanitor guards %d round(s), want both the synchronous boot sweep "+
			"and the ticker round", n)
	}
	// The bare call must be gone: `sweep()` may appear only inside a guard.
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "sweep()" {
			t.Errorf("startSupportRetentionJanitor still calls sweep() unguarded: %q", trimmed)
		}
	}
}

// funcSource returns the source text of the named top-level func or method in
// file. Methods are matched on name alone, which is unambiguous for the
// inventory above.
func funcSource(t *testing.T, file, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	src := string(raw)
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		return src[fset.Position(fn.Body.Lbrace).Offset:fset.Position(fn.Body.Rbrace).Offset]
	}
	t.Fatalf("func %s not found in %s — the inventory is stale; update chaos105Workers", name, file)
	return ""
}
