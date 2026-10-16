package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// CHAOS-71 gates: elapsed time on the data path and the readiness probe is
// measured on the MONOTONIC clock, never the wall clock.
//
// The pre-fix idiom was
//
//	stamp := time.Now().UnixNano()
//	elapsed := time.Since(time.Unix(0, stamp))
//
// where UnixNano() discards the monotonic reading and time.Unix(0, n)
// reconstructs a value that has none, so the subtraction is wall-clock. A
// backwards step (NTP correction, VM suspend/resume, container host clock
// change, manual date change) left the stamp in the FUTURE, making elapsed
// NEGATIVE — which satisfies neither `elapsed >= deadline` nor
// `elapsed >= grace`, so the tunnel reaper stopped reaping and the DP
// readiness probe stopped reporting a control-plane outage, each for as long
// as the step went.

// swapMonoNanos replaces the monotonic clock source for one test and restores
// it. Tests using it must not run in parallel (package-level var, the same
// idiom tunnelIdleTimeout already uses).
func swapMonoNanos(t *testing.T, fn func() int64) {
	t.Helper()
	old := monoNanos
	monoNanos = fn
	t.Cleanup(func() { monoNanos = old })
}

// TestChaos71_MonoEpochCarriesMonotonicReading is the foundational invariant:
// monoEpoch must carry a monotonic reading, because time.Sub only subtracts
// monotonic readings when BOTH operands have one. If monoEpoch ever loses its
// reading (a round-trip through Unix()/UTC()/a struct field that strips it),
// every monoNanos measurement silently degrades back to the wall clock and
// every gate below keeps passing.
func TestChaos71_MonoEpochCarriesMonotonicReading(t *testing.T) {
	if !hasMonotonicReading(monoEpoch) {
		t.Fatalf("monoEpoch has no monotonic reading (%v) — monoNanos has silently degraded to a "+
			"wall-clock measurement and every CHAOS-71 fix is inert", monoEpoch)
	}
	// CONTROL: the detector must reject a value whose reading was stripped,
	// otherwise it matches everything and proves nothing.
	if hasMonotonicReading(time.Unix(0, monoEpoch.UnixNano())) {
		t.Error("control failed: hasMonotonicReading reports a stripped value as monotonic")
	}
}

// hasMonotonicReading reports whether t carries a monotonic reading, via the
// documented " m=" suffix time.Time.String() appends for exactly that case.
func hasMonotonicReading(t time.Time) bool { return strings.Contains(t.String(), " m=") }

// TestChaos71_MonoSinceNeverNegativeForPriorStamp pins the property that makes
// both fixes work: an elapsed duration measured against an EARLIER monoNanos
// stamp is never negative, so no caller needs a negative-age branch.
func TestChaos71_MonoSinceNeverNegativeForPriorStamp(t *testing.T) {
	for i := 0; i < 2000; i++ {
		stamp := monoNanos()
		if d := monoSince(stamp); d < 0 {
			t.Fatalf("monoSince(earlier stamp) = %v, want >= 0 (iteration %d)", d, i)
		}
	}
}

// TestChaos71_MonoNanosIsNeverZero pins the sentinel invariant: 0 must stay
// outside the stamp domain, because every caller holding a stamp in an
// atomic.Int64 uses 0 to mean "never stamped" (readyz's `since != 0`, the
// roster log gates' `last != 0`). On the wall clock that was free — 0 is 1970 —
// but a process-relative stamp really can be 0 at the first nanosecond, which
// would read as "no stamp" and suppress the very transition it recorded.
func TestChaos71_MonoNanosIsNeverZero(t *testing.T) {
	for i := 0; i < 2000; i++ {
		if got := monoNanos(); got == 0 {
			t.Fatalf("monoNanos() = 0 on iteration %d — 0 is the callers' \"never stamped\" sentinel "+
				"and must never be a real stamp", i)
		}
	}
}

// TestChaos71_Control_WallClockIdiomGoesNegativeOnBackwardsStep is the CONTROL
// that proves the gates above are testing something real. It reproduces the
// pre-fix arithmetic against the stamp a backwards wall-clock step leaves
// behind, and shows the negative elapsed satisfies NEITHER predicate — the
// tunnel reaper's deadline nor the readiness grace window.
func TestChaos71_Control_WallClockIdiomGoesNegativeOnBackwardsStep(t *testing.T) {
	const step = 30 * time.Minute

	// A stamp written just before the clock stepped back by `step` reads, on
	// the new wall clock, as `step` in the future.
	wallStamp := time.Now().Add(step).UnixNano()
	elapsed := time.Since(time.Unix(0, wallStamp)) // the verbatim pre-fix idiom

	if elapsed >= 0 {
		t.Fatalf("control failed: pre-fix idiom yielded %v, expected a NEGATIVE elapsed after a "+
			"backwards step — the control no longer reproduces the defect", elapsed)
	}
	if elapsed >= tunnelIdleTimeout {
		t.Error("control failed: a negative elapsed must not satisfy the reaper deadline")
	}
	if elapsed >= dpCPPollFailGrace {
		t.Error("control failed: a negative elapsed must not satisfy the probe grace window")
	}
	// Both predicates being false is the defect: nothing is reaped, nothing is
	// reported, for the whole duration of the step.
	t.Logf("pre-fix idiom after a %v backwards step: elapsed=%v (reaper fires=%v, probe fails=%v)",
		step, elapsed, elapsed >= tunnelIdleTimeout, elapsed >= dpCPPollFailGrace)
}

// TestChaos71_TunnelActivityStampIsMonotonicDomain is a DEFECT GATE: it fails
// against the pre-fix code. newTunnelActivityStamp stored time.Now().UnixNano()
// (~1.7e18, nanoseconds since 1970); it must now store a monotonic reading
// taken from monoNanos (nanoseconds since this process started).
func TestChaos71_TunnelActivityStampIsMonotonicDomain(t *testing.T) {
	before := monoNanos()
	got := newTunnelActivityStamp().Load()
	after := monoNanos()

	if got < before || got > after {
		t.Fatalf("newTunnelActivityStamp() = %d, want a monotonic stamp within [%d, %d]. A value near "+
			"%d would be time.Now().UnixNano() — the wall-clock domain CHAOS-71 removed",
			got, before, after, time.Now().UnixNano())
	}
}

// TestChaos71_CPPollFailingSinceIsMonotonicDomain is the same DEFECT GATE for
// the readiness probe's healthy→failing transition stamp.
func TestChaos71_CPPollFailingSinceIsMonotonicDomain(t *testing.T) {
	prevFailing := dpControlPlanePollFailing.Load()
	prevSince := dpCPPollFailingSince.Load()
	t.Cleanup(func() {
		dpControlPlanePollFailing.Store(prevFailing)
		dpCPPollFailingSince.Store(prevSince)
	})

	// dpMarkCPPollFailing stamps on the healthy→failing EDGE only.
	dpMarkCPPollHealthy()
	before := monoNanos()
	dpMarkCPPollFailing()
	after := monoNanos()

	got := dpCPPollFailingSince.Load()
	if got < before || got > after {
		t.Fatalf("dpCPPollFailingSince = %d, want a monotonic stamp within [%d, %d]. A value near %d "+
			"would be time.Now().UnixNano() — the wall-clock domain CHAOS-71 removed",
			got, before, after, time.Now().UnixNano())
	}
}

// TestChaos71_CPPollGraceFlipsOnMonotonicElapsedOnly drives the probe's grace
// window off an injected monotonic clock: the row flips to fail once the
// monotonic elapsed reaches the grace window, and — the NEGATIVE CONTROL
// against the wrong fix — a stamp that appears to be in the FUTURE must leave
// the row ok rather than flipping it. "Negative age means expired" would be
// fail-closed here but would flap the probe of every node in the fleet on any
// backwards step, however small.
func TestChaos71_CPPollGraceFlipsOnMonotonicElapsedOnly(t *testing.T) {
	withDPMode(t)

	prevFailing := dpControlPlanePollFailing.Load()
	prevSince := dpCPPollFailingSince.Load()
	t.Cleanup(func() {
		dpControlPlanePollFailing.Store(prevFailing)
		dpCPPollFailingSince.Store(prevSince)
	})

	// A virtual monotonic clock. It starts at 1, never 0: 0 is the "never
	// stamped" sentinel the probe reads as "cannot prove sustained".
	var fake atomic.Int64
	fake.Store(1)
	swapMonoNanos(t, func() int64 { return fake.Load() })

	dpControlPlanePollFailing.Store(true)
	dpCPPollFailingSince.Store(monoNanos()) // failing as of virtual t=1

	// Inside the window: ok.
	fake.Store(1 + int64(dpCPPollFailGrace) - 1)
	if row := dpCPPollRow(t); row != "ok" {
		t.Errorf("cp_poll = %q just inside the grace window, want ok (no flap on a missed poll)", row)
	}

	// At the window: fail.
	fake.Store(1 + int64(dpCPPollFailGrace))
	if row := dpCPPollRow(t); row != "fail" {
		t.Errorf("cp_poll = %q at the grace window, want fail — a sustained CP outage must become "+
			"probe-visible, which is what the wall-clock stamp suppressed", row)
	}

	// NEGATIVE CONTROL: a future stamp (what a backwards step used to leave)
	// must not be read as expired.
	fake.Store(1 + int64(dpCPPollFailGrace))
	dpCPPollFailingSince.Store(1 + int64(dpCPPollFailGrace) + int64(time.Hour))
	if row := dpCPPollRow(t); row != "ok" {
		t.Errorf("cp_poll = %q for a stamp in the future, want ok — treating a negative age as "+
			"expired would mark every node unready on a trivial backwards step", row)
	}
}

// dpCPPollRow returns the cp_poll row's status from a fresh probe evaluation.
func dpCPPollRow(t *testing.T) string {
	t.Helper()
	checks := map[string]*readinessCheck{}
	appendDPHealthChecks(checks)
	row := checks["cp_poll"]
	if row == nil {
		t.Fatal("cp_poll row missing from the DP probe")
	}
	return row.Status
}

// TestChaos71_TunnelReaperFiresOnMonotonicElapsed is the behavioural end of the
// tunnel fix: a silent tunnel is reaped once the MONOTONIC elapsed time passes
// the idle window, with the deadline decision taken entirely off monoNanos.
func TestChaos71_TunnelReaperFiresOnMonotonicElapsed(t *testing.T) {
	setTunnelIdleTimeout(t, 200*time.Millisecond)

	// A virtual monotonic clock running 100x real time. It must RUN rather than
	// take one step: the relay refreshes the activity stamp whenever a copy
	// returns bytes, so a single step applied before the first deadline pop is
	// captured by that refresh and the tunnel then looks freshly active
	// forever. A running clock is also the honest model — the real monotonic
	// clock advances on its own, and the point of the fix is that this
	// decision reads nothing else.
	virtualStart := time.Now()
	swapMonoNanos(t, func() int64 { return int64(time.Since(virtualStart))*100 + 1 })

	clientProxy, clientPeer := net.Pipe()
	destProxy, destPeer := net.Pipe()
	t.Cleanup(func() {
		clientPeer.Close()
		destPeer.Close()
	})

	resCh := make(chan int64, 1)
	go func() {
		d, _ := bidiRelayCounted(destProxy, clientProxy, clientProxy, destProxy)
		resCh <- d
	}()

	// Prove the tunnel is live first.
	go clientPeer.Write([]byte("hello")) //nolint:errcheck // test write; teardown may race it
	buf := make([]byte, 5)
	if _, err := io.ReadFull(destPeer, buf); err != nil {
		t.Fatalf("initial relay read: %v", err)
	}

	// Both peers now go silent without closing (the half-open case). Only the
	// virtual MONOTONIC clock carries them past the idle window; the wall clock
	// advances 100x slower and is irrelevant to the decision.
	select {
	case d := <-resCh:
		if d != 5 {
			t.Errorf("bytes to dest = %d, want 5 (accounting must survive the reap)", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("silent tunnel was not reaped once the monotonic elapsed passed the idle window")
	}
}

// TestChaos71_NoWallClockElapsedIdiomInPackageMain is the durable guard: the
// `time.Unix(0, stamp)` elapsed-measurement idiom must not come back into
// package main. The ban is deliberately narrow — time.Unix(0, nanos) is only
// ever an elapsed-measurement stamp, while time.Unix(seconds, 0) is a genuine
// absolute instant (a wire-carried token expiry, a timestamp formatted for
// display) and stays legal.
func TestChaos71_NoWallClockElapsedIdiomInPackageMain(t *testing.T) {
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	scanned := 0
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		for _, pos := range wallClockElapsedSites(fset, file) {
			t.Errorf("%s:%s measures elapsed time with time.Unix(0, stamp): that subtraction is "+
				"WALL-clock (the reconstructed value has no monotonic reading), so a backwards clock "+
				"step makes it negative and the deadline never fires. Stamp with monoNanos() and "+
				"measure with monoSince() (CHAOS-71).", name, pos)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no package-main sources — the guard is matching nothing")
	}

	// CONTROL: the verbatim pre-fix shapes must be REJECTED by this predicate,
	// and the legitimate absolute-instant shapes must be ACCEPTED.
	fset := token.NewFileSet()
	ctrl, err := parser.ParseFile(fset, "control.go", wallClockElapsedControlSource, 0)
	if err != nil {
		t.Fatalf("parse control: %v", err)
	}
	if n := len(wallClockElapsedSites(fset, ctrl)); n != 2 {
		t.Errorf("control failed: want exactly 2 flagged pre-fix sites in the control source, got %d — "+
			"the guard is either matching nothing or flagging the legitimate absolute-time uses", n)
	}
	t.Logf("scanned %d package-main sources", scanned)
}

// wallClockElapsedSites returns the positions of calls that subtract a
// time.Unix(0, nanos) value from now — time.Since(time.Unix(0, x)) or
// x.Sub(time.Unix(0, y)).
func wallClockElapsedSites(fset *token.FileSet, file *ast.File) []string {
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// time.Since(arg) or <expr>.Sub(arg).
		if sel.Sel.Name != "Sub" {
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "time" || sel.Sel.Name != "Since" {
				return true
			}
		}
		if isTimeUnixNanosOnly(call.Args[0]) {
			pos := fset.Position(call.Pos())
			out = append(out, fmt.Sprintf("%d:%d", pos.Line, pos.Column))
		}
		return true
	})
	return out
}

// isTimeUnixNanosOnly reports whether expr is time.Unix(0, nanos) — the
// nanos-only reconstruction used for elapsed measurement. time.Unix(sec, 0)
// is an absolute instant and is deliberately NOT matched.
func isTimeUnixNanosOnly(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Unix" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "time" {
		return false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}

// wallClockElapsedControlSource holds the VERBATIM pre-fix shapes (which must
// be flagged) alongside the legitimate absolute-instant shapes (which must
// not). It is a control string and is never compiled into the binary.
const wallClockElapsedControlSource = `package control

func preFixReaper() {
	if time.Since(time.Unix(0, shared.Load())) >= timeout {
		teardown()
	}
}

func preFixLogGate() {
	if last != 0 && now.Sub(time.Unix(0, last)) < interval {
		return
	}
}

func legitimateAbsoluteInstants() {
	if time.Unix(e.Expiry, 0).Before(now) {
		return
	}
	until := time.Unix(tokenExp, 0).Sub(now)
	_ = time.Unix(u, 0).UTC().Format(time.RFC3339)
	_ = until
}
`
