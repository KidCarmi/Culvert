package scanner

// CHAOS-110: the in-flight gate for DPI scan workers.
//
// scan() cannot run re.Match on the calling goroutine, because re.Match is not
// interruptible and the per-pattern budget needs a goroutine to ABANDON. That
// abandonment is the whole point of the timeout — and it is also the leak: an
// abandoned worker outlives the request, keeps the response body reachable
// until its match finally returns, and keeps burning a core while it does.
// Before this gate, nothing counted those workers and nothing capped them.
// Measured on the baseline: 200 concurrent abandoned scans held 200.3 MiB of
// reachable heap after every parent had already returned and the test held no
// body reference, and 64 abandoned scans at an 8 MiB scan window held 512.1
// MiB — exactly one response body each, reclaimed only when the matches ended.
//
// The twin engine already solves this. internal/yara counts every in-flight
// regex goroutine, has the abandoned worker INHERIT its charge so the cap can
// see it, caps the total, and reports saturation. This file is that treatment
// for the DPI engine, with one deliberate difference described below.
//
// WHY A BOUNDED WAIT RATHER THAN YARA'S IMMEDIATE VERDICT
//
// yara decides at the cap: it skips the match and resolves through an
// admin-selected posture. That is right for yara, whose matches are charged per
// RULE STRING inside one scan. It would be wrong here. A DPI scan is one unit
// per inspected response, so the cap is reached by ordinary ARRIVAL
// concurrency — a merely busy gateway can easily have more concurrent inspected
// text responses than it has cores — and an immediate verdict at the cap would
// turn "busy" into "blocking legitimate traffic". So a scan that finds the gate
// full WAITS for a slot, bounded by the same budget a single pattern may run
// for. Because a typical operator pattern matches in hundreds of nanoseconds,
// the wait is unobservable in normal operation; it only becomes real when the
// engine is genuinely occupied by long-running matches.
//
// Only when that wait expires does the gate refuse, and then it fails CLOSED
// (S17 / Zero Trust), which is not a new posture: it is the same verdict the
// existing timeout branch already returns for the same epistemic state — the
// gateway has no opinion about this content and must not pass it uninspected.
//
// Bounding concurrency is also what makes the existing budget mean anything.
// The per-pattern budget is WALL CLOCK, so without a cap a match's elapsed time
// grows with the number of other matches competing for the same cores, and
// scans start failing closed because the gateway is busy rather than because
// the content is slow. Measured on the baseline, one core, a match needing 68ms
// against a 200ms budget (a 3x margin): at concurrency 1, 0 of 1 clean bodies
// were blocked; at 4, 4 of 4; at 8, 8 of 8; at 32, 32 of 32. Every one of those
// blocks then left another abandoned worker competing for the same cores, which
// is the feedback half: the busier the gateway got, the more clean traffic it
// blocked, and each block made the next scan slower. The cap breaks that loop
// by keeping concurrent matches near the core count, so elapsed time stays
// close to CPU time and the budget keeps measuring the CONTENT.

import (
	"runtime"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// SaturatedReason is the pattern string reported when the gate refuses a scan.
// It reaches the DPI_BLOCKED log line and the inspection record; the
// client-visible block page is a fixed string that names no pattern, so this
// does not disclose the node's posture to the client that triggered it.
const SaturatedReason = "dpi-engine-saturated"

// PanicReason is the pattern string reported when a match panicked and the
// guard contained it. Like SaturatedReason it reaches only the DPI_BLOCKED log
// line and the inspection record, never the client-visible block page.
const PanicReason = "dpi-match-panic"

// dpiMatchComponent names this guard's component for obs.SafeCall's panic
// report, mirroring internal/yara's "yara-match".
const dpiMatchComponent = "dpi-match"

// inflightFloor keeps a GOMAXPROCS=1 container able to overlap two scans, so
// one scan waiting on a GC pause or a page fault does not stall the next.
//
// It is deliberately NOT higher. The gate bounds CPU-bound regex work, and
// over-subscribing a core defeats the budget it is protecting: the per-pattern
// budget is wall clock, so admitting four CPU-bound matches onto one core
// stretches each one's elapsed time about fourfold and starts failing clean
// content closed for want of CPU. Two per core leaves slack for descheduling
// while keeping elapsed time close to CPU time.
const inflightFloor = 2

// saturationLogInterval rate-limits the saturation and approaching-saturation
// logs. Per-event timeout logging is deliberately left alone — see the
// amplification note in the CHAOS-110 review.
const saturationLogInterval = 10 * time.Second

// slotGate is one generation of the gate. SetMaxInflight publishes a new
// generation; holders release into the generation they acquired from, so a
// resize never loses or double-counts a slot.
type slotGate struct {
	ch    chan struct{}
	limit int
}

var (
	gate               atomic.Pointer[slotGate]
	inflight           atomic.Int64
	saturationBlocks   atomic.Int64
	abandonedWorkers   atomic.Int64
	matchPanics        atomic.Int64
	lastSaturatedLog   atomic.Int64
	lastApproachingLog atomic.Int64
)

func init() { SetMaxInflight(defaultMaxInflight()) }

// defaultMaxInflight sizes the gate off the CPU allowance, because what it
// bounds is CPU-bound regex work plus one retained response body per worker.
// Go sizes GOMAXPROCS from the cgroup quota, so a CPU-limited container gets a
// correspondingly smaller gate without the operator configuring anything.
func defaultMaxInflight() int {
	n := 2 * runtime.GOMAXPROCS(0)
	if n < inflightFloor {
		n = inflightFloor
	}
	return n
}

// SetMaxInflight republishes the gate with room for n concurrent scan workers.
// n < 1 is clamped to 1. Exported as the seam a future operator setting (or a
// test) can drive; production uses defaultMaxInflight.
func SetMaxInflight(n int) {
	if n < 1 {
		n = 1
	}
	gate.Store(&slotGate{ch: make(chan struct{}, n), limit: n})
}

// MaxInflight is the current cap.
func MaxInflight() int {
	if g := gate.Load(); g != nil {
		return g.limit
	}
	return 0
}

// Inflight is the number of scan workers alive right now, INCLUDING workers
// whose scan has already failed closed and walked away. Counting the abandoned
// ones is the point: they are the goroutines and the retained bodies the cap
// exists to bound.
func Inflight() int64 { return inflight.Load() }

// SaturationBlocks counts scans refused because no slot came free within the
// wait budget. Each one is a fail-closed block of content that was never
// inspected, so a non-zero and rising value is an availability signal, not just
// a capacity one.
func SaturationBlocks() int64 { return saturationBlocks.Load() }

// AbandonedWorkers counts scans whose worker outlived its parent — the
// uninterruptible-match population the cap is sized against.
func AbandonedWorkers() int64 { return abandonedWorkers.Load() }

// MatchPanics counts matches that panicked and were contained by the worker's
// guard. Distinct from a timeout: a timeout means the match did not finish, a
// panic means it crashed. Both fail closed, but they point at different causes.
func MatchPanics() int64 { return matchPanics.Load() }

// acquireSlot books one slot, waiting at most wait for one to come free.
// The fast path is a non-blocking send: no allocation, no timer.
func acquireSlot(wait time.Duration) (*slotGate, bool) {
	g := gate.Load()
	if g == nil {
		return nil, true // gate not initialised; never refuse on our own bug
	}
	select {
	case g.ch <- struct{}{}:
		approachingCheck(inflight.Add(1), g.limit)
		return g, true
	default:
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case g.ch <- struct{}{}:
		approachingCheck(inflight.Add(1), g.limit)
		return g, true
	case <-t.C:
		return nil, false
	}
}

// release returns the slot to the generation it came from. Called by the WORKER
// on its way out, never by the parent: a parent that has given up is exactly
// the case where the goroutine and its body are still there.
func (g *slotGate) release() {
	if g == nil {
		return
	}
	inflight.Add(-1)
	<-g.ch
}

// approachingCheck warns once per interval while the gate is near its cap, so
// the operator sees the squeeze before it starts costing blocks. n is the depth
// this acquisition just reached, so this costs no extra atomic load.
func approachingCheck(n int64, limit int) {
	if limit <= 0 || n < approachingThreshold(limit) {
		return
	}
	if logAllowed(&lastApproachingLog) {
		obs.Warnf("DPI: approaching saturation: %d of %d in-flight scan workers", n, limit)
	}
}

// approachingThreshold is the in-flight depth at which the gate is 80% full,
// rounded UP.
//
// Rounding matters because this gate is sized from the CPU allowance and its
// floor is 2 (inflightFloor), so the smallest real gate has two slots.
// Truncating 80% DOWN made that threshold 2*80/100 = 1, which is one ORDINARY
// scan: a single-vCPU container — a common sidecar shape — logged "approaching
// saturation: 1 of 2" every saturationLogInterval forever, at no load at all.
// That is the worst possible failure for this particular line, because it is
// the lead indicator for the gate's fail-closed refusal (SaturationBlocks):
// an operator who learns to ignore it loses the only warning they get before
// clean content starts being blocked uninspected.
//
// Rounding up makes a 2-slot gate warn at 2 of 2 and leaves every larger gate
// with its lead time (8 -> 7, 64 -> 52). At two and three slots there is no
// lead time to be had; the honest threshold there is the cap itself.
func approachingThreshold(limit int) int64 {
	if limit <= 0 {
		return 0
	}
	t := int64((limit*80 + 99) / 100)
	if t > int64(limit) {
		t = int64(limit)
	}
	return t
}

// logAllowed is a coarse once-per-interval gate on a degraded-state log line.
// It is best-effort: a lost race logs twice, which is harmless, and is cheaper
// than a mutex on a path a saturated gateway takes often.
func logAllowed(last *atomic.Int64) bool {
	now := time.Now().UnixNano()
	prev := last.Load()
	if now-prev < int64(saturationLogInterval) {
		return false
	}
	return last.CompareAndSwap(prev, now)
}

// resetInflightForTest restores the package counters and a fresh gate. Test-only.
func resetInflightForTest(limit int) {
	inflight.Store(0)
	saturationBlocks.Store(0)
	abandonedWorkers.Store(0)
	matchPanics.Store(0)
	lastSaturatedLog.Store(0)
	lastApproachingLog.Store(0)
	SetMaxInflight(limit)
}
