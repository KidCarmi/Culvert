// guard.go — CHAOS-24 background-worker panic containment.
//
// Go terminates the process on an unrecovered panic in ANY goroutine. Culvert
// is an in-line security appliance, so a panic in a long-lived background
// worker (a feed sync parsing third-party data, a health poller, a log drain)
// is a total gateway outage — every in-flight tunnel dropped — triggered by
// input the operator does not control. package main already contains the
// crash-recording plane (crashguard.go: recordCrash + the
// culvert_crash_records_total{component} counter + the system-actor audit
// entry), but internal/* leaf packages cannot import package main (ADR-0003),
// so the workers that live in internal/ had no way to reach it.
//
// This file is the seam. It mirrors the SetSink pattern already used for log
// lines: internal packages call Guard/SafeCall, and package main publishes the
// real handler once at startup (SetPanicSink → recordCrash), so a recovered
// worker panic lands in exactly the same metric/audit/log pipeline as a
// recovered proxy or admin panic. No new observability surface is introduced.
//
// CONTAINMENT SEMANTICS — the rule that makes this safe:
//
//	Guard the loop BODY (one iteration), never the goroutine.
//
// Recovering at the goroutine level would let the worker RETURN, converting a
// loud crash into a silent permanent stall — strictly worse, and in two cases
// actively dangerous:
//
//   - reqlog's drain goroutine owns a BLOCKING queue (persist.go: a full queue
//     parks the caller rather than dropping the durable audit record). If that
//     goroutine exits, every request goroutine eventually blocks forever in
//     Add: the proxy wedges with no crash, no restart, and no alert.
//   - a fencing-lease keepalive that stops renewing while still believing it
//     holds write authority is a split-brain vector (see ha_lease.go, where a
//     panicking renew round is charged against the confirmed-validity window
//     and self-fences rather than being retried blindly).
//
// So the contract is: contain the iteration, report it, keep the loop alive —
// and where "keep going" is not the safe answer, the CALLER inspects
// SafeCall's return and fails closed explicitly.
package obs

import (
	"fmt"
	"sync/atomic"
)

// panicSink receives every panic recovered by Guard/SafeCall. Published once at
// startup by package main (SetPanicSink → recordCrash); until then, and in unit
// tests, the default sink emits a WARN line so a panic is never fully silent.
var panicSink atomic.Pointer[func(component string, v any)]

func init() {
	def := func(component string, v any) {
		Warnf("PANIC_RECOVERED component=%q (no crash sink installed): %s",
			Sanitize(component), Sanitize(fmt.Sprint(v)))
	}
	panicSink.Store(&def)
}

// SetPanicSink publishes the handler for recovered worker panics. Call once at
// startup, before workers run. A nil fn is ignored (the default WARN sink
// stays), so a mis-wired startup can never silence panic reporting entirely.
func SetPanicSink(fn func(component string, v any)) {
	if fn == nil {
		return
	}
	panicSink.Store(&fn)
}

// reportPanic hands a recovered value to the sink. It never re-panics: a
// panicking sink must not take down the worker it exists to protect (package
// main's recordCrash has its own inner recover for the same reason, but this
// guard also covers a test or third-party sink).
func reportPanic(component string, v any) {
	defer func() { _ = recover() }()
	if p := panicSink.Load(); p != nil {
		(*p)(component, v)
	}
}

// ReportPanic hands an already-recovered value to the sink. Use it when the
// caller must run its own cleanup in the same deferred function that recovers —
// recover() only works when called DIRECTLY by the deferred func, so such a
// caller cannot delegate to Guard. internal/reqlog's drain does this: it has to
// discard a poisoned write buffer before reporting.
func ReportPanic(component string, v any) {
	if v == nil {
		return
	}
	reportPanic(component, v)
}

// Guard is the deferred one-liner for a worker loop body:
//
//	func (w *worker) tick() {
//		defer obs.Guard("threatfeed")
//		...
//	}
//
// It recovers, reports, and returns normally so the surrounding loop continues
// to its next iteration. Guard must NOT be deferred at the top of a long-lived
// goroutine — that would let the goroutine exit on panic (see the file header).
func Guard(component string) {
	if v := recover(); v != nil {
		reportPanic(component, v)
	}
}

// SafeCall runs fn with a panic guard and reports whether it panicked. Use it
// when the loop needs to KNOW a round failed — a fail-closed worker must not
// treat a panicking round as a successful one (ha_lease.go charges a panicking
// keepalive round against the lease-validity window instead of retrying it
// blindly, so panic containment can never manufacture a split brain).
//
// Callers that simply want the loop to continue can ignore the return value.
func SafeCall(component string, fn func()) (panicked bool) {
	defer func() {
		if v := recover(); v != nil {
			panicked = true
			reportPanic(component, v)
		}
	}()
	fn()
	return false
}
