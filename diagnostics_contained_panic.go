package main

// diagnostics_contained_panic.go — operator-contract row for a recently
// contained panic.
//
// The crash plane (crashguard.go) recovers a panic, counts it, logs it, writes
// a system-actor audit entry and — when a webhook subscribes to
// panic_contained — pages. The one-page diagnostics report, where an operator
// checks "is this node healthy", said nothing: a node whose feed sync, HA
// round or request handler had just crashed read all-green unless the operator
// scraped culvert_crash_records_total, had subscribed a webhook beforehand, or
// found the entry in the bounded audit ring before it was evicted. A panic in
// the alert-delivery plane itself raises no page at all (crashAlertExcluded),
// so this row is the only on-appliance signal for it.
//
// Report-only: reads the existing counter, the existing last-crash record and
// the stamp below. It changes neither containment, the throttle, the alert
// latch nor any request outcome. Contributes NO row unless a panic was
// contained within containedPanicRecentWindow. Names only what the audit log
// already shows a viewer (component label, crash id): never the panic value or
// the stack, which stay behind the redacting accessors.

import (
	"fmt"
	"sync/atomic"
	"time"
)

// containedPanicCode is the operator-contract code of the row below.
const containedPanicCode = "contained_panic_recent"

// containedPanicRecentWindow is how long after the most recent contained panic
// the row keeps warning. Bounded so the row clears on its own instead of
// staying amber until a restart (the cdr_fail_open_recent precedent).
const containedPanicRecentWindow = 24 * time.Hour

// crashLastMono is the monoNanos stamp of the most recent contained panic,
// stamped for EVERY occurrence (before the sink's per-component throttle), so
// a crash loop keeps the row current. 0 means "never". Monotonic so a
// wall-clock step cannot hide or age the row; process-local and never
// persisted. Observability only: nothing on a request path reads it.
var crashLastMono int64

// noteContainedPanic records the time of a contained panic.
func noteContainedPanic() {
	atomic.StoreInt64(&crashLastMono, monoNanos())
}

// checkContainedPanic returns zero or one row for a panic contained within
// containedPanicRecentWindow.
func checkContainedPanic() []OperatorContractCheck {
	last := atomic.LoadInt64(&crashLastMono)
	if last == 0 {
		return nil
	}
	rec, _ := lastCrashSnapshot()
	return containedPanicRows(atomic.LoadInt64(&statCrashRecords), monoSince(last), rec.Component, rec.ID)
}

// containedPanicRows builds the row from the count since startup, the running
// time elapsed since the latest contained panic, and the most recently RECORDED
// crash (component and id are empty when the sink throttled every record).
func containedPanicRows(total int64, ago time.Duration, component, crashID string) []OperatorContractCheck {
	if total <= 0 || ago > containedPanicRecentWindow {
		return nil
	}
	latest := ""
	if component != "" {
		latest = fmt.Sprintf(" The latest recorded one was in component %q (crash_id=%s).", sanitizeLog(component), sanitizeLog(crashID))
	}
	return []OperatorContractCheck{{
		Code:   containedPanicCode,
		Status: diagWarn,
		Message: fmt.Sprintf("%d internal fault(s) (panics) were recovered and contained on this node since startup; the most "+
			"recent was %s ago.%s The node kept running, but the request or background round that faulted did not complete, "+
			"and a background component may stay degraded until this node restarts", total, ago.Truncate(time.Second), latest),
		OperatorAction: "Open the Audit log and filter for panic_recovered to see each affected component, time and crash id. " +
			"Create a bundle under Support (it carries the redacted crash record) and quote the crash id when contacting support. " +
			"If the named component's feature is misbehaving, restart this node in a maintenance window. To be notified next " +
			"time, subscribe an alert webhook to \"Contained panic\". This row clears 24h after the last contained panic.",
	}}
}
