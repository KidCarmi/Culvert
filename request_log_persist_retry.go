package main

// request_log_persist_retry.go — automatic completion of a configured request
// log (request_log_file / -request-log) that could not be opened at STARTUP.
//
// loadObservability tolerates the failure: it logs it, records the operator's
// intent (requestLogConfiguredPath) and keeps the traffic log in the volatile
// ring. Until this file that was permanent, and the request_log_persistence
// row told the operator to fix the path AND restart the proxy. The restart was
// toil: opening the configured path is exactly what startup already tried.
//
// This loop re-attempts the SAME path with the SAME rotation size on the
// cadence the deferred audit-log open uses (audit_persist_retry.go). The owner
// (internal/reqlog, deferred.go) publishes the sink through Init's transition.
// It chooses nothing, touches no settings and creates no configuration
// version. Unlike the audit trail, entries recorded before the open are NOT
// replayed into the file (deferred.go explains why); they stay in the ring.
//
// Refusal boundaries live in the owner and are re-checked under its lock on
// every attempt: nothing pending (startup succeeded, or another sink was
// wired), the shutdown hook has closed the log, or the lifecycle context is
// cancelled.

import (
	"context"
	"fmt"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// crashComponentRequestLogOpenRetry names the deferred request-log open in the
// crash plane.
const crashComponentRequestLogOpenRetry = "request_log_open_retry"

// startRequestLogOpenRetry runs the deferred open until it succeeds, is
// disarmed, or ctx is cancelled. Started from the background-services slice.
// Returns at once (no timer) when startup opened the log or none is configured.
func startRequestLogOpenRetry(ctx context.Context) {
	// Same bounded cadence as the audit log: 10s doubling to 2m, 25% jitter.
	runRequestLogOpenRetry(ctx, auditOpenRetryDelay)
}

// runRequestLogOpenRetry is the loop with the backoff injected so tests drive
// it without wall-clock waits. Single goroutine; attempts are additionally
// serialized inside reqlog.TryDeferredOpen.
func runRequestLogOpenRetry(ctx context.Context, delay func(attempt int) time.Duration) {
	for failed := 0; reqlog.DeferredOpenPending() != ""; failed++ {
		wait := time.NewTimer(delay(failed))
		select {
		case <-wait.C:
		case <-ctx.Done():
			wait.Stop()
			return
		}
		// Per-ROUND guard (CHAOS-118): this loop is `go`-detached, so an
		// unrecovered panic would take the gateway down over a log-file open.
		// The owner releases its locks by defer/explicit unlock, so a
		// recovered round simply counts as a failed attempt.
		finished := false
		panicked := runGuarded(crashComponentRequestLogOpenRetry, func() {
			finished = attemptRequestLogOpenRetry(ctx, failed+1)
		})
		if finished && !panicked {
			return
		}
	}
}

// attemptRequestLogOpenRetry makes one attempt. It reports true when the loop
// is finished: the log is now persisting, or nothing is pending any more.
func attemptRequestLogOpenRetry(ctx context.Context, attempt int) bool {
	if ctx.Err() != nil {
		return true
	}
	path, opened, err := reqlog.TryDeferredOpen()
	switch {
	case err != nil:
		if attempt == 1 || attempt%auditOpenRetryLogEvery == 0 {
			logger.Printf("RequestLog: automatic open attempt %d of the configured request log failed (%q) — still retrying; the request log is in-memory only until it opens",
				attempt, sanitizeLog(err.Error()))
		}
		return false
	case !opened:
		return true
	}
	logger.Printf("RequestLog: the configured request log %q became writable — durable persistence established automatically on attempt %d; entries recorded before this point remain in the in-memory ring only",
		sanitizeLog(path), attempt)
	// Attributed to "system": no human asked for this open at this moment.
	auditSystem("request_log.persistence.auto_open", path,
		fmt.Sprintf("durable request-log persistence established automatically: the request log configured at startup could not be opened and became writable on attempt %d; entries recorded before it opened were not written to it", attempt))
	return true
}

// armRequestLogDeferredOpen records that the configured request log whose
// startup open just failed should be opened automatically, with the same
// rotation size, once it becomes writable. Called only from the runtime boot
// path (loadObservability).
func armRequestLogDeferredOpen(path string, maxMB int) {
	if reqlog.ArmDeferredOpen(path, maxMB) {
		logger.Printf("RequestLog: retrying the configured request log automatically; it starts persisting once the path becomes writable, with no restart")
	}
}
