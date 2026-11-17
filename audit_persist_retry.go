package main

// audit_persist_retry.go — automatic completion of a configured audit log
// (audit_log_file / -audit-log) that could not be opened at STARTUP.
//
// loadObservability tolerates the failure: it logs it, records the operator's
// intent (auditLogConfiguredPath) and keeps the trail in the volatile ring.
// Until this file that was the end of it, and the audit_log_persistence row
// told the operator to fix the path AND restart the proxy. The restart was
// toil: opening the configured path is exactly what startup already tried.
//
// This loop does what that restart would do for the trail, minus the human and
// minus the loss: it re-attempts the SAME path on a bounded backoff, and the
// owner (internal/audit, deferred.go) writes the entries recorded in the
// meantime before any newer one. It chooses nothing, touches no settings and
// creates no configuration version.
//
// Refusal boundaries live in the owner and are re-checked under its lock on
// every attempt: nothing pending (startup succeeded, or another writer was
// installed), the shutdown hook has closed the sink, or the lifecycle context
// is cancelled. The one-shot prepare-downgrade command never arms it, so that
// command still REFUSES when its audit sink cannot be opened.

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

const (
	// auditOpenRetryInitialDelay is the wait before the first retry: a path
	// fixed by an operator (chown, mount) is usually fixed within minutes.
	auditOpenRetryInitialDelay = 10 * time.Second
	// auditOpenRetryMaxDelay caps the backoff. There is no attempt limit —
	// the configured path stays the operator's intent for the life of the
	// process — so this is the cadence bound: one open(2) every two minutes.
	auditOpenRetryMaxDelay = 2 * time.Minute
	// auditOpenRetryJitterFrac spreads attempts of nodes sharing a volume.
	auditOpenRetryJitterFrac = 0.25
	// auditOpenRetryLogEvery rate-limits the failed-attempt log line. The
	// degraded trail is already reported by the audit_log_persistence row.
	auditOpenRetryLogEvery = 10
)

// crashComponentAuditOpenRetry names the deferred audit-log open in the crash plane.
const crashComponentAuditOpenRetry = "audit_open_retry"

// auditOpenRetryDelay is the production backoff: 10s doubling to a 2-minute
// cap, plus up to 25% jitter. attempt is the number of failed retries so far.
func auditOpenRetryDelay(attempt int) time.Duration {
	d := auditOpenRetryMaxDelay
	if attempt >= 0 && attempt < 8 {
		if scaled := auditOpenRetryInitialDelay << attempt; scaled < auditOpenRetryMaxDelay {
			d = scaled
		}
	}
	return d + time.Duration(rand.Float64()*auditOpenRetryJitterFrac*float64(d)) // #nosec G404 -- jitter, not crypto
}

// startAuditOpenRetry runs the deferred open until it succeeds, is disarmed,
// or ctx is cancelled. Started from the background-services slice. Returns at
// once (no timer) when startup opened the log or none is configured.
func startAuditOpenRetry(ctx context.Context) {
	runAuditOpenRetry(ctx, auditOpenRetryDelay)
}

// runAuditOpenRetry is the loop with the backoff injected so tests drive it
// without wall-clock waits. Single goroutine: attempts are serialized here and
// additionally inside audit.TryDeferredOpen.
func runAuditOpenRetry(ctx context.Context, delay func(attempt int) time.Duration) {
	failed := 0
	for audit.DeferredOpenPending() != "" {
		t := time.NewTimer(delay(failed))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		// Per-ROUND guard (CHAOS-118): this loop is `go`-detached, so an
		// unrecovered panic would take the gateway down over an audit-file
		// open. The owner releases its locks by defer/explicit unlock before
		// returning, so keep-going is safe.
		done := false
		if runGuarded(crashComponentAuditOpenRetry, func() {
			done = attemptAuditOpenRetry(ctx, failed+1)
		}) {
			done = false
		}
		if done {
			return
		}
		failed++
	}
}

// attemptAuditOpenRetry makes one attempt. It reports true when the loop is
// finished: the log is now persisting, or nothing is pending any more.
func attemptAuditOpenRetry(ctx context.Context, attempt int) bool {
	if ctx.Err() != nil {
		return true
	}
	res, opened, err := audit.TryDeferredOpen()
	if err != nil {
		if attempt == 1 || attempt%auditOpenRetryLogEvery == 0 {
			logger.Printf("Audit: automatic open attempt %d of the configured audit log failed (%q) — still retrying; the trail is in-memory only until it opens",
				attempt, sanitizeLog(err.Error()))
		}
		return false
	}
	if !opened {
		return true
	}
	logger.Printf("Audit: the configured audit log %q became writable — durable persistence established automatically on attempt %d; %d entries recorded meanwhile were written, %d had been evicted and are counted as audit write errors",
		sanitizeLog(res.Path), attempt, res.Backfilled, res.Dropped)
	// Attributed to "system": no human asked for this open at this moment.
	// It lands in the file right after the backfill, marking where the
	// recovered gap ends.
	auditSystem("audit.persistence.auto_open", res.Path,
		fmt.Sprintf("durable audit persistence established automatically: the audit log configured at startup could not be opened and became writable on attempt %d; %d entries recorded meanwhile were written to it, %d were evicted before it opened", attempt, res.Backfilled, res.Dropped))
	return true
}

// armAuditDeferredOpen records that the configured audit log whose startup
// open just failed should be opened automatically once it becomes writable.
// Called only from the runtime boot path (loadObservability), never from a
// one-shot command that must refuse without its audit sink.
func armAuditDeferredOpen(path string) {
	if audit.ArmDeferredOpen(path) {
		logger.Printf("Audit: retrying the configured audit log automatically; entries recorded until it opens are kept and written to it first (up to the newest %d)", audit.MaxRing)
	}
}
