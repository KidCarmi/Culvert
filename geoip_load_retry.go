package main

// geoip_load_retry.go — automatic completion of a configured GeoIP database
// (proxy.geoip_db / -geoip-db) that could not be opened at STARTUP.
//
// loadGeoIP tolerates the failure: it logs it and runs with GeoIP disabled.
// Until this file that was permanent. A destination-country rule cannot match
// without a database, so an enabled country BLOCK rule stopped blocking, and
// the geoip_database_for_rules row told the operator to fix the file AND
// restart the proxy. The restart was toil: opening the configured path is
// exactly what startup already tried.
//
// This loop re-attempts the SAME path on the cadence the deferred audit-log
// open uses (audit_persist_retry.go). It chooses nothing, touches no settings
// and creates no configuration version. Once the database loads, country rules
// match exactly as they would have after the restart.
//
// It is NOT a reload of a loaded database (GEO-1, internal/geoip): the owner
// publishes only while no database is loaded and re-checks that under its lock.
// Refusal boundaries, re-checked on every attempt: nothing pending (startup
// succeeded, or none is configured), a database is already loaded, or the
// lifecycle context is cancelled.

import (
	"context"
	"fmt"
	"time"

	"github.com/KidCarmi/Culvert/internal/geoip"
)

// crashComponentGeoIPLoadRetry names the deferred GeoIP load in the crash plane.
const crashComponentGeoIPLoadRetry = "geoip_load_retry"

// startGeoIPLoadRetry runs the deferred load until it succeeds, is disarmed,
// or ctx is cancelled. Started from the background-services slice. Returns at
// once (no timer) when startup loaded the database or none is configured.
func startGeoIPLoadRetry(ctx context.Context) {
	// Same bounded cadence as the audit log: 10s doubling to 2m, 25% jitter.
	runGeoIPLoadRetry(ctx, auditOpenRetryDelay)
}

// runGeoIPLoadRetry is the loop with the backoff injected so tests drive it
// without wall-clock waits. Single goroutine; attempts are additionally
// serialized inside geoip.TryDeferredLoad.
func runGeoIPLoadRetry(ctx context.Context, delay func(attempt int) time.Duration) {
	for failed := 0; geoip.DeferredLoadPending() != ""; failed++ {
		wait := time.NewTimer(delay(failed))
		select {
		case <-wait.C:
		case <-ctx.Done():
			wait.Stop()
			return
		}
		// Per-ROUND guard (CHAOS-118): this loop is `go`-detached, so an
		// unrecovered panic would take the gateway down over a database
		// open. The owner releases its locks by defer, so a recovered round
		// simply counts as a failed attempt.
		finished := false
		panicked := runGuarded(crashComponentGeoIPLoadRetry, func() {
			finished = attemptGeoIPLoadRetry(ctx, failed+1)
		})
		if finished && !panicked {
			return
		}
	}
}

// attemptGeoIPLoadRetry makes one attempt. It reports true when the loop is
// finished: the database is now loaded, or nothing is pending any more.
func attemptGeoIPLoadRetry(ctx context.Context, attempt int) bool {
	if ctx.Err() != nil {
		return true
	}
	path, loaded, err := geoip.TryDeferredLoad()
	switch {
	case err != nil:
		if attempt == 1 || attempt%auditOpenRetryLogEvery == 0 {
			logger.Printf("GeoIP: automatic load attempt %d of the configured database failed (%q) — still retrying; GeoIP stays disabled and destination-country rules do not match until it loads",
				attempt, sanitizeLog(err.Error()))
		}
		return false
	case !loaded:
		return true
	}
	logger.Printf("GeoIP: the configured database %q became readable — loaded automatically on attempt %d; destination-country rules now match",
		sanitizeLog(path), attempt)
	// Attributed to "system": no human asked for this load at this moment.
	auditSystem("geoip.database.auto_load", path,
		fmt.Sprintf("GeoIP database loaded automatically: the database configured at startup could not be opened and became readable on attempt %d; destination-country rules did not match before this point", attempt))
	return true
}

// armGeoIPDeferredLoad records that the configured database whose startup load
// just failed should be loaded automatically once it becomes readable. Called
// only from the boot path (loadGeoIP).
func armGeoIPDeferredLoad(path string) {
	if geoip.ArmDeferredLoad(path) {
		logger.Printf("GeoIP: retrying the configured database automatically; destination-country rules start matching once it loads, with no restart")
	}
}
