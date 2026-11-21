package main

// background_services_startup.go — loader for the background-services slice.
// Owns the side effects: the SSE broadcaster + alert-retry goroutines. The
// resolver + DTO live in background_services_startup_config.go; the
// initBackgroundServices shim in main.go wires them. (The legacy updater
// wiring — allowlist/URL/token/version-file/update-checker/cluster-update —
// was removed with the updater sidecar.)

import (
	"context"
)

// loadBackgroundServices starts the background services.
func loadBackgroundServices(cfg backgroundServicesStartupConfig, ctx context.Context) {
	// P1.2 / S4.SSE: parented to ctx so the goroutine exits when
	// runProxyUntilShutdown cancels the lifecycle context.
	startSSEBroadcaster(ctx)

	// F16: alert retry queue.
	go startAlertRetryLoop(ctx)

	// M3: support debug capture-level auto-revert watchdog (active auto-stop; the
	// on-read expiry check already guarantees restart-surviving revert without it).
	go startDebugLevelWatchdog(ctx)

	// NOTE: the support-bundle age-retention janitor is deliberately NOT started
	// here. Its boot sweep must observe the GUI-configured retention caps (Slice B),
	// which LoadAdminSettings restores LATER in startup — so it is started from the
	// persistent-admin-state loader, immediately after LoadAdminSettings, to avoid a
	// boot sweep running the default caps for up to one tick.

	// CHAOS-81: the SIEM feed's degradation transition. The drop observer is
	// driven by traffic, and traffic stops — a collector that dies and is then
	// followed by a quiet period would cross the threshold with nothing left
	// to fire the alert. Detection only; no-ops when no collector is
	// configured.
	go startSyslogHealthWatchdog(ctx)

	// The SIEM feed's boot-dial retry: a collector that could not be
	// connected at startup is re-dialled on a bounded backoff until it
	// connects, the operator changes or disables the target, or the node
	// shuts down. Idle (no timer, no dial) unless a boot dial failed.
	go startSyslogIntentRetry(ctx)

	// The audit log's deferred open: a configured audit_log_file that could
	// not be opened at startup is re-attempted on a bounded backoff until it
	// opens (entries recorded meanwhile are written first), or the node shuts
	// down. Returns at once unless the startup open failed.
	go startAuditOpenRetry(ctx)

	// The request log's deferred open: a configured request_log_file that
	// could not be opened at startup is re-attempted on the same bounded
	// backoff until it opens, or the node shuts down. Returns at once unless
	// the startup open failed.
	go startRequestLogOpenRetry(ctx)

	// The GeoIP database's deferred load: a configured geoip_db that could not
	// be opened at startup is re-attempted on the same bounded backoff until
	// it loads, or the node shuts down. It never reloads a loaded database.
	// Returns at once unless the startup load failed.
	go startGeoIPLoadRetry(ctx)

	// CHAOS-107: the ClamAV signature-generation observer. ClamAV definitions
	// change out-of-process (freshclam), so the verdict cache can only be
	// reconciled against them by ASKING on a cadence; nothing else in the
	// process does. Self-no-ops when no local ClamAV is configured.
	go startScanSignatureWatch(ctx)

	// ADR-0011 §3: decryption inspection-coverage trend sampler (volatile time-series
	// behind the Decryption Health panel's coverage-erosion chart).
	go startDecCoverageSampler(ctx)
}
