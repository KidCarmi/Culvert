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

	// ADR-0011 §3: decryption inspection-coverage trend sampler (volatile time-series
	// behind the Decryption Health panel's coverage-erosion chart).
	go startDecCoverageSampler(ctx)
}
