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
}
