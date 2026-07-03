package main

// background_services_startup.go — loader for the background-services slice.
// Owns the side effects: the SSE broadcaster + alert-retry goroutines, the
// updater allowlist install + URL validation, the updater token, the
// version-file write for the sidecar, the update-checker goroutine, and
// cluster-update recovery. The resolver + DTO live in
// background_services_startup_config.go; the initBackgroundServices shim in
// main.go wires them.

import (
	"context"
	"os"
)

// loadBackgroundServices starts the background services. ORDER IS THE
// CONTRACT (verbatim from the pre-slice init): the allowlist is installed
// BEFORE the updater URL is validated (H4 — validateUpdaterURL consults it),
// and recoverClusterUpdate runs last so a recovered rolling update sees the
// fully-wired update subsystem.
func loadBackgroundServices(cfg backgroundServicesStartupConfig, ctx context.Context) {
	// P1.2 / S4.SSE: parented to ctx so the goroutine exits when
	// runProxyUntilShutdown cancels the lifecycle context.
	startSSEBroadcaster(ctx)

	// F16: alert retry queue.
	go startAlertRetryLoop(ctx)

	// Docker self-update wiring. H4: allowlist first, then validate.
	SetUpdaterURLAllowlist(cfg.UpdaterURLAllowlist)
	if u := cfg.UpdaterURLCandidate; u != "" {
		if err := validateUpdaterURL(u); err != nil {
			logWarnf("Update: invalid updater URL %q: %v — using default", u, err)
		} else {
			updaterURL = u
		}
	}
	ensureUpdaterToken()

	// Write the clean semver to the shared volume so the updater sidecar can
	// read it without inspecting Docker image tags (which show "latest" for
	// local builds). Path is the sidecar contract — fixed.
	if cfg.VersionFileBody != "" {
		// #nosec G306 -- 0644 required: updater sidecar runs with cap_drop:ALL (no DAC_OVERRIDE)
		_ = os.WriteFile("/data/version.txt", []byte(cfg.VersionFileBody+"\n"), 0o644)
	}

	go startUpdateChecker(ctx)
	recoverClusterUpdate()
}
