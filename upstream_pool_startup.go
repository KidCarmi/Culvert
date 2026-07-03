package main

// upstream_pool_startup.go — loader for the upstream-pool slice. Owns the
// side effects: configuring the upstreamPool singleton, rewiring the shared
// upstream transport (applyUpstreamProxy — which goes through
// swapUpstreamTransport per the S6 read-only-after-publication rule), and
// starting the cancellable health-check loop. The resolver + DTO live in
// upstream_pool_startup_config.go; the initUpstreamPool shim in main.go
// wires them.

import "context"

// loadUpstreamPool applies the resolved upstream config. ORDER IS THE
// CONTRACT (verbatim from the pre-slice init): Configure the pool BEFORE
// applyUpstreamProxy reads it to rewire the transport; the health loop
// (P1.3 / S4.UpstreamHealth — parented to ctx so it exits on shutdown)
// starts only when a positive interval was resolved.
func loadUpstreamPool(cfg upstreamPoolStartupConfig, ctx context.Context) {
	upstreamPool.Configure(cfg.Proxies, cfg.CBThreshold, cfg.CBTimeout)
	applyUpstreamProxy()
	logger.Printf("Upstream: %s", formatUpstreamSummary(cfg.Proxies))

	if cfg.HealthInterval <= 0 {
		return
	}
	go runUpstreamHealthCheckLoop(ctx, upstreamPool, cfg.HealthInterval)
}
