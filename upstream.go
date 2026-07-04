package main

// upstream.go — Upstream-pool shim: aliases + singleton over
// internal/upstream (ADR-0002). The engine — circuit breaker, round-robin
// failover pool, health-check loop, config/status types — lives in the
// package; main keeps the process singleton and the transport wiring
// (applyUpstreamProxy, upstream_transport.go).
//
// Persistence stays where it was: the pool itself does not persist —
// admin_settings.json round-trips upstreamPool.Entries() (raw, may embed
// credentials; UpstreamProxiesSaved sentinel), and List() stays redacted for
// display. Circuit-breaker params are YAML-owned (Configure remembers them;
// SetProxies reuses them) — see CLAUDE.md "Upstream pool durability".

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/upstream"
)

type (
	// UpstreamEntry is one parent proxy from config.yaml.
	UpstreamEntry = upstream.Entry
	// UpstreamConfig is the "upstream" section of config.yaml.
	UpstreamConfig = upstream.Config
	// UpstreamStatus is returned by the admin API.
	UpstreamStatus = upstream.Status
	// UpstreamProxy represents one parent proxy in the chain.
	UpstreamProxy = upstream.Proxy
	// UpstreamPool manages a set of parent proxies with failover.
	UpstreamPool = upstream.Pool
)

var upstreamPool = &UpstreamPool{}

func runUpstreamHealthCheckLoop(ctx context.Context, pool *UpstreamPool, interval time.Duration) {
	upstream.RunHealthCheckLoop(ctx, pool, interval)
}

func formatUpstreamSummary(entries []UpstreamEntry) string {
	return upstream.FormatSummary(entries)
}
