package main

// scan_signature_watch.go — CHAOS-107: the signature-generation observer.
//
// The scan verdict cache is keyed on the SHA-256 of the content alone, so it
// carries no reference to the signature set that produced the verdict. YARA
// rule mutations already flush it on every admin CRUD path (ui_security.go,
// "Tier 1.1"), because those changes arrive THROUGH Culvert. ClamAV definitions
// do not: freshclam updates them out-of-process, several times a day, and the
// node only learns about it by asking. Nothing asked on a schedule, so a
// "clean" verdict kept being served for the rest of CacheTTL after the
// signature that would have caught it landed.
//
// internal/secscan owns the reconciliation (it owns the cache, per ADR-0006);
// this file owns only the cadence, which is a startup/wiring concern and so
// belongs to main.

import (
	"context"
	"time"
)

// crashComponentScanSigWatch names this worker in the crash record the
// per-round guard writes (CHAOS-105).
const crashComponentScanSigWatch = "scan_signature_watch"

// scanSigPollInterval is how often the node re-reads the ClamAV signature
// identity.
//
// Deliberately SHORTER than the scanner's own 10-minute VERSION cache rather
// than equal to it: a tick that lands inside the previous window is served from
// that cache and costs nothing, and the overlap is what keeps worst-case
// detection latency near one VERSION window instead of two. One VERSION command
// to a local daemon per ~10 minutes is not a load consideration; signature sets
// change a few times a day, so a tighter interval would buy nothing real.
const scanSigPollInterval = 5 * time.Minute

// startScanSignatureWatch polls the ClamAV signature identity until ctx is
// cancelled, flushing the verdict cache whenever the identity changes. Parented
// to the lifecycle context (loadBackgroundServices), so it exits on shutdown.
//
// It no-ops by construction wherever there is nothing to observe — no ClamAV
// configured, scanning disabled, or a client without the VERSION capability all
// make ClamAVVersion report not-ok — so it is started unconditionally rather
// than gated on a scanning mode that can be reconfigured after startup.
//
// The opening observation is immediate and runs BEFORE the first tick, which is
// what makes the common case free: initScanning (main stmt 265) precedes
// initBackgroundServices (stmt 269), so this baselines against an empty verdict
// cache and records the generation without flushing anything. The reconciliation
// does not DEPEND on winning that race — a baseline onto a non-empty cache
// flushes it, since those entries have no provenance — but winning it is why a
// healthy boot shows no flush at all.
func startScanSignatureWatch(ctx context.Context) {
	runGuarded(crashComponentScanSigWatch, func() { globalSecScanner.RefreshSignatures() })

	tick := time.NewTicker(scanSigPollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// CHAOS-105: a signature poll must not be able to end the process.
			// Guarding the ROUND (not the goroutine) keeps the ticker alive, so
			// a transient fault costs one interval instead of silently
			// disarming the observer for the lifetime of the process — which
			// would reintroduce exactly the stale-clean window this exists to
			// close, with the dashboard still green.
			runGuarded(crashComponentScanSigWatch, func() { globalSecScanner.RefreshSignatures() })
		}
	}
}
