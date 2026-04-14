package main

// Background health probe for the active Sluice instance.
//
// The poller runs every `cdrHealthInterval` and:
//   - Caches the last Health response so /api/cdr/health is cheap.
//   - Updates the `culvert_cdr_instance_healthy` gauge.
//   - Refreshes per-instance metadata (version, last-seen profiles) on the
//     registry entry so the GUI profile picker stays current.
//
// Failures are rate-limited in logs (one line per consecutive failure
// window) so a dead Sluice doesn't spam proxy.log.  The cache is cleared
// when three consecutive probes fail — better to serve "no data" than
// stale reassurance.

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

const (
	cdrHealthInterval      = 15 * time.Second
	cdrHealthProbeDeadline = 5 * time.Second
	cdrHealthFailStaleAfter = 3 // clear cache after N consecutive failures
)

var (
	cdrHealthMu       sync.RWMutex
	cdrHealthLast     *pb.HealthResponse
	cdrHealthLastSeen time.Time
	cdrHealthFailures int64 // consecutive failures
)

// init swaps the cdr_ui.go placeholder for the real snapshot reader.
func init() {
	cdrHealthSnapshot = cdrGetHealthSnapshot
}

// cdrGetHealthSnapshot returns the most recent successful Health response.
// Callers MUST treat nil as "no data" — do not dial on demand here; the
// request handler can fall back to a synchronous probe when it chooses to.
func cdrGetHealthSnapshot() *pb.HealthResponse {
	cdrHealthMu.RLock()
	defer cdrHealthMu.RUnlock()
	return cdrHealthLast
}

// cdrHealthLastSeenAt reports when the current snapshot was captured.
// Returns zero time when no snapshot exists.
func cdrHealthLastSeenAt() time.Time {
	cdrHealthMu.RLock()
	defer cdrHealthMu.RUnlock()
	return cdrHealthLastSeen
}

// startCDRHealthPoller launches the background goroutine.  Safe to call
// multiple times — each call spawns one additional goroutine that honours
// the given context, so callers using a per-boot lifecycle context get
// clean shutdown for free.  Returns immediately.
func startCDRHealthPoller(ctx context.Context) {
	go func() {
		t := time.NewTicker(cdrHealthInterval)
		defer t.Stop()
		// Fire once right away so the GUI has data before the first tick.
		probeCDRHealth(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				probeCDRHealth(ctx)
			}
		}
	}()
}

// probeCDRHealth issues one Health RPC and updates the cached snapshot.
// Exported via its lowercase name for tests; wraps the client surface with
// the deadline and failure-accounting policy.
func probeCDRHealth(ctx context.Context) {
	client := cdrActiveClient()
	if client == nil {
		// No active client — clear snapshot so /api/cdr/health shows
		// "no data" rather than stale reassurance.
		clearCDRHealth()
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, cdrHealthProbeDeadline)
	defer cancel()
	resp, err := client.Health(probeCtx)
	if err != nil {
		failCount := atomic.AddInt64(&cdrHealthFailures, 1)
		atomic.StoreInt64(&statCDRInstanceHealthy, 0)
		// Log the first few consecutive failures; after that fall silent
		// to protect proxy.log.
		if failCount <= cdrHealthFailStaleAfter {
			logger.Printf("CDR: health probe failed (%d/%d): %v", failCount, cdrHealthFailStaleAfter, err)
		}
		if failCount >= cdrHealthFailStaleAfter {
			clearCDRHealth()
		}
		return
	}
	atomic.StoreInt64(&cdrHealthFailures, 0)
	if resp.Healthy {
		atomic.StoreInt64(&statCDRInstanceHealthy, 1)
	} else {
		atomic.StoreInt64(&statCDRInstanceHealthy, 0)
	}
	atomic.StoreInt64(&statCDRQueueDepth, int64(resp.QueueDepth))

	cdrHealthMu.Lock()
	cdrHealthLast = resp
	cdrHealthLastSeen = time.Now()
	cdrHealthMu.Unlock()

	// Update registry metadata (version, last-seen) for the active instance.
	if inst := cdrActiveInstanceFromRegistry(); inst != nil {
		inst.Version = resp.Version
		inst.LastHealth = time.Now().UTC()
		// No persistence here — this is runtime telemetry, not config.
	}
}

// clearCDRHealth wipes the cached snapshot.  Called when the poller sees
// too many consecutive failures or when no client is active.
func clearCDRHealth() {
	cdrHealthMu.Lock()
	cdrHealthLast = nil
	cdrHealthLastSeen = time.Time{}
	cdrHealthMu.Unlock()
}

// cdrActiveInstanceFromRegistry returns the registry entry for the
// singleton client, or nil when none matches.  Used by the poller to
// bind runtime metadata back to the persisted entry.
func cdrActiveInstanceFromRegistry() *CDREnrolledInstance {
	// Phase 2c is single-instance: the first enabled entry is the active
	// one.  Phase 2d will replace this with a client↔instance map.
	return cdrInstances.firstEnabled()
}

// ─── Warmup ────────────────────────────────────────────────────────────────

// warmupCDRClient fires a one-shot Health probe right after a successful
// initCDRClient, in its own goroutine so boot isn't delayed by the TLS
// handshake latency.  Errors are info-level: failure here just means the
// first real user request pays the handshake cost (same as today).
//
// Double-duty: validates mTLS cert + fingerprint are correctly wired so
// admins see problems at boot instead of on the first real download.
func warmupCDRClient() {
	client := cdrActiveClient()
	if client == nil {
		return
	}
	go func(c *CDRClient) {
		ctx, cancel := context.WithTimeout(context.Background(), cdrHealthProbeDeadline)
		defer cancel()
		if resp, err := c.Health(ctx); err != nil {
			logger.Printf("CDR: warmup probe failed (non-fatal): %v", err)
			return
		} else if resp != nil {
			logger.Printf("CDR: warmup OK — sluice version=%q supported_types=%v profiles=%d",
				sanitizeLog(resp.Version), resp.SupportedTypes, len(resp.Profiles))
			// Seed the snapshot + counters so /api/cdr/health is useful
			// before the 15s poller tick.
			cdrHealthMu.Lock()
			cdrHealthLast = resp
			cdrHealthLastSeen = time.Now()
			cdrHealthMu.Unlock()
			if resp.Healthy {
				atomic.StoreInt64(&statCDRInstanceHealthy, 1)
			}
			atomic.StoreInt64(&statCDRQueueDepth, int64(resp.QueueDepth))
		}
	}(client)
}
