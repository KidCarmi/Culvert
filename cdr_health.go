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

// probeCDRHealth issues one Health RPC per pool member and updates the
// per-instance + aggregate snapshots.  The "active" gauge reports 1 when
// AT LEAST ONE instance is healthy; 0 when the pool is empty or all
// members are failing.  Queue depth is the minimum observed (most
// conservative backpressure signal).
func probeCDRHealth(ctx context.Context) {
	members := cdrPool.List()
	if len(members) == 0 {
		// No pool — clear aggregate snapshot so /api/cdr/health shows
		// "no data" rather than stale reassurance.
		clearCDRHealth()
		return
	}

	var (
		anyHealthy      bool
		minQueue        int32 = -1
		bestResp        *pb.HealthResponse
		aggregateFailed int
	)

	for _, pc := range members {
		probeCtx, cancel := context.WithTimeout(ctx, cdrHealthProbeDeadline)
		resp, err := pc.Client.Health(probeCtx)
		cancel()
		if err != nil {
			aggregateFailed++
			pc.clearHealth()
			continue
		}
		pc.setHealth(resp)
		if resp.Healthy {
			anyHealthy = true
			if minQueue < 0 || resp.QueueDepth < minQueue {
				minQueue = resp.QueueDepth
			}
			// Prefer any healthy response for the aggregate "last"
			// snapshot; first healthy wins deterministically (pool
			// order mirrors registry order).
			if bestResp == nil {
				bestResp = resp
			}
		}
	}

	// Aggregate failure accounting — mirrors Phase 2c semantics.
	if aggregateFailed == len(members) {
		failCount := atomic.AddInt64(&cdrHealthFailures, 1)
		atomic.StoreInt64(&statCDRInstanceHealthy, 0)
		if failCount <= cdrHealthFailStaleAfter {
			logger.Printf("CDR: all %d instance health probes failed (%d/%d)",
				len(members), failCount, cdrHealthFailStaleAfter)
		}
		if failCount >= cdrHealthFailStaleAfter {
			clearCDRHealth()
		}
		return
	}
	atomic.StoreInt64(&cdrHealthFailures, 0)
	if anyHealthy {
		atomic.StoreInt64(&statCDRInstanceHealthy, 1)
	} else {
		atomic.StoreInt64(&statCDRInstanceHealthy, 0)
	}
	if minQueue >= 0 {
		atomic.StoreInt64(&statCDRQueueDepth, int64(minQueue))
	}

	if bestResp != nil {
		cdrHealthMu.Lock()
		cdrHealthLast = bestResp
		cdrHealthLastSeen = time.Now()
		cdrHealthMu.Unlock()
	}

	// Update registry metadata (version, last-seen) for every instance
	// that responded.  Runtime telemetry only — no persistence.
	for _, pc := range members {
		if h, _ := pc.HealthSnapshot(); h != nil {
			if inst := cdrInstances.Get(pc.Name); inst != nil {
				inst.Version = h.Version
				inst.LastHealth = time.Now().UTC()
			}
		}
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

// ─── Warmup ────────────────────────────────────────────────────────────────

// warmupCDRClient fires one-shot Health probes against every pool
// member right after a successful initCDRClient, each in its own
// goroutine so boot isn't delayed by the TLS handshake latency.
// Errors are info-level: failure here just means the first real user
// request pays the handshake cost (same as today).
//
// Double-duty: validates mTLS cert + fingerprint are correctly wired
// per instance so admins see problems at boot instead of under load.
func warmupCDRClient() {
	members := cdrPool.List()
	if len(members) == 0 {
		return
	}
	for _, pc := range members {
		go func(pc *cdrPooledClient) {
			ctx, cancel := context.WithTimeout(context.Background(), cdrHealthProbeDeadline)
			defer cancel()
			resp, err := pc.Client.Health(ctx)
			if err != nil {
				logger.Printf("CDR: warmup probe failed for %q (non-fatal): %v",
					sanitizeLog(pc.Name), err)
				return
			}
			pc.setHealth(resp)
			logger.Printf("CDR: warmup OK %q — version=%q supported_types=%v profiles=%d",
				sanitizeLog(pc.Name), sanitizeLog(resp.Version), resp.SupportedTypes, len(resp.Profiles))

			// Seed aggregate snapshot too so /api/cdr/health is useful
			// before the 15s poller tick.
			cdrHealthMu.Lock()
			if cdrHealthLast == nil || !cdrHealthLast.Healthy {
				cdrHealthLast = resp
				cdrHealthLastSeen = time.Now()
			}
			cdrHealthMu.Unlock()
			if resp.Healthy {
				atomic.StoreInt64(&statCDRInstanceHealthy, 1)
				atomic.StoreInt64(&statCDRQueueDepth, int64(resp.QueueDepth))
			}
		}(pc)
	}
}
