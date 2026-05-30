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
	"os"
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
		clearCDRHealth()
		return
	}
	agg := probeAllMembers(ctx, members)
	if agg.failed == len(members) {
		handleAllMembersFailed(len(members))
		return
	}
	applyAggregateHealth(agg)
	updateRegistryMetadataFromPool(members)
	propagateServerRotation(members)

	// Opportunistic auto-renewal: any instance whose client cert is
	// within the renewal window gets a RenewCert call fired off in a
	// background goroutine.  Single-flight prevents double-renewal
	// when successive polls see the same expiry value.
	maybeRenewExpiringClients(members)
}

// propagateServerRotation reads Health.rotated_fingerprint{,_until_unix}
// for each pool member and mirrors it onto the registry entry so
// subsequent dials accept EITHER pin.  Once the grace window has
// passed, promotes RotatedFingerprint to ServerFingerprint and clears
// the rotation fields, then triggers a reinit so the dialled client
// drops the old pin.
func propagateServerRotation(members []*cdrPooledClient) {
	var needReinit bool
	for _, pc := range members {
		h, _ := pc.HealthSnapshot()
		if h == nil {
			continue
		}
		inst := cdrInstances.Get(pc.Name)
		if inst == nil {
			continue
		}
		newRotated := normalisePinHex(h.RotatedFingerprint)
		// Case 1: grace window expired — promote + clear.
		if inst.RotatedFingerprint != "" &&
			inst.RotatedFingerprintUntilUnix > 0 &&
			time.Now().Unix() >= inst.RotatedFingerprintUntilUnix {
			// The fingerprint advertised as "primary" in Health is the
			// new one.  Adopt it.
			if newPrimary := normalisePinHex(h.ServerFingerprint); newPrimary != "" {
				inst.ServerFingerprint = newPrimary
			}
			inst.RotatedFingerprint = ""
			inst.RotatedFingerprintUntilUnix = 0
			needReinit = true
			if err := cdrInstances.Save(); err != nil {
				logger.Printf("CDR: rotation promote: save registry: %v", err)
			}
			logger.Printf("CDR: server-cert rotation complete for %q — promoted new fingerprint", sanitizeLog(pc.Name))
			continue
		}
		// Case 2: new rotation signalled.
		if newRotated != "" &&
			h.RotatedFingerprintUntilUnix > 0 &&
			inst.RotatedFingerprint != newRotated {
			inst.RotatedFingerprint = newRotated
			inst.RotatedFingerprintUntilUnix = h.RotatedFingerprintUntilUnix
			needReinit = true
			if err := cdrInstances.Save(); err != nil {
				logger.Printf("CDR: rotation stage: save registry: %v", err)
			}
			logger.Printf("CDR: server-cert rotation signalled by %q — dual-pin active until %s",
				sanitizeLog(pc.Name), time.Unix(h.RotatedFingerprintUntilUnix, 0).UTC().Format(time.RFC3339))
		}
	}
	if needReinit {
		if err := initCDRClient(cdrActiveConfig()); err != nil {
			logger.Printf("CDR: rotation re-init failed (existing pool still serving): %q",
				sanitizeLog(err.Error()))
		}
	}
}

// cdrRenewWindow is the days-remaining threshold that triggers
// auto-renewal.  30 days matches Sluice's recommendation — gives
// plenty of headroom if a Sluice instance is briefly unreachable.
const cdrRenewWindow = 30

// maybeRenewExpiringClients scans pool members and kicks off a
// RenewCert call for any whose client cert is within the renewal
// window.  Each renewal runs in its own goroutine so a slow Sluice
// doesn't stall the poller.
func maybeRenewExpiringClients(members []*cdrPooledClient) {
	for _, pc := range members {
		inst := cdrInstances.Get(pc.Name)
		if inst == nil || inst.ClientCertPath == "" {
			continue
		}
		exp, err := loadCertExpiry(inst.ClientCertPath)
		if err != nil {
			continue // no data → no action; next poll retries
		}
		if daysUntil(exp) > cdrRenewWindow {
			continue
		}
		if !pc.renewInFlight.CompareAndSwap(0, 1) {
			continue // already renewing — skip silently
		}
		go runRenewFor(pc, inst)
	}
}

// runRenewFor performs a single RenewCert RPC, persists the new
// cert/key atomically, and re-initialises the pool so the fresh
// credentials take effect for subsequent RPCs.  Errors are logged
// but non-fatal — the old cert still works until its own NotAfter,
// giving us up to cdrRenewWindow days of retries.
func runRenewFor(pc *cdrPooledClient, inst *CDREnrolledInstance) {
	defer pc.renewInFlight.Store(0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := pc.Client.RenewCert(ctx, &pb.RenewCertRequest{})
	if err != nil {
		logger.Printf("CDR: RenewCert failed for %q (will retry next poll): %v",
			sanitizeLog(pc.Name), err)
		return
	}
	if len(resp.ClientCert) == 0 || len(resp.ClientKey) == 0 {
		logger.Printf("CDR: RenewCert for %q returned empty material; skipping", sanitizeLog(pc.Name))
		return
	}

	// Write the new bundle to disk atomically via tmp + rename, so a
	// crash mid-rename leaves either the old or the new cert intact —
	// never a half-written one.  Same 0600 perms as enrollment.
	if werr := os.WriteFile(inst.ClientCertPath+".tmp", resp.ClientCert, 0o600); werr != nil {
		logger.Printf("CDR: RenewCert %q: write cert tmp: %v", sanitizeLog(pc.Name), werr)
		return
	}
	// CA-3: encrypt the client key at rest when enabled; plaintext otherwise.
	// The cert above stays a plaintext public cert.
	keyOut, kerr := encodeCDRClientKeyForWrite(inst.ClientKeyPath, resp.ClientKey)
	if kerr != nil {
		_ = os.Remove(inst.ClientCertPath + ".tmp")
		logger.Printf("CDR: RenewCert %q: encrypt key: %v", sanitizeLog(pc.Name), kerr)
		return
	}
	if werr := os.WriteFile(inst.ClientKeyPath+".tmp", keyOut, 0o600); werr != nil {
		_ = os.Remove(inst.ClientCertPath + ".tmp")
		logger.Printf("CDR: RenewCert %q: write key tmp: %v", sanitizeLog(pc.Name), werr)
		return
	}
	if werr := os.Rename(inst.ClientCertPath+".tmp", inst.ClientCertPath); werr != nil {
		logger.Printf("CDR: RenewCert %q: swap cert: %v", sanitizeLog(pc.Name), werr)
		return
	}
	if werr := os.Rename(inst.ClientKeyPath+".tmp", inst.ClientKeyPath); werr != nil {
		logger.Printf("CDR: RenewCert %q: swap key: %v", sanitizeLog(pc.Name), werr)
		return
	}

	logger.Printf("CDR: RenewCert %q succeeded — days_until_expiry=%d",
		sanitizeLog(pc.Name), resp.DaysUntilExpiry)

	// Re-init the client so the next RPC uses the new cert.  The old
	// *CDRClient (and its grpc.ClientConn) gets closed inside
	// initCDRClient's pool.replace() path.  Failure here is non-fatal:
	// the old cert keeps working until its NotAfter, so traffic
	// continues — next poll retries the reinit.
	if err := initCDRClient(cdrActiveConfig()); err != nil {
		logger.Printf("CDR: RenewCert %q: reinit failed (old cert still valid): %q",
			sanitizeLog(pc.Name), sanitizeLog(err.Error()))
	}
}

// probeAllMembers fires one Health RPC per pool member and collects the
// aggregate view.  Extracted from probeCDRHealth to bound cyclomatic.
func probeAllMembers(ctx context.Context, members []*cdrPooledClient) probeAggregate {
	var agg probeAggregate
	agg.minQueue = -1
	for _, pc := range members {
		probeCtx, cancel := context.WithTimeout(ctx, cdrHealthProbeDeadline)
		resp, err := pc.Client.Health(probeCtx)
		cancel()
		if err != nil {
			agg.failed++
			pc.clearHealth()
			continue
		}
		pc.setHealth(resp)
		if !resp.Healthy {
			continue
		}
		agg.anyHealthy = true
		if agg.minQueue < 0 || resp.QueueDepth < agg.minQueue {
			agg.minQueue = resp.QueueDepth
		}
		if agg.bestResp == nil {
			agg.bestResp = resp
		}
	}
	return agg
}

// probeAggregate holds the combined view of one polling tick.
type probeAggregate struct {
	anyHealthy bool
	minQueue   int32
	bestResp   *pb.HealthResponse
	failed     int
}

// handleAllMembersFailed applies the Phase 2c "everyone failed" policy:
// bump counter, log sparingly, clear the snapshot once we've been
// failing for long enough that the UI shouldn't trust stale data.
func handleAllMembersFailed(memberCount int) {
	failCount := atomic.AddInt64(&cdrHealthFailures, 1)
	atomic.StoreInt64(&statCDRInstanceHealthy, 0)
	if failCount <= cdrHealthFailStaleAfter {
		logger.Printf("CDR: all %d instance health probes failed (%d/%d)",
			memberCount, failCount, cdrHealthFailStaleAfter)
	}
	if failCount >= cdrHealthFailStaleAfter {
		clearCDRHealth()
	}
}

// applyAggregateHealth updates the aggregate gauges + snapshot from the
// probe result.
func applyAggregateHealth(agg probeAggregate) {
	atomic.StoreInt64(&cdrHealthFailures, 0)
	if agg.anyHealthy {
		atomic.StoreInt64(&statCDRInstanceHealthy, 1)
	} else {
		atomic.StoreInt64(&statCDRInstanceHealthy, 0)
	}
	if agg.minQueue >= 0 {
		atomic.StoreInt64(&statCDRQueueDepth, int64(agg.minQueue))
	}
	if agg.bestResp != nil {
		cdrHealthMu.Lock()
		cdrHealthLast = agg.bestResp
		cdrHealthLastSeen = time.Now()
		cdrHealthMu.Unlock()
	}
}

// updateRegistryMetadataFromPool copies runtime telemetry (version,
// last-health) from each pool member back onto its registry entry.
// Not persisted — purely for the admin GUI.
func updateRegistryMetadataFromPool(members []*cdrPooledClient) {
	for _, pc := range members {
		h, _ := pc.HealthSnapshot()
		if h == nil {
			continue
		}
		inst := cdrInstances.Get(pc.Name)
		if inst == nil {
			continue
		}
		inst.Version = h.Version
		inst.LastHealth = time.Now().UTC()
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
