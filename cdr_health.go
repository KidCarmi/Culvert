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

	"github.com/KidCarmi/Sluice/pkg/sluiceauth"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

const (
	cdrHealthInterval       = 15 * time.Second
	cdrHealthProbeDeadline  = 5 * time.Second
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
		// CHAOS-24: contain the ROUND — a panic probing one CDR member must
		// not kill the gateway, and must not silently stop the poller (the
		// health snapshot would freeze at its last value and the GUI would
		// keep showing a stale "healthy" long after the pool went down).
		runGuarded("cdr_health", func() { probeCDRHealth(ctx) })
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				runGuarded("cdr_health", func() { probeCDRHealth(ctx) })
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

	// 2E-C R7: resolve renewals whose outcome was lost BEFORE deciding on
	// new ones (an unresolved generation refuses further staging).
	reconcilePendingRenewals(members)

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
// 2E-C: all registry mutations go through locked registry mutators that
// persist inside their own critical section — the earlier shape wrote
// through Get()'s shared pointer with no lock and then called the bare
// Save(), which raced admin mutations in both memory and the durable
// file (see cdrstore.go Save + TestCDR2EC_RemovalIsNotResurrectedByConcurrentSave).
func propagateServerRotation(members []*cdrPooledClient) {
	var needReinit bool
	for _, pc := range members {
		h, _ := pc.HealthSnapshot()
		if h == nil {
			continue
		}
		inst, ok := cdrInstances.GetCopy(pc.Name)
		if !ok {
			continue
		}
		newRotated := normalisePinHex(h.RotatedFingerprint)
		// Case 1: grace window expired — promote + clear.  The
		// fingerprint advertised as "primary" in Health is the new one.
		if inst.RotatedFingerprint != "" &&
			inst.RotatedFingerprintUntilUnix > 0 &&
			time.Now().Unix() >= inst.RotatedFingerprintUntilUnix {
			changed, err := cdrInstances.PromoteRotation(pc.Name, normalisePinHex(h.ServerFingerprint))
			if err != nil {
				logger.Printf("CDR: rotation promote: save registry: %v", err)
			}
			if changed {
				needReinit = true
				logger.Printf("CDR: server-cert rotation complete for %q — promoted new fingerprint", sanitizeLog(pc.Name))
			}
			continue
		}
		// Case 2: new rotation signalled.
		if newRotated != "" &&
			h.RotatedFingerprintUntilUnix > 0 &&
			inst.RotatedFingerprint != newRotated {
			changed, err := cdrInstances.StageRotation(pc.Name, newRotated, h.RotatedFingerprintUntilUnix)
			if err != nil {
				logger.Printf("CDR: rotation stage: save registry: %v", err)
			}
			if changed {
				needReinit = true
				logger.Printf("CDR: server-cert rotation signalled by %q — dual-pin active until %s",
					sanitizeLog(pc.Name), time.Unix(h.RotatedFingerprintUntilUnix, 0).UTC().Format(time.RFC3339))
			}
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
		inst, ok := cdrInstances.GetCopy(pc.Name)
		if !ok || inst.ClientCertPath == "" {
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

// runRenewFor performs ONE renewal as a recoverable transaction (2E-C R7,
// cdr_lineage.go) and re-initialises the pool so the fresh credential
// takes effect. `inst` is the registry snapshot the DECISION was taken
// from; the instance is re-validated under its lifecycle lock before
// anything is staged, so a renewal decided before a delete/revoke never
// writes PEMs, resurrects registry state or introduces a new fingerprint
// after the removal committed.
//
// Durable order: intent (operation id) → RPC → issued fingerprint →
// tmp PEMs → cert rename → key rename → activation. Every step after the
// RPC leaves the durable lineage able to name the credential Sluice now
// trusts, and reconcileCredentialLineage finishes an interrupted swap at
// the next boot. Errors are logged, not fatal — the previous credential
// keeps working until its NotAfter, giving cdrRenewWindow days of retries.
func runRenewFor(pc *cdrPooledClient, inst CDREnrolledInstance) {
	defer pc.renewInFlight.Store(0)
	unlock := cdrLifecycle.lock(inst.Name)
	defer unlock()

	cur, ok := cdrInstances.GetCopy(inst.Name)
	if !ok || !cur.EnrolledAt.Equal(inst.EnrolledAt) || cur.ClientCertPath != inst.ClientCertPath {
		logger.Printf("CDR: RenewCert %q: instance removed or re-enrolled before the renewal ran; skipping", sanitizeLog(inst.Name))
		return
	}
	inst = cur

	opID := mintCDROperationID()
	seq, err := cdrInstances.StageRenewal(inst.Name, opID)
	if err != nil {
		logger.Printf("CDR: RenewCert %q: stage renewal intent: %v", sanitizeLog(inst.Name), err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := pc.Client.RenewCert(ctx, &pb.RenewCertRequest{OperationId: opID})
	if err != nil {
		// Outcome unknown: the "renewing" generation stays durable and the
		// poller resolves it through EnrollStatus (issued ⇒ orphaned and
		// revocable; not issued ⇒ dropped). Never silently forgotten.
		logger.Printf("CDR: RenewCert failed for %q (operation %s left for reconciliation): %v",
			sanitizeLog(inst.Name), opID, err)
		return
	}
	if len(resp.ClientCert) == 0 || len(resp.ClientKey) == 0 {
		logger.Printf("CDR: RenewCert for %q returned empty material (operation %s left for reconciliation)", sanitizeLog(inst.Name), opID)
		return
	}
	fp, ferr := sluiceauth.Fingerprint(resp.ClientCert)
	if ferr != nil {
		logger.Printf("CDR: RenewCert %q: fingerprint renewed cert: %v (operation %s left for reconciliation)", sanitizeLog(inst.Name), ferr, opID)
		return
	}
	if resp.ClientCertFingerprint != "" && resp.ClientCertFingerprint != fp {
		logger.Printf("CDR: RenewCert %q: server-reported fingerprint %s differs from the issued cert %s; using the cert",
			sanitizeLog(inst.Name), sanitizeLog(resp.ClientCertFingerprint), fp)
	}

	// The issued credential is durable BEFORE any PEM is written: a
	// failure here means the bundle is discarded and the generation stays
	// "renewing" for reconciliation (EnrollStatus names the fingerprint).
	if serr := cdrInstances.RecordIssuedCredential(inst.Name, seq, fp, certNotAfterUnix(resp.ClientCert), cdrCredStaged); serr != nil {
		logger.Printf("CDR: RenewCert %q: record issued credential %s: %v — bundle discarded, operation %s left for reconciliation",
			sanitizeLog(inst.Name), fp, serr, opID)
		return
	}

	if !installRenewedPEMs(inst, resp.ClientCert, resp.ClientKey) {
		return
	}
	if aerr := cdrInstances.ActivateCredential(inst.Name, seq); aerr != nil {
		// Disk holds the new credential and the durable lineage already
		// names it (staged); the next boot's reconcile activates it.
		logger.Printf("CDR: RenewCert %q: activate seq %d: %v (durable lineage names %s as staged; reconciled at next boot)",
			sanitizeLog(inst.Name), seq, aerr, fp)
		return
	}
	logger.Printf("CDR: RenewCert %q succeeded — seq=%d fingerprint=%s days_until_expiry=%d",
		sanitizeLog(inst.Name), seq, fp, resp.DaysUntilExpiry)

	// Re-init the client so the next RPC uses the new cert.  The old
	// *CDRClient (and its grpc.ClientConn) gets closed inside
	// initCDRClient's pool.replace() path.  Failure here is non-fatal:
	// the old cert keeps working until its NotAfter, so traffic
	// continues — next poll retries the reinit.
	if err := initCDRClient(cdrActiveConfig()); err != nil {
		logger.Printf("CDR: RenewCert %q: reinit failed (old cert still valid): %q",
			sanitizeLog(inst.Name), sanitizeLog(err.Error()))
	}
}

// installRenewedPEMs writes the new bundle atomically via tmp + rename
// (cert first, then key), so a crash mid-swap leaves either the old or
// the new material intact — never a half-written file — and the staged
// lineage entry lets reconcileCredentialLineage finish the swap.
func installRenewedPEMs(inst CDREnrolledInstance, certPEM, keyPEM []byte) bool {
	if werr := os.WriteFile(inst.ClientCertPath+".tmp", certPEM, 0o600); werr != nil {
		logger.Printf("CDR: RenewCert %q: write cert tmp: %v", sanitizeLog(inst.Name), werr)
		return false
	}
	// CA-3: encrypt the client key at rest when enabled; plaintext otherwise.
	// The cert above stays a plaintext public cert.
	keyOut, kerr := encodeCDRClientKeyForWrite(inst.ClientKeyPath, keyPEM)
	if kerr != nil {
		_ = os.Remove(inst.ClientCertPath + ".tmp")
		logger.Printf("CDR: RenewCert %q: encrypt key: %v", sanitizeLog(inst.Name), kerr)
		return false
	}
	if werr := os.WriteFile(inst.ClientKeyPath+".tmp", keyOut, 0o600); werr != nil {
		_ = os.Remove(inst.ClientCertPath + ".tmp")
		logger.Printf("CDR: RenewCert %q: write key tmp: %v", sanitizeLog(inst.Name), werr)
		return false
	}
	if werr := os.Rename(inst.ClientCertPath+".tmp", inst.ClientCertPath); werr != nil {
		logger.Printf("CDR: RenewCert %q: swap cert: %v", sanitizeLog(inst.Name), werr)
		return false
	}
	if werr := os.Rename(inst.ClientKeyPath+".tmp", inst.ClientKeyPath); werr != nil {
		logger.Printf("CDR: RenewCert %q: swap key: %v", sanitizeLog(inst.Name), werr)
		return false
	}
	return true
}

// reconcilePendingRenewals resolves every "renewing" generation whose RPC
// outcome was lost, by asking Sluice (EnrollStatus is authoritative and
// idempotent): issued ⇒ recorded as ORPHANED with its fingerprint (key
// material never arrived; it must be revoked), not issued ⇒ dropped.
// Runs before maybeRenewExpiringClients so an unresolved renewal never
// blocks the next one indefinitely.
func reconcilePendingRenewals(members []*cdrPooledClient) {
	for _, pc := range members {
		inst, ok := cdrInstances.GetCopy(pc.Name)
		if !ok {
			continue
		}
		for _, g := range inst.Credentials {
			if g.State != cdrCredRenewing || g.OperationID == "" {
				continue
			}
			if !pc.renewInFlight.CompareAndSwap(0, 1) {
				break // a renewal is running for this member; it owns the lock
			}
			resolveRenewingGeneration(pc, inst, g)
			pc.renewInFlight.Store(0)
		}
	}
}

func resolveRenewingGeneration(pc *cdrPooledClient, inst CDREnrolledInstance, g CDRCredentialGeneration) {
	unlock := cdrLifecycle.lock(inst.Name)
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), cdrHealthProbeDeadline)
	defer cancel()
	st, err := pc.Client.EnrollStatus(ctx, g.OperationID)
	if err != nil {
		logger.Printf("CDR: lineage: %q EnrollStatus(%s) unavailable (retry next poll): %v", sanitizeLog(inst.Name), g.OperationID, err)
		return
	}
	switch st.GetOutcome() {
	case pb.EnrollOutcome_ENROLL_NOT_ISSUED:
		if err := cdrInstances.DropUnissuedRenewal(inst.Name, g.Seq); err != nil {
			logger.Printf("CDR: lineage: %q drop unissued seq %d: %v", sanitizeLog(inst.Name), g.Seq, err)
		}
	case pb.EnrollOutcome_ENROLL_ISSUED:
		fp := st.GetClientCertFingerprint()
		state := cdrCredOrphaned
		if st.GetRevoked() {
			state = cdrCredRevoked
		}
		if err := cdrInstances.RecordIssuedCredential(inst.Name, g.Seq, fp, 0, state); err != nil {
			logger.Printf("CDR: lineage: %q record orphan %s: %v", sanitizeLog(inst.Name), fp, err)
			return
		}
		if state == cdrCredOrphaned {
			logger.Printf("CDR: lineage: %q renewal operation %s was ISSUED as %s but the credential never landed locally — marked orphaned; revoke it",
				sanitizeLog(inst.Name), g.OperationID, fp)
			auditAdd(AuditEntry{
				TS: time.Now().UnixMilli(), Time: time.Now().Format("2006-01-02 15:04:05"),
				Actor: "system:cdr-lineage", Action: "cdr.instance.credential.orphaned", Object: inst.Name,
				Detail: "renewal operation " + g.OperationID + " issued fingerprint " + fp + " but the credential was not stored locally; it remains trusted by Sluice until revoked",
			})
		}
	default:
		// A v0.2 server has no EnrollStatus; leave the generation as-is.
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
// Not persisted — purely for the admin GUI. 2E-C: writes go through the
// locked SetHealthMeta — the earlier unlocked pointer write raced the
// GET /api/cdr/instances render (pinned by
// TestCDR2EC_InstanceListDoesNotRaceHealthPoller).
func updateRegistryMetadataFromPool(members []*cdrPooledClient) {
	for _, pc := range members {
		h, _ := pc.HealthSnapshot()
		if h == nil {
			continue
		}
		cdrInstances.SetHealthMeta(pc.Name, h.Version, time.Now().UTC())
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
