package main

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	cpdpapply "github.com/KidCarmi/Culvert/internal/mcp/cpdp/apply"
)

// initMCPDistribution is the PR-12 startup shim (disabled-by-default) that composes
// the MCP CP→DP signed-distribution DATA-PLANE appliers in PRODUCTION — the missing
// production caller that previously left applySnapshotMCP unable to reach the rollout
// commit path (B-MECH-1 / Codex P1-A).
//
// It runs AFTER initMCPRollout so the node-local rollout state is already restored
// before an applier can drive a rollout commit, and it reconciles the two durable
// stores at the end (crash-window convergence, §8). It is fail-closed and
// disabled-safe:
//
//   - No trust provisioned (the default) ⇒ NO applier is composed, the DP apply path
//     stays a no-op, and a received ConfigSnapshot is byte-identical to the pre-PR-10
//     SWG snapshot. The composition reason is recorded read-only for the admin surface.
//   - A present-but-invalid trust value ⇒ fail closed to disabled (never an applier
//     that trusts nothing or the wrong key).
//   - A per-capability Recover failure ⇒ fail closed: NO applier is registered for
//     EITHER capability, so a corrupt durable state can never leave a half-composed DP.
//
// Gateway and Management appliers are physically isolated (separate trust-verified
// engines + separate durable files); a failure composing one never affects the other
// beyond the shared fail-closed decision. Registration is idempotent — a second call
// is a no-op — so startup can never register two conflicting appliers.
func initMCPDistribution(_ *startupState) {
	d := globalMCPDistribution
	if d.enabled.Load() {
		return // already composed (idempotent guard against double registration)
	}
	cfg := resolveMCPDistributionStartupConfig(
		os.Getenv(envMCPDistributionTrustKeys),
		resolveMCPDPNodeID(),
		filepath.Join(dataDir, "mcp_distribution"),
	)
	if !cfg.Enabled {
		d.mu.Lock()
		d.composeReason = cfg.Reason
		d.mu.Unlock()
		if cfg.Reason != "not_configured" {
			logger.Printf("MCP distribution DP compose skipped (fail-closed): %q", sanitizeLog(cfg.Reason))
		}
		return
	}

	// Ensure the per-capability durable-state directory exists before composing (the
	// atomic file store writes a temp file alongside its target).
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		logger.Printf("MCP distribution DP compose failed: cannot create state dir (fail-closed): %q", sanitizeLog(err.Error()))
		d.mu.Lock()
		d.composeReason = "state_dir_unavailable"
		d.mu.Unlock()
		return
	}

	// Compose both capability appliers off to the side first; only publish them once
	// BOTH constructed and recovered, so a snapshot can never observe a half-composed DP.
	clock := func() int64 { return time.Now().UnixNano() }
	idGen := func() string { return ulid.MustNew(ulid.Now(), rand.Reader).String() }
	built := map[cpdp.Capability]*cpdpapply.Applier{}
	for _, capb := range []cpdp.Capability{cpdp.CapabilityGateway, cpdp.CapabilityManagement} {
		ap, err := cpdpapply.New(cpdpapply.Config{
			Capability: capb,
			Trust:      cfg.Trust,
			DPVersion:  cpdp.DPCompatVersion,
			Limits:     cpdp.DefaultLimits(),
			NodeID:     cfg.NodeID,
			Store:      cpdpapply.NewFileStore(cfg.DataDir, capb),
			Clock:      clock,
			IDGen:      idGen,
		})
		if err != nil {
			logger.Printf("MCP distribution DP compose failed for %s (fail-closed, none registered): %q", capb.String(), sanitizeLog(err.Error()))
			d.mu.Lock()
			d.composeReason = "invalid_applier"
			d.mu.Unlock()
			return
		}
		if rerr := ap.Recover(); rerr != nil {
			// Fail closed: a corrupt/unverifiable durable state must never leave a
			// half-composed DP or a permissive empty active snapshot.
			logger.Printf("MCP distribution DP recover failed for %s (fail-closed, none registered): %q", capb.String(), sanitizeLog(rerr.Error()))
			d.mu.Lock()
			d.composeReason = "recover_failed"
			d.mu.Unlock()
			return
		}
		built[capb] = ap
	}

	// §8 crash-window convergence: reconcile the node-local rollout state with the
	// recovered distribution active envelopes so a crash between distribution
	// activation and rollout commit converges to a single truthful state on restart.
	//
	// This MUST run BEFORE the appliers are published to the global seam. The DP
	// config-sync poller is already running by the time this shim executes (it is
	// started from initCluster, ~16 startup steps earlier, and polls immediately),
	// so publishing first would open a window in which a freshly-pulled, validly
	// signed ConfigSnapshot is applied concurrently and then has its rollout commit
	// OVERWRITTEN by this reconcile replaying the stale recovered envelope — exactly
	// the distribution/rollout split the PR-12 transaction exists to prevent (and, if
	// the newer envelope was a de-escalation, a silent revert to the wider mode).
	// Reconciling off the locally-built appliers closes the window by construction:
	// applySnapshotMCP cannot observe an applier until reconcile has finished.
	reconcileRolloutWithAppliers(built)

	// Publish both appliers atomically, then flip enabled last.
	d.mu.Lock()
	d.dpGateway = built[cpdp.CapabilityGateway]
	d.dpManagement = built[cpdp.CapabilityManagement]
	d.composeReason = "ready"
	d.composeKeyIDs = cfg.TrustKeyIDs
	d.mu.Unlock()
	d.enabled.Store(true)

	logger.Printf("MCP distribution DP appliers composed (node=%q, trust_roots=%d, gateway+management isolated)",
		sanitizeLog(cfg.NodeID), len(cfg.TrustKeyIDs))
}

// resolveMCPDPNodeID resolves a stable, non-secret DP node id for acknowledgements.
// It prefers the already-resolved cluster node id, then the hostname, then a fixed
// fallback — mirroring how cluster_startup seeds clusterRole.nodeID.
func resolveMCPDPNodeID() string {
	if clusterRole.nodeID != "" {
		return clusterRole.nodeID
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "mcp-dp"
}

// reconcileRolloutWithAppliers converges the two durable stores at startup. For each
// capability whose recovered distribution active envelope carries a rollout config, it
// re-commits that rollout idempotently, so a crash BETWEEN distribution activation and
// the coupled rollout commit heals to a consistent state (distribution is the signed
// source of truth for mode/scope; the rollout projection follows it).
//
// It is idempotent by construction: when the rollout state already matches the active
// envelope the commit is a same-mode/same-scope no-op that preserves the window and
// soak timers (never restamps). A commit that fails closed (e.g. an executing mode
// without execution dependencies — which the coordinator's pre-check prevents from
// ever being distribution-persisted in the shipped build) leaves the restored rollout
// state untouched and is logged; it never promotes.
//
// It takes the appliers as a PARAMETER rather than reading them back off the published
// global seam. That is what makes the convergence race-free rather than merely
// unlikely: the composing goroutine can converge while the appliers are still private
// to it, so the config-apply path cannot observe an applier mid-reconcile. Do not
// "simplify" this back into a global read — see the ordering note in
// initMCPDistribution.
func reconcileRolloutWithAppliers(appliers map[cpdp.Capability]*cpdpapply.Applier) {
	now := time.Now()
	for _, capb := range []cpdp.Capability{cpdp.CapabilityGateway, cpdp.CapabilityManagement} {
		a := appliers[capb]
		if a == nil {
			continue
		}
		active := a.Active()
		if active == nil {
			continue
		}
		cfg := rolloutFromEnvelope(active)
		if cfg == nil {
			continue
		}
		// Capability isolation, re-checked at the commit point. commitRolloutTransition
		// routes by cfg.Capability, so a recovered envelope whose inner rollout declares
		// the OTHER capability would commit onto that capability's state — crossing the
		// ADR-0024 boundary at startup, with no operator action and no CP round trip.
		// The apply-time coordinator makes this unreachable through the live path, and
		// cpdp validation now rejects such an envelope outright, but Applier.Recover
		// re-verifies only signature/capability/min-version (NOT full payload
		// validation), so this path must not inherit its safety from a check that ran in
		// a different process lifetime. Fail closed and leave the restored state alone.
		if !rolloutCapabilityMatches(cfg, capb) {
			logger.Printf("MCP rollout reconcile for %s refused: recovered rollout declares a different capability (isolation, fail-closed)", capb.String())
			continue
		}
		if err := getMCPRollout().commitRolloutTransition(cfg, "startup-reconcile", now); err != nil {
			logger.Printf("MCP rollout reconcile for %s left rollout state unchanged: %q", capb.String(), sanitizeLog(err.Error()))
		}
	}
}
