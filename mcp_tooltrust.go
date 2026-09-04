package main

// MCP tool-trust coordinator (ADR-0034). This is the composition-root seam that
// owns the durable ToolApproval store (the SOURCE OF TRUTH for MCP tool trust) and
// materializes its authoritative state as the catalog's Usable projection. It is
// disabled-by-default: with no Gateway qualification inventory loaded, no store is
// composed, no file is written, and the catalog + preflight behave byte-identically
// to the pre-approval slice.
//
// The invariant the whole file exists to keep: a tool is catalog.Usable IFF an
// ACTIVE, unexpired, unrevoked, shadow-purpose ToolApproval binds to the tool's
// CURRENT observed fingerprint AND the server is usable AND the record is not
// ServerDisabled. The store persists the decision; the coordinator derives the
// projection and reconciles the catalog on approve / revoke / expiry / startup /
// read. Trust is NOT authorization — a Usable tool merely survives to the
// default-deny policy step (proved in internal/mcp/policy anti-weakening tests).
//
// Nothing here executes a tool, dials a server, materializes a credential, or arms
// any live-execution tier: a shadow_evaluation approval only ever produces
// catalog.Usable, which satisfies ONLY evaluateShadowActivationPreflight — never
// liveExecDepsConfigured / modeExecReady.

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// mcpToolTrust is the process-wide coordinator singleton.
var mcpToolTrust = &mcpToolTrustCoordinator{}

// mcpToolTrustReconcile is the read-path reconcile hook. It is installed by
// initMCPToolTrust when the coordinator is composed and defaults to a no-op, so a
// caller (the Shadow preflight's usable-tool scan, the admin inventory read) can
// always call it to make the catalog Usable projection reflect current trust
// (expiring + demoting due grants) WITHOUT importing the coordinator or changing
// its own filtering. It never widens usability — it only ever withdraws expired
// trust and re-affirms matching active trust.
var mcpToolTrustReconcile = func() {}

// mcpToolTrustCoordinator owns the durable store and the catalog derivation.
type mcpToolTrustCoordinator struct {
	mu       sync.RWMutex
	store    *tooltrust.Store
	composed bool
	reason   string // bounded, secret-free classification when not composed
	// nowFn is the injected clock the derivation reads (default time.Now). It drives
	// expiry in reconcile + annotateTool so a test can advance it deterministically;
	// production leaves it as time.Now.
	nowFn func() time.Time
	// deriveMu serializes every path that reads the durable grants and then mutates the
	// catalog projection (reconcile, ApproveShadow's promote, Revoke's demote). Without
	// it a reconcile that snapshotted ActiveApprovals just before a concurrent revoke
	// could promote a just-revoked tool after the revoke demoted it (a TOCTOU that left
	// the tool Usable until the next reconcile). It is an OUTER lock: taken before any
	// store/catalog lock, never from under one.
	deriveMu sync.Mutex
	// pendingDemotions holds tools whose catalog Demote FAILED (Catalog.Demote returns
	// ReasonStaleSnapshot when its bounded CAS loses to a concurrent ingest). A failed
	// demote leaves the tool Usable, and if its last approval record is later pruned at the
	// store cap, ToolRefs can no longer rediscover it — so the demotion would be lost and
	// withdrawn trust would stay effective. Every reconcile re-derives ToolRefs UNION this
	// set, so a failed demotion is retried until it succeeds even after the record is gone.
	// Accessed only under deriveMu (every rederive path holds it).
	pendingDemotions map[activeToolKey]struct{}
}

// now returns the coordinator clock (time.Now when unset). It reads nowFn under the
// lock because the background reconcile loop may call it concurrently with a test
// swapping the coordinator (production sets nowFn once at init and never mutates it).
func (c *mcpToolTrustCoordinator) now() time.Time {
	c.mu.RLock()
	fn := c.nowFn
	c.mu.RUnlock()
	if fn != nil {
		return fn()
	}
	return time.Now()
}

// runCatalogIngestSerialized runs a discovery catalog ingest (its snapshot PUBLISH) under
// deriveMu, so the catalog revision advance it performs is MUTUALLY EXCLUSIVE with an
// approve/request/revoke/reconcile critical section. It is the execution.SetIngestGuard seam:
// without it, a rediscovery could advance the live revision after ApproveShadow's loadTarget
// captured the pre-advance copy but before store.Approve validated it, so an identical
// rediscovery (or an F1→F2→F1 flap) in that window would pass the optimistic-concurrency check
// against a stale revision and be approved instead of returning the required stale-target
// conflict. deriveMu is the OUTER lock (taken before any store/catalog lock, never from under
// one), and discovery is never invoked from within a deriveMu section, so wrapping the ingest
// here cannot deadlock. The post-ingest reconcile (OnIngest) still takes deriveMu separately
// after this returns.
func (c *mcpToolTrustCoordinator) runCatalogIngestSerialized(ingest func() error) error {
	c.deriveMu.Lock()
	defer c.deriveMu.Unlock()
	return ingest()
}

// initMCPToolTrust composes the tool-trust store and runs the startup reconcile. It
// runs AFTER initMCPRuntime (which publishes the qualification inventory) so the
// derivation has a live catalog to project onto. Fail-closed at every gate: if the
// inventory is not loaded, or the durable store cannot be constructed/loaded, no
// store is composed and NO tool is ever promoted (the catalog stays at its seeded
// Quarantined dispositions).
func initMCPToolTrust(_ *startupState) {
	reg, cat := mcpInventory.sharedInventory()
	if reg == nil || cat == nil {
		mcpToolTrust.setUncomposed("inventory_not_loaded")
		return
	}
	store, err := tooltrust.NewStore(tooltrust.Config{
		Path: filepath.Join(dataDir, "mcp_tooltrust", "approvals.json"),
	})
	if err != nil {
		mcpToolTrust.setUncomposed("store_unavailable")
		logger.Printf("MCP tool-trust compose skipped (fail-closed): %q", sanitizeLog(err.Error()))
		return
	}
	if err := store.Load(); err != nil {
		// A corrupt/newer durable store fails closed: no trust is materialized. We do
		// NOT quarantine or delete the file — an operator recovers it out of band.
		mcpToolTrust.setUncomposed("store_load_failed")
		logger.Printf("MCP tool-trust load failed (fail-closed, no trust materialized): %q", sanitizeLog(err.Error()))
		return
	}
	mcpToolTrust.mu.Lock()
	mcpToolTrust.store = store
	mcpToolTrust.composed = true
	mcpToolTrust.reason = ""
	mcpToolTrust.mu.Unlock()
	mcpToolTrustReconcile = mcpToolTrust.reconcile
	// Wire the discovery ingest path (ADR-0034): a Discovery built by execution.NewDiscovery
	// reconciles trust immediately after a successful ingest, so a re-discovered tool matching
	// an active approval is re-promoted at once (not after the periodic sweep). The closure
	// reads the CURRENT mcpToolTrustReconcile, so a later reset makes it a no-op.
	setMCPDiscoveryReconcileHook(func() { mcpToolTrustReconcile() })
	// Serialize the discovery ingest PUBLISH with the approve/revoke/reconcile critical
	// section (ADR-0034 optimistic concurrency): a rediscovery cannot advance the catalog
	// revision underneath an in-flight approval's loadTarget→store.Approve window, so an
	// identical rediscovery / revision flap in that window is caught as a stale-target
	// conflict rather than silently approved. Bound to the coordinator, not the swappable
	// reconcile var, because it is a pure critical-section wrapper.
	setMCPDiscoveryIngestGuard(mcpToolTrust.runCatalogIngestSerialized)
	// Startup reconcile is load-bearing (ADR-0034 D3): the boot inventory re-seeds
	// every tool Quarantined; this re-applies each active approval whose bound
	// fingerprint matches the freshly-seeded tool. Without it every restart silently
	// revokes trust.
	mcpToolTrust.reconcile()
	// A periodic sweep bounds the expired-trust window. reconcile is otherwise driven
	// only by inventory reads + the Shadow preflight; during an ACTIVE Shadow experiment
	// no such read happens, so an approval that reaches its ExpiresAt mid-run would keep
	// its tool catalog.Usable indefinitely (the runtime policy path reads eligibility
	// directly). The loop expires + demotes on a timer so stale trust cannot outlive its
	// TTL by more than the tick. Bound to the process lifecycle (stops on shutdown).
	startToolTrustReconcileLoop(resolveLifecycleCtx())
}

// mcpToolTrustLoop tracks the most recently started reconcile loop so a test
// can observe (toolTrustReconcileLoopRunning) whether it has exited.
var mcpToolTrustLoop struct {
	mu   sync.Mutex
	done chan struct{} // closed when the loop goroutine returns
}

// toolTrustReconcileLoopRunning reports whether the most recently started
// reconcile loop is still running (false when none was started).
func toolTrustReconcileLoopRunning() bool {
	mcpToolTrustLoop.mu.Lock()
	done := mcpToolTrustLoop.done
	mcpToolTrustLoop.mu.Unlock()
	if done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

// mcpToolTrustReconcileInterval bounds how long an expired grant can keep a tool
// Usable during an active Shadow experiment (no inventory read is guaranteed then).
// A package var so a test can shorten it.
var mcpToolTrustReconcileInterval = 30 * time.Second

// startToolTrustReconcileLoop runs a periodic reconcile bound to ctx. It reports
// whether it started (false when the coordinator is not composed), so the
// disabled-by-default posture is directly assertable. The reconcile is panic-guarded.
func startToolTrustReconcileLoop(ctx context.Context) bool {
	if composed, _ := mcpToolTrust.composedStatus(); !composed {
		return false
	}
	interval := mcpToolTrustReconcileInterval // read in the caller goroutine (ordered with tests)
	done := make(chan struct{})
	mcpToolTrustLoop.mu.Lock()
	mcpToolTrustLoop.done = done
	mcpToolTrustLoop.mu.Unlock()
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				runGuarded("mcp_tooltrust_reconcile", mcpToolTrust.reconcile)
			}
		}
	}()
	return true
}

func (c *mcpToolTrustCoordinator) setUncomposed(reason string) {
	c.mu.Lock()
	c.store = nil
	c.composed = false
	c.reason = reason
	c.mu.Unlock()
}

// getStore returns the composed store or a fail-closed error. A nil store means the
// trust subsystem is not composed (no MCP inventory / load failure), so every trust
// mutation and read is refused rather than silently succeeding.
func (c *mcpToolTrustCoordinator) getStore() (*tooltrust.Store, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.composed || c.store == nil {
		return nil, mcperr.New(mcperr.ReasonAdminNotFound, "tooltrust.coordinator", "tool trust not configured")
	}
	return c.store, nil
}

// composedStatus reports whether the coordinator is composed and its bounded reason
// (for the admin status surface).
func (c *mcpToolTrustCoordinator) composedStatus() (composed bool, reason string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.composed, c.reason
}

// reconcile makes the catalog Usable projection consistent with the durable store as
// of now: it first EXPIRES due grants and demotes their tools (withdraw stale
// trust), then PROMOTES every active grant whose bound fingerprint exactly matches
// the tool's current observed fingerprint (re-affirm matching trust). It is
// idempotent, fail-safe (a per-tool CAS/stale failure is skipped, never fails open),
// and cheap (O(active approvals)). Because it only ever demotes-expired and
// promotes-exact-match, calling it from a read path can never widen usability.
func (c *mcpToolTrustCoordinator) reconcile() {
	c.deriveMu.Lock()
	defer c.deriveMu.Unlock()
	store, err := c.getStore()
	if err != nil {
		return
	}
	reg, cat := mcpInventory.sharedInventory()
	if reg == nil || cat == nil {
		return
	}
	now := c.now()
	// Best-effort durable transition of due grants to Expired (for the admin view). The
	// CATALOG demotion below deliberately does NOT depend on this succeeding: if the
	// store is unwritable, ExpireDue reverts the in-memory status to Active but the grant
	// is still past its expiry, so activeAsOf (and thus ActiveApprovals) already excludes
	// it — rederiveTool will demote its tool regardless.
	_, _ = store.ExpireDue(now)
	// Re-derive EVERY tool referenced by any approval: promote when an active, matching,
	// unexpired grant covers the current fingerprint; demote otherwise. This is what
	// makes expiry effective even when persisting the Expired status failed, and it is
	// the single place trust is materialized — never a blind promote-only pass that could
	// leave a no-longer-covered tool Usable. The active set is snapshotted+indexed ONCE
	// here and reused for every tool (O(refs + approvals), not O(refs × approvals)).
	activeByTool := indexActiveByTool(store.ActiveApprovals(now))
	// Work set is ToolRefs UNION pendingDemotions: a tool whose Demote failed on an earlier
	// pass (and whose record may since have been pruned) is NOT in ToolRefs any more, but it
	// may still be Usable, so it must keep being re-derived until the demotion lands.
	work := make(map[activeToolKey]struct{}, len(activeByTool))
	for _, ref := range store.ToolRefs() {
		work[activeToolKey{serverID: ref.ServerID, toolName: ref.ToolName}] = struct{}{}
	}
	for k := range c.pendingDemotions {
		work[k] = struct{}{}
	}
	for k := range work {
		c.rederiveToolWith(reg, cat, k.serverID, k.toolName, activeByTool)
	}
}

// toolTrustTargetInput carries the current facts a request/approve is verified
// against, resolved from the LIVE registry + catalog (never from the caller).
type toolTrustTargetInput struct {
	target      tooltrust.CurrentTarget
	fingerprint catalog.Fingerprint // the live record fingerprint (for the catalog CAS)
	key         catalog.ToolKey
	found       bool
}

// loadTarget resolves the authoritative current facts for a (server, tool) from the
// shared inventory. found is false when the tool is not in the catalog.
func (c *mcpToolTrustCoordinator) loadTarget(serverID, toolName string) toolTrustTargetInput {
	reg, cat := mcpInventory.sharedInventory()
	if reg == nil || cat == nil {
		return toolTrustTargetInput{}
	}
	key := catalog.ToolKey{Server: registry.ServerID(serverID), Name: toolName}
	rec, ok := cat.Current().Get(key)
	srv, sok := reg.Current().Get(registry.ServerID(serverID))
	t := tooltrust.CurrentTarget{
		ServerExists: sok,
		ServerUsable: sok && srv.Usable(),
		ToolExists:   ok,
	}
	if sok {
		t.Tenant = string(srv.OwnerScope)
		t.ServerRevision = srv.Revision
	}
	if ok {
		t.Approvable = rec.Eligibility != catalog.ServerDisabled
		sum := rec.Fingerprint.Sum()
		t.Fingerprint = tooltrust.FingerprintDigest(sum)
		t.FingerprintFormatVersion = rec.Fingerprint.FormatVersion
		// The optimistic-concurrency token is the tool's PER-RECORD revision — the value the
		// admin inventory endpoint exposes as ToolView.Revision — NOT the global catalog
		// snapshot revision. Using the global revision made an unrelated tool/server update
		// advance the token and produce a spurious 409 stale-target even when the reviewed
		// tool was unchanged; the per-record revision advances iff THIS tool changed.
		t.CatalogRevision = rec.Revision
	}
	return toolTrustTargetInput{target: t, fingerprint: rec.Fingerprint, key: key, found: ok && sok}
}

// toolTrustRequestInput is the coordinator-level request (already RBAC-checked by the
// handler). It carries the client's EXPECTED fingerprint hex + expected catalog
// revision (the review-time optimistic-concurrency evidence) — never arbitrary
// server facts.
type toolTrustRequestInput struct {
	Tenant              string
	ServerID            string
	ToolName            string
	ExpectedFingerprint string // hex of the 32-byte digest the reviewer saw
	ExpectedCatalogRev  uint64
	Purpose             tooltrust.Purpose
	RequestedBy         string
	Reason              string
	TicketRef           string
	ExpiresAt           *time.Time
}

// RequestApproval records a pending trust request after resolving and validating the
// current facts. The client's expected fingerprint MUST equal the tool's current
// observed fingerprint (else the reviewer's view is stale — rejected fail-closed);
// the request then binds that exact digest. The tenant is taken from the SERVER's
// ownership scope, never from the caller.
func (c *mcpToolTrustCoordinator) RequestApproval(in toolTrustRequestInput) (*tooltrust.ToolApproval, error) {
	store, err := c.getStore()
	if err != nil {
		return nil, err
	}
	// Serialize the WHOLE resolve→validate→create against ingest/reconcile/approve/revoke.
	// deriveMu is the OUTER lock, and taking it BEFORE loadTarget is load-bearing: catalog
	// ingestion advances the revision/fingerprint only under deriveMu (runCatalogIngestSerialized),
	// so without holding it here a rediscovery could advance the target between loadTarget and
	// CreateRequest and the STALE copied target would be persisted as an immediately-unapprovable
	// pending record (the exact-target optimistic-concurrency contract must fail closed, not admit
	// a dead record that consumes store capacity). It ALSO serializes the at-capacity PRUNE that
	// CreateRequest may run: a prune that interleaves between reconcile's ExpireDue (which makes a
	// grant terminal) and its ToolRefs re-derivation would delete that grant's last ToolRef before
	// the tool is demoted, stranding a still-Usable projection with no record left to discover.
	// Taken before the store lock, never from under it, matching the approve/revoke paths.
	c.deriveMu.Lock()
	defer c.deriveMu.Unlock()
	ti := c.loadTarget(in.ServerID, in.ToolName)
	if !ti.found {
		return nil, mcperr.New(mcperr.ReasonToolNotFound, "tooltrust.request", "target tool not found")
	}
	if !ti.target.ServerUsable {
		return nil, mcperr.New(mcperr.ReasonServerNotUsable, "tooltrust.request", "server not usable")
	}
	if ti.target.Tenant != in.Tenant {
		// The caller selected a tenant that does not own this server: uniform not-found
		// so a caller cannot probe another tenant's servers.
		return nil, mcperr.New(mcperr.ReasonToolNotFound, "tooltrust.request", "target tool not found")
	}
	if !ti.target.Approvable {
		return nil, mcperr.New(mcperr.ReasonToolNotApprovable, "tooltrust.request", "tool not in an approvable state")
	}
	expected, err := parseFingerprintHex(in.ExpectedFingerprint)
	if err != nil {
		return nil, err
	}
	if expected != ti.target.Fingerprint {
		return nil, mcperr.New(mcperr.ReasonToolFingerprintMismatch, "tooltrust.request", "expected fingerprint does not match the current tool")
	}
	// The reviewed catalog revision is a REQUIRED part of the exact-target contract, not an
	// optional hint. Treating a zero/omitted value as "not asserted" let a caller skip the
	// freshness check entirely: an identical rediscovery (same fingerprint, bumped revision)
	// between review and request would then bind the NEW current revision, and approval could no
	// longer detect that the operator never reviewed that revision. Require the caller to assert
	// the per-record revision they reviewed (ToolView.Revision), and reject an omission or a
	// mismatch fail-closed — the fingerprint is the capability half, the revision the
	// optimistic-concurrency half.
	if in.ExpectedCatalogRev == 0 {
		return nil, mcperr.New(mcperr.ReasonToolApprovalStale, "tooltrust.request", "reviewed catalog revision is required (exact-target contract)")
	}
	if in.ExpectedCatalogRev != ti.target.CatalogRevision {
		return nil, mcperr.New(mcperr.ReasonToolApprovalStale, "tooltrust.request", "catalog revision advanced since review")
	}
	return store.CreateRequest(tooltrust.RequestInput{
		Tenant:                   in.Tenant,
		ServerID:                 in.ServerID,
		ToolName:                 in.ToolName,
		Fingerprint:              ti.target.Fingerprint,
		FingerprintFormatVersion: ti.target.FingerprintFormatVersion,
		Purpose:                  in.Purpose,
		CatalogRevision:          ti.target.CatalogRevision,
		ServerRevision:           ti.target.ServerRevision,
		RequestedBy:              in.RequestedBy,
		Reason:                   in.Reason,
		TicketRef:                in.TicketRef,
		ExpiresAt:                in.ExpiresAt,
	})
}

// RequestLiveApproval records a pending LIVE-execution trust request. It is the explicit,
// dedicated live issue path (§3): it forces Purpose = live_execution so a live request can never
// be confused for a shadow one, then reuses the same authoritative resolve→validate→create as
// RequestApproval (exact current fingerprint + reviewed catalog revision). The store additionally
// requires a live request to carry an explicit finite expiry within the short-TTL ceiling (§6);
// four-eyes is enforced later, at ApproveLive. Issuing a request is NEVER a grant and arms nothing.
func (c *mcpToolTrustCoordinator) RequestLiveApproval(in toolTrustRequestInput) (*tooltrust.ToolApproval, error) {
	in.Purpose = tooltrust.PurposeLiveExecution
	return c.RequestApproval(in)
}

// ApproveLive approves a pending LIVE-execution request under the stronger live governance, WITHOUT
// touching the catalog (§14/§15). Unlike ApproveShadow it never promotes the tool to catalog.Usable:
// live trust is ORTHOGONAL to Shadow usability — a live grant is consumed only by the Canary
// activation preflight, never by evaluateShadowActivationPreflight. It re-loads the CURRENT target
// under deriveMu (so a concurrent ingest cannot advance the revision between the load and the store
// decision — the same optimistic-concurrency window ApproveShadow closes) and delegates to
// store.Approve, which enforces exact-current-state (verifyTarget + revisionStale), FOUR-EYES
// (approver distinct from the requester — both canonical authenticated principals supplied by the
// admin surface), a mandatory expiry, and the ≤MaxLiveExecutionApprovalTTL ceiling measured from
// the approval instant. Approving a live grant arms NOTHING: no executor, no live tier, no Canary
// transition (§22). It refuses a non-live approval fail-closed so the shadow path is never reached
// through it.
func (c *mcpToolTrustCoordinator) ApproveLive(id, approver, tenant string) (*tooltrust.ToolApproval, error) {
	store, err := c.getStore()
	if err != nil {
		return nil, err
	}
	existing, err := store.Get(id, tenant)
	if err != nil {
		return nil, err
	}
	if existing.Purpose != tooltrust.PurposeLiveExecution {
		// Route mismatch: a shadow approval must be decided via ApproveShadow. Fail closed rather
		// than silently approving a shadow grant without promotion (or a live grant with it).
		return nil, mcperr.New(mcperr.ReasonApprovalPurposeUnsupported, "tooltrust.approve", "not a live_execution approval")
	}
	// Serialize the load→approve against ingest/reconcile/approve/revoke exactly as ApproveShadow
	// does, so the exact-target optimistic-concurrency check runs against a revision that cannot be
	// advanced underneath it. Taken before the store lock, never from under it.
	c.deriveMu.Lock()
	defer c.deriveMu.Unlock()
	ti := c.loadTarget(existing.ServerID, existing.ToolName)
	granted, err := store.Approve(id, approver, ti.target)
	if err != nil {
		return nil, err
	}
	// Deliberately NO promoteFor / catalog mutation: live trust never materializes catalog.Usable.
	return granted, nil
}

// activeLiveApprovals returns copies of every active, unexpired live-execution grant across all
// tenants for the Canary activation preflight to bind per scoped tool. It is a trusted in-process
// read (never a tenant-scoped request path); an uncomposed coordinator yields nil (fail-closed:
// no live approvals, so the live_execution_approval_invalid row stays unmet).
func (c *mcpToolTrustCoordinator) activeLiveApprovals(now time.Time) []*tooltrust.ToolApproval {
	store, err := c.getStore()
	if err != nil {
		return nil
	}
	return store.ActiveLiveApprovals(now)
}

// ApproveShadow approves a pending request (shadow purpose) after re-verifying the
// bound target against freshly-loaded CURRENT facts, then materializes the trust by
// promoting the tool to catalog.Usable. Commit order is durable-first (ADR-0034
// D6/D13): the store persists the active grant BEFORE the catalog CAS, so a crash
// between the two is repaired by the next startup/read reconcile. A promote that
// loses the CAS (a concurrent ingest advanced the catalog under the decision) leaves
// the grant durably active but the tool not yet Usable; the next reconcile promotes
// it — no false trust, and the caller is told it is stale.
func (c *mcpToolTrustCoordinator) ApproveShadow(id, approver, tenant string) (*tooltrust.ToolApproval, error) {
	store, err := c.getStore()
	if err != nil {
		return nil, err
	}
	// The approval must exist within the caller's tenant BEFORE we load facts.
	existing, err := store.Get(id, tenant)
	if err != nil {
		return nil, err
	}
	// Route isolation (§3/§15): ApproveShadow is the SHADOW path — it promotes the tool to
	// catalog.Usable. A live_execution approval must NEVER be approved here (that would both skip the
	// live route's intent and, worse, materialize catalog.Usable from a live grant). Refuse it
	// fail-closed; ApproveLive is its only decision path. Symmetric with ApproveLive's live-only guard.
	if existing.Purpose != tooltrust.PurposeShadowEvaluation {
		return nil, mcperr.New(mcperr.ReasonApprovalPurposeUnsupported, "tooltrust.approve", "not a shadow_evaluation approval")
	}
	// Serialize the approve+promote with reconcile/revoke so the durable transition and
	// the catalog promotion are one critical section (no interleaving demote/promote).
	c.deriveMu.Lock()
	defer c.deriveMu.Unlock()
	ti := c.loadTarget(existing.ServerID, existing.ToolName)
	granted, err := store.Approve(id, approver, ti.target)
	if err != nil {
		return nil, err
	}
	// The grant is durably active, but a short TTL may have ELAPSED during the Approve write:
	// Approve checks expiry before the durable transition, and the clock advances under it.
	// promoteFor only re-verifies the fingerprint, so an already-expired grant would be
	// promoted Usable until the next reconcile tick. Recheck expiry as of now and re-derive
	// (which demotes an expired grant) instead of promoting an elapsed one.
	if granted.ExpiresAt != nil && !c.now().Before(*granted.ExpiresAt) {
		if reg, cat := mcpInventory.sharedInventory(); reg != nil && cat != nil {
			c.rederiveTool(store, reg, cat, granted.ServerID, granted.ToolName, c.now())
		}
		return granted, nil
	}
	// Materialize the trust: promote the exact reviewed fingerprint. Fail-closed and
	// idempotent; a stale CAS is surfaced but the durable grant stands.
	if _, perr := c.promoteFor(granted); perr != nil {
		return granted, perr
	}
	return granted, nil
}

// promoteFor promotes the tool an active grant binds to, using the live record
// fingerprint as the CAS-expected value. It re-reads the live record so the promote
// is verified against the current observation, never a stale copy.
func (c *mcpToolTrustCoordinator) promoteFor(a *tooltrust.ToolApproval) (*catalog.Snapshot, error) {
	_, cat := mcpInventory.sharedInventory()
	if cat == nil {
		return nil, mcperr.New(mcperr.ReasonToolNotFound, "tooltrust.promote", "catalog unavailable")
	}
	key := catalog.ToolKey{Server: registry.ServerID(a.ServerID), Name: a.ToolName}
	rec, ok := cat.Current().Get(key)
	if !ok {
		return nil, mcperr.New(mcperr.ReasonToolNotFound, "tooltrust.promote", "tool not found")
	}
	sum := rec.Fingerprint.Sum()
	if !a.MatchesTool(a.Tenant, a.ServerID, a.ToolName,
		tooltrust.FingerprintDigest(sum), rec.Fingerprint.FormatVersion) {
		return nil, mcperr.New(mcperr.ReasonToolFingerprintMismatch, "tooltrust.promote", "tool drifted since approval")
	}
	return cat.Promote(key, rec.Fingerprint)
}

// Reject decides a pending request as rejected (no catalog effect).
func (c *mcpToolTrustCoordinator) Reject(id, actor, tenant, reason string) error {
	store, err := c.getStore()
	if err != nil {
		return err
	}
	// Tenant scope the reject: resolve within tenant first.
	if _, gerr := store.Get(id, tenant); gerr != nil {
		return gerr
	}
	return store.Reject(id, actor, reason)
}

// Revoke terminates a grant and immediately withdraws its trust from the catalog
// (durable-first: the store persists the revocation, then the catalog is demoted).
func (c *mcpToolTrustCoordinator) Revoke(id, actor, tenant, reason string) (*tooltrust.ToolApproval, error) {
	store, err := c.getStore()
	if err != nil {
		return nil, err
	}
	// Serialize the revoke+demote with reconcile/approve so a concurrent reconcile cannot
	// promote this tool from a pre-revoke ActiveApprovals snapshot after we demote it.
	c.deriveMu.Lock()
	defer c.deriveMu.Unlock()
	revoked, err := store.Revoke(id, actor, tenant, reason)
	if err != nil {
		return nil, err
	}
	// RE-DERIVE the tool rather than blindly demoting: another active approval (or a
	// pending record that was the revoke target) may still leave the tool legitimately
	// covered, and ordinary Shadow evaluation does not reconcile per call, so a wrong
	// demotion would block a still-trusted tool until the next read/preflight.
	reg, cat := mcpInventory.sharedInventory()
	if reg != nil && cat != nil {
		c.rederiveTool(store, reg, cat, revoked.ServerID, revoked.ToolName, c.now())
	}
	return revoked, nil
}

// rederiveTool re-derives ONE tool's catalog eligibility from the durable store: it
// promotes when some active, unexpired, shadow-purpose approval binds the tool's CURRENT
// fingerprint on a usable, correctly-owned server, and demotes otherwise. It is
// fail-closed and idempotent (Promote/Demote CAS), so it only ever reflects durable
// trust — used by revoke and the expiry sweep so withdrawing one grant never drops a
// tool a different grant still covers.
func (c *mcpToolTrustCoordinator) rederiveTool(store *tooltrust.Store, reg *registry.Registry, cat *catalog.Catalog, serverID, toolName string, now time.Time) {
	c.rederiveToolWith(reg, cat, serverID, toolName, indexActiveByTool(store.ActiveApprovals(now)))
}

// activeToolKey groups active approvals by their (server, tool).
type activeToolKey struct{ serverID, toolName string }

// indexActiveByTool groups a single ActiveApprovals snapshot by (server, tool) so a
// reconcile that touches many tools scans/clones/sorts the active set ONCE instead of
// once per tool (O(references + approvals) rather than O(references × approvals)).
func indexActiveByTool(active []*tooltrust.ToolApproval) map[activeToolKey][]*tooltrust.ToolApproval {
	idx := make(map[activeToolKey][]*tooltrust.ToolApproval, len(active))
	for _, a := range active {
		k := activeToolKey{serverID: a.ServerID, toolName: a.ToolName}
		idx[k] = append(idx[k], a)
	}
	return idx
}

// rederiveToolWith re-derives one tool's eligibility against a PRECOMPUTED active-by-tool
// index (so the caller controls how often ActiveApprovals is snapshotted). Promotes when
// some active grant in the index covers the tool's current fingerprint on a usable,
// correctly-owned server; demotes otherwise. Fail-closed and idempotent.
func (c *mcpToolTrustCoordinator) rederiveToolWith(reg *registry.Registry, cat *catalog.Catalog, serverID, toolName string, activeByTool map[activeToolKey][]*tooltrust.ToolApproval) {
	tk := activeToolKey{serverID: serverID, toolName: toolName}
	key := catalog.ToolKey{Server: registry.ServerID(serverID), Name: toolName}
	rec, ok := cat.Current().Get(key)
	if !ok {
		// The tool is absent from the catalog, so it cannot be Usable — nothing is owed.
		c.clearPendingDemotion(tk)
		return
	}
	srv, sok := reg.Current().Get(registry.ServerID(serverID))
	sum := rec.Fingerprint.Sum()
	covered := false
	if sok && srv.Usable() {
		for _, a := range activeByTool[tk] {
			if string(srv.OwnerScope) == a.Tenant &&
				a.MatchesTool(a.Tenant, serverID, toolName, tooltrust.FingerprintDigest(sum), rec.Fingerprint.FormatVersion) {
				covered = true
				break
			}
		}
	}
	if covered {
		_, _ = cat.Promote(key, rec.Fingerprint)
		c.clearPendingDemotion(tk) // legitimately Usable ⇒ no demotion owed
		return
	}
	// Not covered ⇒ the tool must be demoted. If Demote loses its bounded CAS to a concurrent
	// ingest it returns an error and the tool stays Usable; record the debt so the next
	// reconcile retries it even if the approval record is pruned in the meantime.
	if _, err := cat.Demote(key); err != nil {
		c.markPendingDemotion(tk)
	} else {
		c.clearPendingDemotion(tk)
	}
}

// markPendingDemotion / clearPendingDemotion track tools whose catalog demotion is still
// owed. Called only from the rederive paths, all of which hold deriveMu.
func (c *mcpToolTrustCoordinator) markPendingDemotion(k activeToolKey) {
	if c.pendingDemotions == nil {
		c.pendingDemotions = make(map[activeToolKey]struct{})
	}
	c.pendingDemotions[k] = struct{}{}
}

func (c *mcpToolTrustCoordinator) clearPendingDemotion(k activeToolKey) {
	delete(c.pendingDemotions, k)
}

// Get returns a tenant-scoped approval copy.
func (c *mcpToolTrustCoordinator) Get(id, tenant string) (*tooltrust.ToolApproval, error) {
	store, err := c.getStore()
	if err != nil {
		return nil, err
	}
	return store.Get(id, tenant)
}

// List returns a tenant-scoped, bounded approval list.
func (c *mcpToolTrustCoordinator) List(tenant string, limit int) ([]*tooltrust.ToolApproval, error) {
	store, err := c.getStore()
	if err != nil {
		return nil, err
	}
	return store.List(tenant, limit), nil
}

// toolTrustAnnotation is the trust overlay for one inventory tool (ADR-0034 Sec 21):
// the governing approval's status/purpose/id and optional expiry. Empty when no
// approval references the tool.
type toolTrustAnnotation struct {
	Status    string
	Purpose   string
	ID        string
	ExpiresAt *time.Time
}

// toolTrustAnnotator is a per-inventory-response snapshot of a tenant's approvals, grouped
// by (server, tool). It exists so GET /api/mcp/tools annotates every tool from ONE snapshot
// instead of re-listing (and re-allocating) all approvals per tool — an unbounded tool
// inventory would otherwise let a viewer amplify a single request into O(tools × approvals)
// clones + sorts (a memory/CPU DoS). Build it once with newToolTrustAnnotator, then call
// annotate per tool. A nil annotator yields no annotation (trust not composed).
type toolTrustAnnotator struct {
	byTool map[activeToolKey][]*tooltrust.ToolApproval
	now    time.Time
}

// newToolTrustAnnotator snapshots the tenant's approvals ONCE and groups them by (server,
// tool). Returns nil when the coordinator is not composed (callers treat nil as "no
// annotations", identical to the pre-change fail-closed behavior).
func (c *mcpToolTrustCoordinator) newToolTrustAnnotator(tenant string) *toolTrustAnnotator {
	store, err := c.getStore()
	if err != nil {
		return nil
	}
	all := store.AllForTenant(tenant)
	byTool := make(map[activeToolKey][]*tooltrust.ToolApproval, len(all))
	for _, a := range all {
		k := activeToolKey{serverID: a.ServerID, toolName: a.ToolName}
		byTool[k] = append(byTool[k], a)
	}
	return &toolTrustAnnotator{byTool: byTool, now: c.now()}
}

// annotate returns the trust overlay for one tool at the given current fingerprint hex from
// the pre-grouped snapshot. It prefers the ACTIVE approval matching the current fingerprint
// (the one that makes the tool Usable); otherwise the most recent pending request; otherwise
// the most recent record. A nil annotator (trust not composed) yields no annotation.
func (t *toolTrustAnnotator) annotate(serverID, name, fingerprintHex string) (toolTrustAnnotation, bool) {
	if t == nil {
		return toolTrustAnnotation{}, false
	}
	var best *tooltrust.ToolApproval
	var bestRank int
	for _, a := range t.byTool[activeToolKey{serverID: serverID, toolName: name}] {
		r := toolApprovalRank(a, fingerprintHex, t.now)
		if best == nil || r > bestRank || (r == bestRank && a.RequestedAt.After(best.RequestedAt)) {
			best, bestRank = a, r
		}
	}
	if best == nil {
		return toolTrustAnnotation{}, false
	}
	return toolTrustAnnotation{
		Status:    best.Status.String(),
		Purpose:   best.Purpose.String(),
		ID:        best.ApprovalID,
		ExpiresAt: best.ExpiresAt,
	}, true
}

// annotateTool returns the trust overlay for a SINGLE (tenant, server, tool). It builds a
// one-shot annotator, so it is O(tenant approvals) with no large pre-allocation; the list
// path (many tools) must instead build one annotator and reuse it.
func (c *mcpToolTrustCoordinator) annotateTool(tenant, serverID, name, fingerprintHex string) (toolTrustAnnotation, bool) {
	return c.newToolTrustAnnotator(tenant).annotate(serverID, name, fingerprintHex)
}

// toolApprovalRank ranks how strongly an approval governs a tool's current
// eligibility: an active grant matching the current fingerprint (3) outranks a
// pending request (2), which outranks any other record (1). Used only for the
// read-only inventory overlay.
func toolApprovalRank(a *tooltrust.ToolApproval, fingerprintHex string, now time.Time) int {
	if a.Status == tooltrust.StatusActive &&
		fingerprintHex == hex.EncodeToString(a.Fingerprint[:]) &&
		a.Purpose.PermitsShadowEvaluation() &&
		(a.ExpiresAt == nil || now.Before(*a.ExpiresAt)) {
		return 3
	}
	if a.Status == tooltrust.StatusPending {
		return 2
	}
	return 1
}

// parseFingerprintHex decodes a 64-char hex string into a fingerprint digest,
// failing closed on any malformed input.
func parseFingerprintHex(s string) (tooltrust.FingerprintDigest, error) {
	var d tooltrust.FingerprintDigest
	if len(s) != 2*len(d) {
		return d, mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.request", "fingerprint must be 32-byte hex")
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(d) {
		return d, mcperr.New(mcperr.ReasonAdminRequestInvalid, "tooltrust.request", "fingerprint is not valid hex")
	}
	copy(d[:], b)
	return d, nil
}

// resetMCPToolTrustForTest restores the coordinator + reconcile hook to their
// uncomposed defaults so a test can isolate the process-global singleton.
func resetMCPToolTrustForTest() {
	mcpToolTrust.mu.Lock()
	mcpToolTrust.store = nil
	mcpToolTrust.composed = false
	mcpToolTrust.reason = ""
	mcpToolTrust.nowFn = nil
	mcpToolTrust.mu.Unlock()
	mcpToolTrust.deriveMu.Lock()
	mcpToolTrust.pendingDemotions = nil
	mcpToolTrust.deriveMu.Unlock()
	mcpToolTrustReconcile = func() {}
	setMCPDiscoveryReconcileHook(nil)
	setMCPDiscoveryIngestGuard(nil)
}
