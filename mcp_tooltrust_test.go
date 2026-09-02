package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// ── harness ───────────────────────────────────────────────────────────────────────

const ttTenant = "qualification"

// seedToolTrustInventory seeds a one-server/one-tool Gateway inventory, publishes it
// as the shared inventory, and returns the live registry/catalog + the tool's current
// fingerprint hex.
func seedToolTrustInventory(t *testing.T) (reg *registry.Registry, cat *catalog.Catalog, serverID, toolName, fpHex string) {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"controlled","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"t","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err = seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: "controlled", Name: "t"})
	if !ok {
		t.Fatal("seeded tool must exist")
	}
	sum := rec.Fingerprint.Sum()
	return reg, cat, "controlled", "t", hex.EncodeToString(sum[:])
}

// twoToolInv is the seeded two-tool inventory a race test drives (a struct rather than a
// six-value return to stay within the gocritic result-count bound).
type twoToolInv struct {
	cat      *catalog.Catalog
	serverID string
	toolA    string
	toolB    string
	fpA      string
	fpB      string
}

// seedToolTrustInventory2 seeds a one-server, TWO-tool inventory so a test can approve
// one tool and prune its record while creating a request for the other — the exact shape
// of the reconcile-vs-prune race (a pruned record is the LAST ToolRef for its tool).
func seedToolTrustInventory2(t *testing.T) twoToolInv {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"controlled","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"t","input_schema":{"type":"object"}},{"name":"u","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
	recA, ok := cat.Current().Get(catalog.ToolKey{Server: "controlled", Name: "t"})
	if !ok {
		t.Fatal("seeded tool t must exist")
	}
	recB, ok := cat.Current().Get(catalog.ToolKey{Server: "controlled", Name: "u"})
	if !ok {
		t.Fatal("seeded tool u must exist")
	}
	sumA := recA.Fingerprint.Sum()
	sumB := recB.Fingerprint.Sum()
	return twoToolInv{
		cat:      cat,
		serverID: "controlled",
		toolA:    "t",
		toolB:    "u",
		fpA:      hex.EncodeToString(sumA[:]),
		fpB:      hex.EncodeToString(sumB[:]),
	}
}

// swapToolTrustNowFnForTest swaps the coordinator clock UNDER mcpToolTrust.mu and returns the
// previous value so a caller restores it the same way.
//
// It exists because the lock is only half the contract. mcpToolTrust.now() reads nowFn under
// c.mu.RLock PRECISELY because the background reconcile loop can call it while a test swaps
// the clock — and that loop (startToolTrustReconcileLoop) is bound to the process lifecycle
// ctx, so it keeps ticking long after the test that composed it returned, into whatever test
// runs next. A bare `mcpToolTrust.nowFn = …` assignment does not hold up the WRITER's end, so
// the reader's lock bought nothing and the pair is a genuine data race (CI caught exactly
// that: the leaked reconcile loop from TestControlledShadowRestartDrill reading now() against
// TestShadowSoak's deferred clock restore). resetMCPToolTrustForTest and the composition
// helpers here already take the lock; routing every swap through this makes it impossible to
// forget in a new one.
func swapToolTrustNowFnForTest(fn func() time.Time) func() time.Time {
	mcpToolTrust.mu.Lock()
	defer mcpToolTrust.mu.Unlock()
	prev := mcpToolTrust.nowFn
	mcpToolTrust.nowFn = fn
	return prev
}

// composeToolTrust composes the coordinator against a temp data dir with the given
// clock (nil ⇒ real time). It isolates the process-global singleton for the test.
func composeToolTrust(t *testing.T, clk func() time.Time) {
	t.Helper()
	composeToolTrustBounded(t, clk, 0, 0)
}

// composeToolTrustBounded is composeToolTrust with explicit store bounds (0 ⇒ store
// defaults). A small MaxRecords lets a test drive the at-capacity prune path.
func composeToolTrustBounded(t *testing.T, clk func() time.Time, maxRecords, maxPerTenant int) {
	t.Helper()
	resetMCPToolTrustForTest()
	t.Cleanup(resetMCPToolTrustForTest)
	dir := t.TempDir()
	store, err := tooltrust.NewStore(tooltrust.Config{
		Path:         filepath.Join(dir, "mcp_tooltrust", "approvals.json"),
		Clock:        clk,
		MaxRecords:   maxRecords,
		MaxPerTenant: maxPerTenant,
	})
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	mcpToolTrust.mu.Lock()
	mcpToolTrust.store = store
	mcpToolTrust.composed = true
	mcpToolTrust.reason = ""
	mcpToolTrust.nowFn = clk
	mcpToolTrust.mu.Unlock()
	mcpToolTrustReconcile = mcpToolTrust.reconcile
	execution.SetReconcileHook(func() { mcpToolTrustReconcile() })    // mirror the production wiring
	execution.SetIngestGuard(mcpToolTrust.runCatalogIngestSerialized) // mirror the production wiring
	mcpToolTrust.reconcile()
}

func requestAndApprove(t *testing.T, serverID, toolName, fpHex string, catRev uint64, expiresIn time.Duration) *tooltrust.ToolApproval {
	t.Helper()
	in := toolTrustRequestInput{
		Tenant:              ttTenant,
		ServerID:            serverID,
		ToolName:            toolName,
		ExpectedFingerprint: fpHex,
		ExpectedCatalogRev:  catRev,
		Purpose:             tooltrust.PurposeShadowEvaluation,
		RequestedBy:         "operator@corp",
		Reason:              "reviewed for shadow eval",
	}
	if expiresIn > 0 {
		exp := mcpToolTrust.now().Add(expiresIn)
		in.ExpiresAt = &exp
	}
	req, err := mcpToolTrust.RequestApproval(in)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	granted, err := mcpToolTrust.ApproveShadow(req.ApprovalID, "admin@corp", ttTenant)
	if err != nil {
		t.Fatalf("ApproveShadow: %v", err)
	}
	return granted
}

func eligibility(t *testing.T, cat *catalog.Catalog, serverID, name string) catalog.Eligibility {
	t.Helper()
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: registry.ServerID(serverID), Name: name})
	if !ok {
		t.Fatalf("tool %s/%s missing", serverID, name)
	}
	return rec.Eligibility
}

func gatewayScope(serverID string) rollout.ScopeSpec {
	return rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Servers:    []string{serverID},
		Operations: []rollout.RiskClass{rollout.RiskWrite},
		HighRisk:   true,
	}
}

// ── end-to-end: promotion closes the last Shadow prerequisite ─────────────────

func TestToolTrust_EndToEnd_PromotesUsableAndClosesPreflightPrereq(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)

	// Before approval: Quarantined, and the PRODUCTION usable-tool gate is fail-closed.
	if eligibility(t, cat, sid, tool) != catalog.Quarantined {
		t.Fatal("seeded tool must start Quarantined")
	}
	if shadowScopeHasUsableTool(gatewayScope(sid), 1) {
		t.Fatal("no usable tool before approval — gate must be fail-closed")
	}

	requestAndApprove(t, sid, tool, fpHex, cat.Current().Revision(), 0)

	// After approval: Usable, and the real preflight usable-tool gate is satisfied.
	if eligibility(t, cat, sid, tool) != catalog.Usable {
		t.Fatalf("approved tool must be Usable, got %s", eligibility(t, cat, sid, tool))
	}
	if !shadowScopeHasUsableTool(gatewayScope(sid), 1) {
		t.Fatal("an approved (Usable) in-scope tool must satisfy the Shadow usable-tool prerequisite")
	}
}

// ── purpose firewall: shadow trust NEVER arms the live-execution tier (Sec 23, mutation #10) ──

func TestToolTrust_PurposeFirewall_ShadowNeverArmsLiveTier(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	requestAndApprove(t, sid, tool, fpHex, cat.Current().Revision(), 0)

	// The shadow prerequisite is satisfied…
	if !shadowScopeHasUsableTool(gatewayScope(sid), 1) {
		t.Fatal("shadow prerequisite must be satisfied by the shadow approval")
	}
	// …but the live-execution tier stays DISARMED, and every RequiresLiveExecution mode
	// remains not-exec-ready. A shadow approval only ever produces catalog.Usable, which
	// touches the Shadow preflight and nothing on the live path.
	if liveExecDepsConfigured(false) {
		t.Fatal("shadow approval must NOT arm the live-execution tier")
	}
	if modeExecReady(rollout.ModeCanary, false) {
		t.Fatal("Canary must stay not-exec-ready after a shadow approval")
	}
	if modeExecReady(rollout.ModeProduction, false) {
		t.Fatal("Production must stay not-exec-ready after a shadow approval")
	}
}

// live_execution is now ISSUABLE, but only WITH an explicit finite expiry (§6). A live request with
// no expiry is refused as a request-shape error (admin_request_invalid), never silently defaulted;
// a live request WITH a valid in-ceiling expiry is accepted as a pending request (a grant still
// requires four-eyes at approve). This replaces the old "live is unissuable" assertion.
func TestToolTrust_LiveExecutionIssuableOnlyWithExpiry(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	base := toolTrustRequestInput{
		Tenant: ttTenant, ServerID: sid, ToolName: tool,
		ExpectedFingerprint: fpHex, ExpectedCatalogRev: cat.Current().Revision(),
		Purpose: tooltrust.PurposeLiveExecution, RequestedBy: "operator@corp",
	}
	// No expiry ⇒ refused as an invalid request (not purpose-unsupported).
	if _, err := mcpToolTrust.RequestLiveApproval(base); mcperr.ReasonOf(err) != mcperr.ReasonAdminRequestInvalid {
		t.Fatalf("live_execution without expiry must be admin_request_invalid, got %v", mcperr.ReasonOf(err).Code())
	}
	// Valid expiry ⇒ accepted as a pending live request.
	withExp := base
	exp := time.Now().Add(time.Hour)
	withExp.ExpiresAt = &exp
	a, err := mcpToolTrust.RequestLiveApproval(withExp)
	if err != nil {
		t.Fatalf("live_execution with a valid expiry must be issuable, got %v", err)
	}
	if a.Purpose != tooltrust.PurposeLiveExecution || a.Status != tooltrust.StatusPending {
		t.Fatalf("want pending live request, got purpose=%v status=%v", a.Purpose, a.Status)
	}
}

// ── crash / restart recovery (Sec 13, D3) ────────────────────────────────

func TestToolTrust_Recovery_RePromotesAcrossRestart(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	// Use a fixed dataDir so the durable store survives the "restart".
	dir := t.TempDir()
	setDataDirForTest(t, dir)
	resetMCPToolTrustForTest()
	t.Cleanup(resetMCPToolTrustForTest)
	initMCPToolTrust(nil)
	requestAndApprove(t, sid, tool, fpHex, cat.Current().Revision(), 0)
	if eligibility(t, cat, sid, tool) != catalog.Usable {
		t.Fatal("tool must be Usable after approval")
	}

	// Simulate a restart: the boot re-seeds a FRESH catalog (all Quarantined) and the
	// coordinator recomposes against the same durable store.
	reg2, cat2, err := seedInventory(mustDecodeControlled(t), limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg2, cat2)
	if eligibility(t, cat2, sid, tool) != catalog.Quarantined {
		t.Fatal("a freshly re-seeded catalog must start Quarantined")
	}
	resetMCPToolTrustForTest()
	initMCPToolTrust(nil) // Load durable approvals + startup reconcile
	if eligibility(t, cat2, sid, tool) != catalog.Usable {
		t.Fatal("startup reconcile must re-promote the tool from the durable approval (D3)")
	}
}

func mustDecodeControlled(t *testing.T) *qualInventoryDoc {
	t.Helper()
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"controlled","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"t","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return doc
}

// ── revocation demotes immediately (Sec 8) ────────────────────────────────

func TestToolTrust_Revoke_DemotesImmediately(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	granted := requestAndApprove(t, sid, tool, fpHex, cat.Current().Revision(), 0)
	if eligibility(t, cat, sid, tool) != catalog.Usable {
		t.Fatal("tool must be Usable after approval")
	}
	if _, err := mcpToolTrust.Revoke(granted.ApprovalID, "admin@corp", ttTenant, "compromised"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if eligibility(t, cat, sid, tool) != catalog.Quarantined {
		t.Fatalf("revoke must demote to Quarantined, got %s", eligibility(t, cat, sid, tool))
	}
	if shadowScopeHasUsableTool(gatewayScope(sid), 1) {
		t.Fatal("a revoked tool must no longer satisfy the usable-tool gate")
	}
	// A later reconcile must NOT re-promote a revoked grant.
	mcpToolTrust.reconcile()
	if eligibility(t, cat, sid, tool) != catalog.Quarantined {
		t.Fatal("a revoked grant must never be re-promoted by reconcile")
	}
}

// ── Codex P1: revoking ONE grant must not demote a tool a second grant covers ──

func TestToolTrust_Revoke_PreservesOtherActiveGrant(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	// Two independent active approvals for the SAME tool at the SAME fingerprint.
	g1 := requestAndApprove(t, sid, tool, fpHex, cat.Current().Revision(), 0)
	g2 := requestAndApprove(t, sid, tool, fpHex, cat.Current().Revision(), 0)
	if g1.ApprovalID == g2.ApprovalID {
		t.Fatal("expected two distinct approvals")
	}
	if eligibility(t, cat, sid, tool) != catalog.Usable {
		t.Fatal("tool must be Usable with two active grants")
	}
	// Revoking one must leave the tool Usable — the other grant still covers it.
	if _, err := mcpToolTrust.Revoke(g1.ApprovalID, "admin@corp", ttTenant, "rotate"); err != nil {
		t.Fatalf("revoke g1: %v", err)
	}
	if eligibility(t, cat, sid, tool) != catalog.Usable {
		t.Fatalf("revoking one of two grants must NOT demote the tool, got %s", eligibility(t, cat, sid, tool))
	}
	// Revoking the last grant withdraws trust.
	if _, err := mcpToolTrust.Revoke(g2.ApprovalID, "admin@corp", ttTenant, "done"); err != nil {
		t.Fatalf("revoke g2: %v", err)
	}
	if eligibility(t, cat, sid, tool) != catalog.Quarantined {
		t.Fatalf("revoking the last grant must demote to Quarantined, got %s", eligibility(t, cat, sid, tool))
	}
}

// ── Codex P1: revoke concurrent with reconcile ends demoted (TOCTOU) ──────────

func TestToolTrust_Revoke_ConcurrentReconcileEndsDemoted(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	g := requestAndApprove(t, sid, tool, fpHex, cat.Current().Revision(), 0)
	if eligibility(t, cat, sid, tool) != catalog.Usable {
		t.Fatal("tool must be Usable after approval")
	}
	// Race a revoke against a reconcile loop. deriveMu serializes the revoke's demote
	// with reconcile's promote, so a stale ActiveApprovals snapshot can never re-promote
	// a just-revoked tool. The final state must be Quarantined (revoked trust withdrawn).
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = mcpToolTrust.Revoke(g.ApprovalID, "admin@corp", ttTenant, "rotate")
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			mcpToolTrust.reconcile()
		}
	}()
	wg.Wait()
	mcpToolTrust.reconcile() // settle
	if eligibility(t, cat, sid, tool) != catalog.Quarantined {
		t.Fatalf("a revoked tool must end Quarantined, not %s (TOCTOU re-promotion)", eligibility(t, cat, sid, tool))
	}
}

// TestToolTrust_RequestPrune_ConcurrentReconcileKeepsExpiredDemoted proves the round-6 P1:
// at the store's record cap, a RequestApproval's prune of a just-Expired record must not
// interleave between reconcile's ExpireDue (which makes the grant terminal) and its
// ToolRefs re-derivation. deriveMu now serializes the create's prune with reconcile, so the
// expired tool is always demoted in the same pass that expired it — the prune can never
// delete its last ToolRef mid-pass and strand it Usable.
func TestToolTrust_RequestPrune_ConcurrentReconcileKeepsExpiredDemoted(t *testing.T) {
	resetInventory(t)
	inv := seedToolTrustInventory2(t)
	cat, sid, toolA, toolB, fpA, fpB := inv.cat, inv.serverID, inv.toolA, inv.toolB, inv.fpA, inv.fpB
	base := time.Unix(1_700_000_000, 0)
	var clkMu sync.Mutex
	now := base
	clk := func() time.Time { clkMu.Lock(); defer clkMu.Unlock(); return now }
	// MaxRecords=1 so the store is at capacity after the single approval; a new request must
	// prune to make room (only possible once A's expired record is swept to terminal).
	composeToolTrustBounded(t, clk, 1, 8)
	requestAndApprove(t, sid, toolA, fpA, cat.Current().Revision(), 10*time.Minute)
	if eligibility(t, cat, sid, toolA) != catalog.Usable {
		t.Fatal("tool A must be Usable after approval")
	}
	// Advance past A's expiry: A is now expired trust that reconcile must withdraw.
	clkMu.Lock()
	now = base.Add(11 * time.Minute)
	clkMu.Unlock()
	rev := cat.Current().Revision()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			mcpToolTrust.reconcile()
		}
	}()
	go func() {
		defer wg.Done()
		// Repeatedly attempt a request for tool B: at the cap this prunes A's Expired record
		// once reconcile has swept it, exercising the prune-vs-reconcile window each time.
		for i := 0; i < 200; i++ {
			_, _ = mcpToolTrust.RequestApproval(toolTrustRequestInput{
				Tenant:              ttTenant,
				ServerID:            sid,
				ToolName:            toolB,
				ExpectedFingerprint: fpB,
				ExpectedCatalogRev:  rev,
				Purpose:             tooltrust.PurposeShadowEvaluation,
				RequestedBy:         "operator@corp",
				Reason:              "b",
			})
		}
	}()
	wg.Wait()
	mcpToolTrust.reconcile() // settle
	if eligibility(t, cat, sid, toolA) != catalog.Quarantined {
		t.Fatalf("expired tool A must end Quarantined even under a concurrent at-cap prune, not %s", eligibility(t, cat, sid, toolA))
	}
}

// ── expiry demotes at the preflight reconcile (Sec 9) ─────────────────────────

func TestToolTrust_Expiry_DemotesAtReconcile(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	base := time.Unix(1_700_000_000, 0)
	now := base
	composeToolTrust(t, func() time.Time { return now })
	requestAndApprove(t, sid, tool, fpHex, cat.Current().Revision(), 10*time.Minute)
	if eligibility(t, cat, sid, tool) != catalog.Usable {
		t.Fatal("tool must be Usable while the grant is live")
	}
	// Advance past expiry; the preflight reconcile hook must expire + demote.
	now = base.Add(11 * time.Minute)
	if shadowScopeHasUsableTool(gatewayScope(sid), 1) {
		t.Fatal("an expired grant must not satisfy the usable-tool gate")
	}
	if eligibility(t, cat, sid, tool) != catalog.Quarantined {
		t.Fatalf("expiry reconcile must demote to Quarantined, got %s", eligibility(t, cat, sid, tool))
	}
}

// ── Codex P1: the periodic loop bounds the expired-trust window during Shadow ──

func TestToolTrust_ReconcileLoop_StartsOnlyWhenComposed(t *testing.T) {
	resetMCPToolTrustForTest()
	t.Cleanup(resetMCPToolTrustForTest)
	// Not composed ⇒ no loop (disabled-by-default posture is directly assertable).
	if startToolTrustReconcileLoop(context.Background()) {
		t.Fatal("an uncomposed coordinator must not start a reconcile loop")
	}
	resetInventory(t)
	seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if !startToolTrustReconcileLoop(ctx) {
		t.Fatal("a composed coordinator must start a reconcile loop")
	}
}

func TestToolTrust_ReconcileLoop_DemotesExpired(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	base := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	nowVal := base
	clk := func() time.Time { mu.Lock(); defer mu.Unlock(); return nowVal }
	composeToolTrust(t, clk)
	requestAndApprove(t, sid, tool, fpHex, cat.Current().Revision(), 10*time.Minute)
	if eligibility(t, cat, sid, tool) != catalog.Usable {
		t.Fatal("tool must be Usable while the grant is live")
	}
	// Advance past expiry, then let the periodic loop (short interval) demote it —
	// no inventory read / preflight is performed here.
	mu.Lock()
	nowVal = base.Add(11 * time.Minute)
	mu.Unlock()
	prevInterval := mcpToolTrustReconcileInterval
	mcpToolTrustReconcileInterval = 5 * time.Millisecond
	t.Cleanup(func() { mcpToolTrustReconcileInterval = prevInterval })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	startToolTrustReconcileLoop(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if eligibility(t, cat, sid, tool) == catalog.Quarantined {
			return // demoted by the loop
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("periodic loop must demote an expired grant, still %s", eligibility(t, cat, sid, tool))
}

// ── rug-pull: drift away from the reviewed fingerprint drops Usable (Sec 15) ──

func TestToolTrust_RugPull_DriftDropsUsable(t *testing.T) {
	resetInventory(t)
	reg, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	requestAndApprove(t, sid, tool, fpHex, cat.Current().Revision(), 0)
	if eligibility(t, cat, sid, tool) != catalog.Usable {
		t.Fatal("tool must be Usable after approval")
	}

	// Re-ingest the SAME tool with an expanded input schema (privilege expansion): the
	// ingest fold moves it off Usable, and a reconcile must NOT restore it (the approval
	// binds the OLD fingerprint).
	_, _, err := cat.Ingest(reg, catalog.DiscoveryInput{
		ServerID: registry.ServerID(sid), Identity: "id",
		Raw: []byte(`{"tools":[{"name":"t","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}]}`),
	})
	if err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	if eligibility(t, cat, sid, tool) == catalog.Usable {
		t.Fatal("drift must drop Usable via the ingest fold")
	}
	mcpToolTrust.reconcile()
	if eligibility(t, cat, sid, tool) == catalog.Usable {
		t.Fatal("reconcile must NOT re-promote a tool that drifted from the reviewed fingerprint")
	}
}

// ── stale request: expected fingerprint must match current (Sec 5) ────────────

func TestToolTrust_RequestRejectsStaleFingerprint(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, _ := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	// A wrong expected fingerprint (the reviewer saw a different digest) is rejected.
	wrong := hex.EncodeToString(make([]byte, 32))
	_, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant: ttTenant, ServerID: sid, ToolName: tool,
		ExpectedFingerprint: wrong, ExpectedCatalogRev: cat.Current().Revision(),
		Purpose: tooltrust.PurposeShadowEvaluation, RequestedBy: "operator@corp",
	})
	if mcperr.ReasonOf(err) != mcperr.ReasonToolFingerprintMismatch {
		t.Fatalf("stale fingerprint must be rejected, got %v", mcperr.ReasonOf(err).Code())
	}
}

// ── concurrent discovery race: approve F1 rejects stale when F2 was ingested (Sec 14) ──

func TestToolTrust_ConcurrentDiscovery_ApproveRejectsStale(t *testing.T) {
	resetInventory(t)
	reg, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	// Request bound to F1 (pending, not yet approved).
	req, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant: ttTenant, ServerID: sid, ToolName: tool,
		ExpectedFingerprint: fpHex, ExpectedCatalogRev: cat.Current().Revision(),
		Purpose: tooltrust.PurposeShadowEvaluation, RequestedBy: "operator@corp",
	})
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	// A concurrent discovery ingests F2 (the tool changed) BEFORE the admin approves.
	if _, _, err := cat.Ingest(reg, catalog.DiscoveryInput{
		ServerID: registry.ServerID(sid), Identity: "id",
		Raw: []byte(`{"tools":[{"name":"t","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}]}`),
	}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	// Approving the F1 request must REJECT STALE, never retarget to F2.
	_, err = mcpToolTrust.ApproveShadow(req.ApprovalID, "admin@corp", ttTenant)
	if mcperr.ReasonOf(err) != mcperr.ReasonToolFingerprintMismatch {
		t.Fatalf("approve after F2 ingest must reject stale, got %v", mcperr.ReasonOf(err).Code())
	}
	if eligibility(t, cat, sid, tool) == catalog.Usable {
		t.Fatal("a stale approval must never promote the drifted tool")
	}
}

// ── HTTP RBAC / tenant scope on the admin routes ─────────────────────────────

func TestToolTrust_HTTP_RBACAndTenant(t *testing.T) {
	// tool-approvals GET is viewer; a tenant is mandatory.
	if got := mcpReq(http.MethodGet, "/api/mcp/tool-approvals", RoleViewer, "").Code; got != http.StatusBadRequest {
		t.Fatalf("GET tool-approvals without tenant = %d, want 400", got)
	}
	// tool-approvals POST (create request) needs operator.
	if got := mcpReq(http.MethodPost, "/api/mcp/tool-approvals?tenant=t", RoleViewer, `{}`).Code; got != http.StatusForbidden {
		t.Fatalf("viewer POST tool-approvals = %d, want 403", got)
	}
	// tool-approval-decision needs admin.
	if got := mcpReq(http.MethodPost, "/api/mcp/tool-approval-decision?tenant=t", RoleOperator, `{"approval_id":"x","action":"approve"}`).Code; got != http.StatusForbidden {
		t.Fatalf("operator POST tool-approval-decision = %d, want 403", got)
	}
	// GET is not allowed on the decision route.
	if got := mcpReq(http.MethodGet, "/api/mcp/tool-approval-decision?tenant=t", RoleAdmin, "").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET tool-approval-decision = %d, want 405", got)
	}
}

// ── coordinator not composed ⇒ fail closed ────────────────────────────────

func TestToolTrust_NotComposedFailsClosed(t *testing.T) {
	resetMCPToolTrustForTest()
	t.Cleanup(resetMCPToolTrustForTest)
	_, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant: ttTenant, ServerID: "controlled", ToolName: "t",
		ExpectedFingerprint: hex.EncodeToString(make([]byte, 32)),
		Purpose:             tooltrust.PurposeShadowEvaluation, RequestedBy: "operator@corp",
	})
	if err == nil {
		t.Fatal("an uncomposed coordinator must fail closed")
	}
	// The reconcile hook is a safe no-op when uncomposed.
	mcpToolTrustReconcile()
}

// TestToolTrust_PendingDemotion_RetriedWhenRecordAbsent proves the round-7 P1: a tool that
// is Usable in the catalog but has NO backing approval record (as if its record was pruned
// after a failed Demote) is still demoted by a later reconcile, because reconcile re-derives
// pendingDemotions in addition to ToolRefs. Without the pending set, an empty ToolRefs would
// leave the stranded projection Usable forever.
func TestToolTrust_PendingDemotion_RetriedWhenRecordAbsent(t *testing.T) {
	resetInventory(t)
	inv := seedToolTrustInventory2(t)
	composeToolTrust(t, nil)
	// Simulate the stranded state: promote toolA to Usable directly (no approval record), and
	// record the demotion debt as a failed demote would have.
	key := catalog.ToolKey{Server: registry.ServerID(inv.serverID), Name: inv.toolA}
	rec, ok := inv.cat.Current().Get(key)
	if !ok {
		t.Fatal("tool A must exist")
	}
	if _, err := inv.cat.Promote(key, rec.Fingerprint); err != nil {
		t.Fatalf("setup promote: %v", err)
	}
	if eligibility(t, inv.cat, inv.serverID, inv.toolA) != catalog.Usable {
		t.Fatal("setup: tool A must be Usable")
	}
	tk := activeToolKey{serverID: inv.serverID, toolName: inv.toolA}
	mcpToolTrust.deriveMu.Lock()
	mcpToolTrust.markPendingDemotion(tk)
	mcpToolTrust.deriveMu.Unlock()
	// The store has no approval for A, so ToolRefs cannot rediscover it; only pendingDemotions
	// keeps it in the reconcile work set.
	mcpToolTrust.reconcile()
	if got := eligibility(t, inv.cat, inv.serverID, inv.toolA); got != catalog.Quarantined {
		t.Fatalf("a stranded Usable tool must be demoted via pendingDemotions, got %s", got)
	}
	mcpToolTrust.deriveMu.Lock()
	_, still := mcpToolTrust.pendingDemotions[tk]
	mcpToolTrust.deriveMu.Unlock()
	if still {
		t.Fatal("a successful demotion must clear the pending-demotion entry")
	}
}

// TestToolTrust_RequestUsesPerRecordRevision proves the round-8 P2: an approval request
// validates the submitted revision against the tool's PER-RECORD revision (the value the
// inventory endpoint exposes as ToolView.Revision), not the global catalog snapshot revision.
// An unrelated tool update advances the global revision but not the reviewed tool's record, so
// posting the exposed per-record revision must NOT produce a spurious stale-target 409.
func TestToolTrust_RequestUsesPerRecordRevision(t *testing.T) {
	resetInventory(t)
	inv := seedToolTrustInventory2(t)
	composeToolTrust(t, nil)
	// Advance the GLOBAL catalog revision via an UNRELATED tool (toolA), leaving toolB's
	// per-record revision unchanged.
	keyA := catalog.ToolKey{Server: registry.ServerID(inv.serverID), Name: inv.toolA}
	recA, ok := inv.cat.Current().Get(keyA)
	if !ok {
		t.Fatal("tool A must exist")
	}
	if _, err := inv.cat.Promote(keyA, recA.Fingerprint); err != nil {
		t.Fatalf("promote unrelated tool A: %v", err)
	}
	keyB := catalog.ToolKey{Server: registry.ServerID(inv.serverID), Name: inv.toolB}
	recB, ok := inv.cat.Current().Get(keyB)
	if !ok {
		t.Fatal("tool B must exist")
	}
	if inv.cat.Current().Revision() == recB.Revision {
		t.Fatal("setup: the global revision must have advanced past toolB's per-record revision")
	}
	// The operator posts the per-record revision the inventory endpoint exposes for toolB.
	_, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant:              ttTenant,
		ServerID:            inv.serverID,
		ToolName:            inv.toolB,
		ExpectedFingerprint: inv.fpB,
		ExpectedCatalogRev:  recB.Revision,
		Purpose:             tooltrust.PurposeShadowEvaluation,
		RequestedBy:         "operator@corp",
		Reason:              "b",
	})
	if err != nil {
		t.Fatalf("an unrelated catalog change must not make toolB's request stale, got %v", err)
	}
}

// TestExpiryFromSeconds_RejectsOutOfRange proves the round-9 P2: an approval TTL of zero
// means no-expiry, a positive in-range value yields a future timestamp, and a negative or
// overflowing value is REJECTED (never silently turned into a never-expiring or
// already-expired grant).
func TestExpiryFromSeconds_RejectsOutOfRange(t *testing.T) {
	if got, err := expiryFromSeconds(0); err != nil || got != nil {
		t.Fatalf("0 must mean no-expiry with no error, got (%v, %v)", got, err)
	}
	if got, err := expiryFromSeconds(3600); err != nil || got == nil || !got.After(time.Now()) {
		t.Fatalf("3600 must produce a future expiry, got (%v, %v)", got, err)
	}
	if _, err := expiryFromSeconds(-1); err == nil {
		t.Fatal("a negative TTL must be rejected, not silently treated as no-expiry")
	}
	if _, err := expiryFromSeconds(math.MaxInt64); err == nil {
		t.Fatal("an overflowing TTL must be rejected before the Duration multiply wraps")
	}
	if _, err := expiryFromSeconds(maxApprovalTTLSeconds + 1); err == nil {
		t.Fatal("a TTL over the cap must be rejected")
	}
	if _, err := expiryFromSeconds(maxApprovalTTLSeconds); err != nil {
		t.Fatalf("a TTL at the cap must be accepted, got %v", err)
	}
}

// TestToolTrust_ApproveExpiredDuringWrite_DemotesNotPromotes proves the round-10 P2: if a
// short-lived grant's TTL elapses during the durable Approve write, ApproveShadow must NOT
// promote the elapsed grant to Usable. The store clock stays at T0 (so Approve accepts the
// not-yet-expired request) while the coordinator clock is advanced past the expiry (modeling
// the TTL elapsing under the write); the post-transition recheck must demote, not promote.
func TestToolTrust_ApproveExpiredDuringWrite_DemotesNotPromotes(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	t0 := time.Unix(1_700_000_000, 0)
	composeToolTrust(t, func() time.Time { return t0 }) // store + coordinator both at T0
	exp := t0.Add(time.Minute)
	req, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant:              ttTenant,
		ServerID:            sid,
		ToolName:            tool,
		ExpectedFingerprint: fpHex,
		ExpectedCatalogRev:  cat.Current().Revision(),
		Purpose:             tooltrust.PurposeShadowEvaluation,
		RequestedBy:         "operator@corp",
		Reason:              "short ttl",
		ExpiresAt:           &exp,
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	// Advance ONLY the coordinator clock past the expiry — the store still sees T0, so Approve
	// accepts the request, but the post-write recheck sees an already-elapsed grant.
	mcpToolTrust.mu.Lock()
	mcpToolTrust.nowFn = func() time.Time { return t0.Add(2 * time.Minute) }
	mcpToolTrust.mu.Unlock()
	if _, err := mcpToolTrust.ApproveShadow(req.ApprovalID, "admin@corp", ttTenant); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got := eligibility(t, cat, sid, tool); got != catalog.Quarantined {
		t.Fatalf("an approved-but-already-expired grant must NOT be promoted Usable, got %s", got)
	}
}

// TestToolTrust_Annotator_SharedSnapshotAnnotatesEachTool proves the round-11 P1 fix: one
// annotator snapshot (built once per inventory response) correctly annotates multiple tools —
// an active grant, a pending request, and a tool with no approval — matching the single-tool
// annotateTool path, so GET /api/mcp/tools no longer re-lists all approvals per tool.
func TestToolTrust_Annotator_SharedSnapshotAnnotatesEachTool(t *testing.T) {
	resetInventory(t)
	inv := seedToolTrustInventory2(t)
	composeToolTrust(t, nil)
	// toolA → active (approved); toolB → pending. Use each tool's PER-RECORD revision (not the
	// global snapshot revision, which the toolA promote bumps) — the exact-target contract keys
	// on ToolView.Revision.
	recB, ok := inv.cat.Current().Get(catalog.ToolKey{Server: registry.ServerID(inv.serverID), Name: inv.toolB})
	if !ok {
		t.Fatal("seeded tool B must exist")
	}
	requestAndApprove(t, inv.serverID, inv.toolA, inv.fpA, inv.cat.Current().Revision(), 0)
	if _, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant:              ttTenant,
		ServerID:            inv.serverID,
		ToolName:            inv.toolB,
		ExpectedFingerprint: inv.fpB,
		ExpectedCatalogRev:  recB.Revision,
		Purpose:             tooltrust.PurposeShadowEvaluation,
		RequestedBy:         "operator@corp",
		Reason:              "b pending",
	}); err != nil {
		t.Fatalf("request B: %v", err)
	}
	ann := mcpToolTrust.newToolTrustAnnotator(ttTenant)
	if ann == nil {
		t.Fatal("annotator must be composed")
	}
	if a, ok := ann.annotate(inv.serverID, inv.toolA, inv.fpA); !ok || a.Status != "active" {
		t.Fatalf("toolA annotation = %+v ok=%v, want active", a, ok)
	}
	if a, ok := ann.annotate(inv.serverID, inv.toolB, inv.fpB); !ok || a.Status != "pending" {
		t.Fatalf("toolB annotation = %+v ok=%v, want pending", a, ok)
	}
	if _, ok := ann.annotate(inv.serverID, "no-such-tool", inv.fpA); ok {
		t.Fatal("a tool with no approval must have no annotation")
	}
	// Parity with the single-tool path.
	if a, ok := mcpToolTrust.annotateTool(ttTenant, inv.serverID, inv.toolA, inv.fpA); !ok || a.Status != "active" {
		t.Fatalf("annotateTool parity = %+v ok=%v, want active", a, ok)
	}
}

// TestToolTrust_Request_RequiresCatalogRevision proves the round-20 fix: the reviewed catalog
// revision is a MANDATORY part of the exact-target contract. A request omitting it (0) is rejected
// fail-closed, so an identical rediscovery cannot bind a revision the operator never reviewed by
// simply not asserting one; the correct current revision is accepted.
func TestToolTrust_Request_RequiresCatalogRevision(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)

	if _, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant:              ttTenant,
		ServerID:            sid,
		ToolName:            tool,
		ExpectedFingerprint: fpHex,
		// ExpectedCatalogRev omitted (0) — must be rejected.
		Purpose:     tooltrust.PurposeShadowEvaluation,
		RequestedBy: "operator@corp",
		Reason:      "no revision asserted",
	}); err == nil {
		t.Fatal("a request omitting the reviewed catalog revision must fail closed")
	}

	if _, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant:              ttTenant,
		ServerID:            sid,
		ToolName:            tool,
		ExpectedFingerprint: fpHex,
		ExpectedCatalogRev:  cat.Current().Revision(),
		Purpose:             tooltrust.PurposeShadowEvaluation,
		RequestedBy:         "operator@corp",
		Reason:              "revision asserted",
	}); err != nil {
		t.Fatalf("a request asserting the current revision must succeed: %v", err)
	}
}

// ttStubUpstream is a no-op UpstreamCaller for wiring tests (never actually called).
type ttStubUpstream struct{}

func (ttStubUpstream) Call(context.Context, upstreamclient.Target, string, json.RawMessage, upstreamclient.CallOptions) (*upstreamclient.Response, error) {
	return &upstreamclient.Response{Result: json.RawMessage(`{"tools":[]}`)}, nil
}

// TestToolTrust_ComposeWiresDiscoveryReconcile proves the round-14 production wiring: once tool
// trust is composed, a Discovery built by execution.NewDiscovery carries the reconcile hook, so
// a successful ingest reconciles trust with no per-caller wiring.
func TestToolTrust_ComposeWiresDiscoveryReconcile(t *testing.T) {
	resetInventory(t)
	reg, cat, _, _, _ := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	d, err := execution.NewDiscovery(reg, cat, ttStubUpstream{})
	if err != nil {
		t.Fatalf("NewDiscovery: %v", err)
	}
	if d.OnIngest == nil {
		t.Fatal("composing tool trust must install the discovery reconcile hook (NewDiscovery.OnIngest)")
	}
}

// TestToolTrust_ComposeWiresIngestGuard proves the round-15 production wiring: once tool trust
// is composed, a Discovery built by execution.NewDiscovery carries the ingest-serialization
// guard, so a discovery publish runs under the coordinator's derive lock with no per-caller
// wiring.
func TestToolTrust_ComposeWiresIngestGuard(t *testing.T) {
	resetInventory(t)
	reg, cat, _, _, _ := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	d, err := execution.NewDiscovery(reg, cat, ttStubUpstream{})
	if err != nil {
		t.Fatalf("NewDiscovery: %v", err)
	}
	if d.IngestGuard == nil {
		t.Fatal("composing tool trust must install the discovery ingest guard (NewDiscovery.IngestGuard)")
	}
}

// TestMCPDiscoveryHookWrappers_DelegateToExecution proves the package-main indirection the
// coordinator routes through — setMCPDiscoveryReconcileHook / setMCPDiscoveryIngestGuard, defined
// in mcp_shadow_startup.go — actually installs the execution.Discovery seams. The coordinator
// (mcp_tooltrust.go) uses these wrappers so it never imports internal/mcp/execution itself: the
// execution-posture wall pins mcp_shadow_startup.go as the SINGLE production importer of that
// package. This test guards that the indirection stays wired end to end.
func TestMCPDiscoveryHookWrappers_DelegateToExecution(t *testing.T) {
	resetInventory(t)
	reg, cat, _, _, _ := seedToolTrustInventory(t)

	var reconciled int
	setMCPDiscoveryReconcileHook(func() { reconciled++ })
	setMCPDiscoveryIngestGuard(func(ingest func() error) error { return ingest() })
	t.Cleanup(func() {
		setMCPDiscoveryReconcileHook(nil)
		setMCPDiscoveryIngestGuard(nil)
	})

	d, err := execution.NewDiscovery(reg, cat, ttStubUpstream{})
	if err != nil {
		t.Fatalf("NewDiscovery: %v", err)
	}
	if d.OnIngest == nil {
		t.Fatal("setMCPDiscoveryReconcileHook must install the reconcile hook on NewDiscovery")
	}
	d.OnIngest()
	if reconciled != 1 {
		t.Fatalf("the wrapper-installed reconcile hook was not invoked, got %d", reconciled)
	}
	if d.IngestGuard == nil {
		t.Fatal("setMCPDiscoveryIngestGuard must install the ingest guard on NewDiscovery")
	}
}

// TestToolTrust_IngestSerializedUnderDeriveMu proves the round-15 fix: runCatalogIngestSerialized
// (the execution.SetIngestGuard seam) runs the discovery ingest under deriveMu, so a catalog
// revision advance is mutually exclusive with an in-flight approve/revoke/reconcile critical
// section. While deriveMu is held (as ApproveShadow holds it across loadTarget→store.Approve),
// a serialized ingest must NOT run; it must proceed once the lock is released.
func TestToolTrust_IngestSerializedUnderDeriveMu(t *testing.T) {
	resetInventory(t)
	seedToolTrustInventory(t)
	composeToolTrust(t, nil)

	// Hold deriveMu as an in-flight approval's critical section would.
	mcpToolTrust.deriveMu.Lock()

	started := make(chan struct{})
	ran := make(chan struct{})
	go func() {
		close(started)
		_ = mcpToolTrust.runCatalogIngestSerialized(func() error {
			close(ran)
			return nil
		})
	}()
	<-started

	select {
	case <-ran:
		mcpToolTrust.deriveMu.Unlock()
		t.Fatal("a serialized ingest ran while deriveMu was held — the publish is not serialized with the approve critical section")
	case <-time.After(50 * time.Millisecond):
		// Expected: the ingest is blocked on deriveMu.
	}

	mcpToolTrust.deriveMu.Unlock()
	select {
	case <-ran:
		// Expected: released, the ingest proceeds.
	case <-time.After(2 * time.Second):
		t.Fatal("the serialized ingest did not run after deriveMu was released")
	}
}

// TestToolTrust_RequestApprovalHoldsDeriveMuAcrossTargetLoad proves the round-17 fix: RequestApproval
// acquires deriveMu BEFORE loadTarget and holds it through CreateRequest. Because a discovery ingest
// advances the catalog revision/fingerprint only under deriveMu (runCatalogIngestSerialized), holding
// the lock across the whole resolve→validate→create makes the target the request binds atomic with its
// validation — a rediscovery can no longer advance it in the gap and leave a stale, immediately-
// unapprovable pending record. While deriveMu is held, RequestApproval must block; it must proceed once
// released.
func TestToolTrust_RequestApprovalHoldsDeriveMuAcrossTargetLoad(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)

	mcpToolTrust.deriveMu.Lock()

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
			Tenant:              ttTenant,
			ServerID:            sid,
			ToolName:            tool,
			ExpectedFingerprint: fpHex,
			ExpectedCatalogRev:  cat.Current().Revision(),
			Purpose:             tooltrust.PurposeShadowEvaluation,
			RequestedBy:         "operator@corp",
			Reason:              "reviewed for shadow eval",
		})
		done <- err
	}()
	<-started

	select {
	case <-done:
		mcpToolTrust.deriveMu.Unlock()
		t.Fatal("RequestApproval completed while deriveMu was held — it does not serialize the target load/create under the lock")
	case <-time.After(50 * time.Millisecond):
		// Expected: blocked on deriveMu before it can load or validate the target.
	}

	mcpToolTrust.deriveMu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RequestApproval after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RequestApproval did not complete after deriveMu was released")
	}
}

// TestToolTrust_OmittedToolWithdrawsTrust proves the round-27 P1 fix at the coordinator
// level: when a COMPLETE discovery for a server stops advertising a tool that was
// previously approved-and-Usable, the ingest fold WITHDRAWS that tool from the catalog
// (drops its record). A server that no longer exposes a tool must not leave a stale
// approved-and-Usable projection behind, a reconcile must not resurrect it, and the
// withdrawn tool must be un-approvable. Tools the server still advertises are untouched.
func TestToolTrust_OmittedToolWithdrawsTrust(t *testing.T) {
	resetInventory(t)
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"controlled","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"t","input_schema":{"type":"object"}},{"name":"u","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
	recA, ok := cat.Current().Get(catalog.ToolKey{Server: "controlled", Name: "t"})
	if !ok {
		t.Fatal("seeded tool t must exist")
	}
	sumA := recA.Fingerprint.Sum()
	fpA := hex.EncodeToString(sumA[:])

	composeToolTrust(t, nil)
	requestAndApprove(t, "controlled", "t", fpA, cat.Current().Revision(), 0)
	if eligibility(t, cat, "controlled", "t") != catalog.Usable {
		t.Fatal("tool t must be Usable after approval")
	}

	// A COMPLETE re-discovery of the server advertises ONLY tool u — tool t is withdrawn.
	if _, _, err := cat.Ingest(reg, catalog.DiscoveryInput{
		ServerID: registry.ServerID("controlled"), Identity: "id",
		Raw: []byte(`{"tools":[{"name":"u","inputSchema":{"type":"object"}}]}`),
	}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}

	// The ingest fold must DROP the withdrawn tool's record entirely.
	if _, ok := cat.Current().Get(catalog.ToolKey{Server: "controlled", Name: "t"}); ok {
		t.Fatal("a tool omitted by a complete discovery must be withdrawn from the catalog")
	}
	// Tool u (still advertised) is untouched.
	if _, ok := cat.Current().Get(catalog.ToolKey{Server: "controlled", Name: "u"}); !ok {
		t.Fatal("a tool still advertised must remain in the catalog")
	}

	// Reconcile must not resurrect the withdrawn tool.
	mcpToolTrust.reconcile()
	if _, ok := cat.Current().Get(catalog.ToolKey{Server: "controlled", Name: "t"}); ok {
		t.Fatal("reconcile must not restore a withdrawn tool")
	}

	// The withdrawn tool is un-approvable: a fresh request against its old fingerprint fails
	// closed because the tool no longer exists in the catalog.
	if _, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant:              ttTenant,
		ServerID:            "controlled",
		ToolName:            "t",
		ExpectedFingerprint: fpA,
		ExpectedCatalogRev:  cat.Current().Revision(),
		Purpose:             tooltrust.PurposeShadowEvaluation,
		RequestedBy:         "operator@corp",
		Reason:              "attempt to re-approve a withdrawn tool",
	}); err == nil {
		t.Fatal("a withdrawn tool must be un-approvable")
	}
}
