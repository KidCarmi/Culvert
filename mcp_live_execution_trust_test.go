package main

// Live-execution trust tests (Culvert MCP — Live Execution Trust). These pin the governed
// live_execution ToolApproval path end to end through the package-main coordinator and the Canary
// activation-preflight bridge:
//
//   - §5 four-eyes (canonical principals), §6 short-TTL, §7 exact-current-state, §8 rug-pull,
//     §9 revocation, §10 expiry, §11 lifecycle, §13 per-tool scope coverage, §15 catalog-usable
//     orthogonality, §17 tenant isolation, §20 concurrency, §22 NO activation coupling, §24 the
//     mutation campaign, §25 red-team.
//
// The invariant behind every case: a live_execution approval is a TRUST decision only — it never
// arms an executor, never composes the live tier, never activates Canary, and never makes a tool
// catalog.Usable. It only lets the Canary preflight's live_execution_approval_invalid row become
// SATISFIABLE; the node still fails closed on live_executor_absent (and budget), so no transition
// can occur.

import (
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// --- live-trust harness ----------------------------------------------------

const (
	liveRequester = "requester-principal" // a canonical authenticated principal (session subject)
	liveApprover  = "approver-principal"  // a DISTINCT canonical principal — four-eyes
)

// liveFakeClock returns a fixed clock so expiry is deterministic across the whole vertical (store +
// coordinator + bridge all read it).
func liveFakeClock() (clk *liveTrustClock, now func() time.Time) {
	c := &liveTrustClock{t: time.Unix(1_700_000_000, 0)}
	return c, c.now
}

type liveTrustClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *liveTrustClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *liveTrustClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *liveTrustClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// liveScope builds a full Canary activation scope (Tenants + Servers + Tools) declaring the tool at
// the given fingerprint hex. Read-first (RiskRead) so the read-first row is not the reason under test.
func liveScope(sid, tool, fpHex string) rollout.ScopeSpec {
	return rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Tenants:    []string{ttTenant},
		Servers:    []string{sid},
		Tools:      []rollout.ToolSel{{Server: sid, Name: tool, Fingerprint: fpHex}},
		Operations: []rollout.RiskClass{rollout.RiskRead},
	}
}

// requestLive creates a pending live_execution request via the dedicated coordinator path.
func requestLive(t *testing.T, sid, tool, fpHex string, catRev uint64, requester string, ttl time.Duration) *tooltrust.ToolApproval {
	t.Helper()
	exp := mcpToolTrust.now().Add(ttl)
	in := toolTrustRequestInput{
		Tenant: ttTenant, ServerID: sid, ToolName: tool,
		ExpectedFingerprint: fpHex, ExpectedCatalogRev: catRev,
		RequestedBy: requester, ExpiresAt: &exp, Reason: "reviewed for live execution",
	}
	a, err := mcpToolTrust.RequestLiveApproval(in)
	if err != nil {
		t.Fatalf("RequestLiveApproval: %v", err)
	}
	return a
}

// requestAndApproveLive drives the full four-eyes live path and returns the active grant.
func requestAndApproveLive(t *testing.T, sid, tool, fpHex string, catRev uint64) *tooltrust.ToolApproval {
	t.Helper()
	req := requestLive(t, sid, tool, fpHex, catRev, liveRequester, time.Hour)
	g, err := mcpToolTrust.ApproveLive(req.ApprovalID, liveApprover, ttTenant)
	if err != nil {
		t.Fatalf("ApproveLive: %v", err)
	}
	if g.Status != tooltrust.StatusActive {
		t.Fatalf("want active grant, got %v", g.Status)
	}
	return g
}

// scopeApprovalReason runs the REAL bridge (buildLiveApprovalBindings) through the pure canary
// validator, at the coordinator clock — exactly what the activation preflight does for the
// live_execution_approval_invalid row.
func scopeApprovalReason(scope rollout.ScopeSpec) canary.ScopeApprovalReason {
	return canary.ValidateScopeApprovals(scope, buildLiveApprovalBindings(scope), mcpToolTrust.now())
}

func hasReason(rd canary.Readiness, want canary.Reason) bool {
	for _, r := range rd.Unmet {
		if r == want {
			return true
		}
	}
	return false
}

// --- §13/§27: the row becomes SATISFIABLE, not auto-satisfied ---------------

func TestLiveTrust_ScopeApprovalSatisfiableWithValidGrant(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	clk, fn := liveFakeClock()
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, fn)
	_ = clk

	scope := liveScope(sid, tool, fpHex)
	// Stock node: no live approval ⇒ the row is UNMET (fail-closed default, §27).
	if r := scopeApprovalReason(scope); r == canary.ScopeApprovalOK {
		t.Fatal("a stock node with no live approval must NOT satisfy the scope-approval row")
	}
	// Issue + four-eyes approve one valid live grant for the scoped tool.
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	if r := scopeApprovalReason(scope); r != canary.ScopeApprovalOK {
		t.Fatalf("a fully-approved scope must satisfy the row, got %q", r)
	}
}

// --- §22: issuing a live approval arms NOTHING -----------------------------

func TestLiveTrust_NoActivationCoupling(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	clk, fn := liveFakeClock()
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, fn)
	_ = clk

	beforeMode := getMCPRollout().stateFor(rollout.CapabilityGateway).CurrentMode()
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())

	// The live tier is NOT armed by issuing trust.
	if liveExecDepsConfigured(false) {
		t.Fatal("SECURITY: issuing a live approval must not arm the live-execution tier")
	}
	// The rollout mode is unchanged (no Canary transition).
	if got := getMCPRollout().stateFor(rollout.CapabilityGateway).CurrentMode(); got != beforeMode {
		t.Fatalf("SECURITY: issuing a live approval changed the rollout mode %v -> %v", beforeMode, got)
	}
	// The row is satisfiable, but the FULL activation preflight is STILL not ready: the node fails
	// closed on live_executor_absent (the ultimate backstop) and canary_budget_not_configured, so no
	// upstream side effect is ever reachable.
	scope := liveScope(sid, tool, fpHex)
	ai := canaryActivationInputsProbe(rollout.CapabilityGateway, scope, 1)
	in := CanaryActivationInput{
		Capability: rollout.CapabilityGateway, Scope: scope, ScopeRev: 1,
		ToolApprovals: ai.ToolApprovals, Budget: ai.Budget,
		ServerUsable: ai.ServerUsable, FingerprintCurrent: ai.FingerprintCurrent,
		Now: mcpToolTrust.now(),
	}
	rd := evaluateCanaryActivationPreflight(in)
	if rd.Ready {
		t.Fatal("SECURITY: Canary must never be ready — the live tier is unarmed")
	}
	if hasReason(rd, canary.ReasonLiveApprovalInvalid) {
		t.Fatal("the live_execution_approval_invalid row must be SATISFIED once the scope is fully approved")
	}
	if !hasReason(rd, canary.ReasonLiveExecutorAbsent) {
		t.Fatal("live_executor_absent must remain unmet — the backstop that keeps Canary unreachable")
	}
	if !hasReason(rd, canary.ReasonBudgetNotConfigured) {
		t.Fatal("canary_budget_not_configured must remain unmet — no authoritative budget store exists")
	}
}

// --- §15: a live approval never makes a tool catalog.Usable ----------------

func TestLiveTrust_ApproveDoesNotPromoteUsable(t *testing.T) {
	resetInventory(t)
	resetExecDeps(t)
	clk, fn := liveFakeClock()
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, fn)
	_ = clk

	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	if eligibility(t, cat, sid, tool) == catalog.Usable {
		t.Fatal("SECURITY: a live_execution approval must NOT make the tool catalog.Usable (§15)")
	}
	if shadowScopeHasUsableTool(gatewayScope(sid), 1) {
		t.Fatal("SECURITY: a live approval must not satisfy the Shadow usable-tool prerequisite")
	}
}

// --- §5: four-eyes on canonical principals ---------------------------------

func TestLiveTrust_FourEyesSelfApprovalRefused(t *testing.T) {
	resetInventory(t)
	clk, fn := liveFakeClock()
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, fn)
	_ = clk
	req := requestLive(t, sid, tool, fpHex, cat.Current().Revision(), liveRequester, time.Hour)
	// The requester approving their own request is refused fail-closed.
	if _, err := mcpToolTrust.ApproveLive(req.ApprovalID, liveRequester, ttTenant); mcperr.ReasonOf(err) != mcperr.ReasonApprovalSelfApproval {
		t.Fatalf("self-approval must be refused, got %v", mcperr.ReasonOf(err).Code())
	}
}

// --- route isolation: live must not go through the shadow approve path -----

func TestLiveTrust_RouteIsolation(t *testing.T) {
	resetInventory(t)
	clk, fn := liveFakeClock()
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, fn)
	_ = clk
	// A live request approved via the SHADOW path is refused (would skip four-eyes + promote Usable).
	req := requestLive(t, sid, tool, fpHex, cat.Current().Revision(), liveRequester, time.Hour)
	if _, err := mcpToolTrust.ApproveShadow(req.ApprovalID, liveApprover, ttTenant); mcperr.ReasonOf(err) != mcperr.ReasonApprovalPurposeUnsupported {
		t.Fatalf("a live approval via ApproveShadow must be refused, got %v", mcperr.ReasonOf(err).Code())
	}
	// A shadow request approved via the LIVE path is refused too (would apply the wrong governance).
	sreq, err := mcpToolTrust.RequestApproval(toolTrustRequestInput{
		Tenant: ttTenant, ServerID: sid, ToolName: tool,
		ExpectedFingerprint: fpHex, ExpectedCatalogRev: cat.Current().Revision(),
		Purpose: tooltrust.PurposeShadowEvaluation, RequestedBy: "operator@corp",
	})
	if err != nil {
		t.Fatalf("shadow request: %v", err)
	}
	if _, err := mcpToolTrust.ApproveLive(sreq.ApprovalID, liveApprover, ttTenant); mcperr.ReasonOf(err) != mcperr.ReasonApprovalPurposeUnsupported {
		t.Fatalf("a shadow approval via ApproveLive must be refused, got %v", mcperr.ReasonOf(err).Code())
	}
}

// --- §13: per-tool coverage (partial / wrong-tenant / wrong-fingerprint) ---

func TestLiveTrust_ScopeCoverageFailures(t *testing.T) {
	t.Run("partial_coverage", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		inv := seedToolTrustInventory2(t)
		composeToolTrust(t, fn)
		_ = clk
		// Approve tool A only; scope names A AND B ⇒ B is uncovered.
		requestAndApproveLive(t, inv.serverID, inv.toolA, inv.fpA, inv.cat.Current().Revision())
		scope := rollout.ScopeSpec{
			Capability: rollout.CapabilityGateway,
			Tenants:    []string{ttTenant},
			Servers:    []string{inv.serverID},
			Tools: []rollout.ToolSel{
				{Server: inv.serverID, Name: inv.toolA, Fingerprint: inv.fpA},
				{Server: inv.serverID, Name: inv.toolB, Fingerprint: inv.fpB},
			},
			Operations: []rollout.RiskClass{rollout.RiskRead},
		}
		if r := scopeApprovalReason(scope); r == canary.ScopeApprovalOK {
			t.Fatal("a partially-approved scope must NOT satisfy the row")
		}
	})
	t.Run("wrong_tenant", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		_ = clk
		requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
		// A scope naming a tenant that does NOT own the server has no resolvable target ⇒ uncovered.
		scope := liveScope(sid, tool, fpHex)
		scope.Tenants = []string{"some-other-tenant"}
		if r := scopeApprovalReason(scope); r == canary.ScopeApprovalOK {
			t.Fatal("an approval for another tenant must not cover a scope admitting a different tenant")
		}
	})
	t.Run("wrong_fingerprint", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		_ = clk
		requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
		// A scope declaring a DIFFERENT fingerprint than the current observation is rejected on the
		// scope-fingerprint check (the rug-pull cannot be smuggled through the target).
		scope := liveScope(sid, tool, "00"+fpHex[2:])
		if r := scopeApprovalReason(scope); r != canary.ScopeApprovalFingerprint {
			t.Fatalf("a scope with a mismatched fingerprint must fail on the fingerprint check, got %q", r)
		}
	})
}

// --- §8: rug-pull — an F1 approval does not govern a drifted F2 ------------

func TestLiveTrust_RugPull_DriftInvalidatesLiveApproval(t *testing.T) {
	resetInventory(t)
	clk, fn := liveFakeClock()
	reg, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, fn)
	_ = clk
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	scope := liveScope(sid, tool, fpHex)
	if r := scopeApprovalReason(scope); r != canary.ScopeApprovalOK {
		t.Fatalf("precondition: valid live approval must satisfy the scope, got %q", r)
	}
	// Drift the tool's fingerprint (expanded input schema — a privilege expansion). The live approval
	// still binds F1, but the CURRENT observation is F2.
	if _, _, err := cat.Ingest(reg, catalog.DiscoveryInput{
		ServerID: registry.ServerID(sid), Identity: "id",
		Raw: []byte(`{"tools":[{"name":"t","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}]}`),
	}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	// The F1 approval must NOT govern F2: the binding target is now F2, which no longer matches the
	// scope's declared F1 (and the approval's F1) — the row fails closed.
	if r := scopeApprovalReason(scope); r == canary.ScopeApprovalOK {
		t.Fatal("SECURITY: an F1 live approval must not govern a drifted F2 tool (rug-pull)")
	}
}

// --- §9/§10: revoke and expiry immediately invalidate live trust ----------

func TestLiveTrust_RevokeInvalidatesImmediately(t *testing.T) {
	resetInventory(t)
	clk, fn := liveFakeClock()
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, fn)
	_ = clk
	g := requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	scope := liveScope(sid, tool, fpHex)
	if r := scopeApprovalReason(scope); r != canary.ScopeApprovalOK {
		t.Fatalf("precondition: satisfied, got %q", r)
	}
	if _, err := mcpToolTrust.Revoke(g.ApprovalID, "security@corp", ttTenant, "incident"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if r := scopeApprovalReason(scope); r == canary.ScopeApprovalOK {
		t.Fatal("SECURITY: a revoked live approval must immediately drop scope coverage")
	}
	// Re-approval after revoke is a NEW decision — the revoked record never re-activates.
	if _, err := mcpToolTrust.ApproveLive(g.ApprovalID, liveApprover, ttTenant); err == nil {
		t.Fatal("a revoked approval must not be re-approvable")
	}
}

func TestLiveTrust_ExpiryInvalidatesAtAndAfterDeadline(t *testing.T) {
	resetInventory(t)
	clk, fn := liveFakeClock()
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, fn)
	req := requestLive(t, sid, tool, fpHex, cat.Current().Revision(), liveRequester, time.Hour)
	g, err := mcpToolTrust.ApproveLive(req.ApprovalID, liveApprover, ttTenant)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	scope := liveScope(sid, tool, fpHex)
	if r := scopeApprovalReason(scope); r != canary.ScopeApprovalOK {
		t.Fatalf("precondition: satisfied, got %q", r)
	}
	// Boundary: now == expires_at must fail closed (not before the expiry).
	clk.set(*g.ExpiresAt)
	if r := scopeApprovalReason(scope); r == canary.ScopeApprovalOK {
		t.Fatal("SECURITY: at now == expires_at a live approval must be treated as expired (fail closed)")
	}
	// After the deadline it is still excluded.
	clk.advance(time.Minute)
	if r := scopeApprovalReason(scope); r == canary.ScopeApprovalOK {
		t.Fatal("SECURITY: an expired live approval must not cover a scope")
	}
}

// --- §17: tenant isolation — no cross-tenant existence oracle --------------

func TestLiveTrust_TenantIsolation(t *testing.T) {
	resetInventory(t)
	clk, fn := liveFakeClock()
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, fn)
	_ = clk
	g := requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	// Get and Revoke from the WRONG tenant return a uniform not-found (never a distinct oracle).
	if _, err := mcpToolTrust.Get(g.ApprovalID, "attacker-tenant"); mcperr.ReasonOf(err) != mcperr.ReasonApprovalNotFound {
		t.Fatalf("cross-tenant Get must be not-found, got %v", mcperr.ReasonOf(err).Code())
	}
	if _, err := mcpToolTrust.Revoke(g.ApprovalID, "attacker", "attacker-tenant", "x"); mcperr.ReasonOf(err) != mcperr.ReasonApprovalNotFound {
		t.Fatalf("cross-tenant Revoke must be not-found, got %v", mcperr.ReasonOf(err).Code())
	}
	// The correct tenant still sees it.
	if _, err := mcpToolTrust.Get(g.ApprovalID, ttTenant); err != nil {
		t.Fatalf("same-tenant Get must succeed, got %v", err)
	}
}

// --- §19: recovery — a revoked live grant never resurrects across restart --

func TestLiveTrust_RevokedDoesNotResurrectAcrossRestart(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	dir := t.TempDir()
	setDataDirForTest(t, dir)
	resetMCPToolTrustForTest()
	t.Cleanup(resetMCPToolTrustForTest)
	initMCPToolTrust(nil)

	req := requestLive(t, sid, tool, fpHex, cat.Current().Revision(), liveRequester, time.Hour)
	g, err := mcpToolTrust.ApproveLive(req.ApprovalID, liveApprover, ttTenant)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := mcpToolTrust.Revoke(g.ApprovalID, "security@corp", ttTenant, "incident"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Restart: re-seed a fresh catalog + reload the durable store from the SAME dir.
	resetInventory(t)
	_, cat2, _, _, _ := seedToolTrustInventory(t)
	resetMCPToolTrustForTest()
	initMCPToolTrust(nil)
	scope := liveScope(sid, tool, fpHex)
	scope.Tools[0].Fingerprint = func() string {
		rec, _ := cat2.Current().Get(catalog.ToolKey{Server: registry.ServerID(sid), Name: tool})
		sum := rec.Fingerprint.Sum()
		return hexOf(sum[:])
	}()
	if r := scopeApprovalReason(scope); r == canary.ScopeApprovalOK {
		t.Fatal("SECURITY: a revoked live approval must not resurrect across a restart")
	}
	got, err := mcpToolTrust.Get(g.ApprovalID, ttTenant)
	if err != nil {
		t.Fatalf("get after restart: %v", err)
	}
	if got.Status != tooltrust.StatusRevoked {
		t.Fatalf("the record must remain revoked across restart, got %v", got.Status)
	}
}

// --- §20: concurrency — exactly one terminal decision wins -----------------

func TestLiveTrust_ConcurrentApproveVsRevokeOneWinner(t *testing.T) {
	resetInventory(t)
	clk, fn := liveFakeClock()
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, fn)
	_ = clk
	req := requestLive(t, sid, tool, fpHex, cat.Current().Revision(), liveRequester, time.Hour)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = mcpToolTrust.ApproveLive(req.ApprovalID, liveApprover, ttTenant) }()
	go func() { defer wg.Done(); _, _ = mcpToolTrust.Revoke(req.ApprovalID, "security@corp", ttTenant, "race") }()
	wg.Wait()

	got, err := mcpToolTrust.Get(req.ApprovalID, ttTenant)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// The store mutex serializes the two, so the record settles at exactly one deterministic status
	// (active if approve landed first, revoked if revoke did) — never a torn or double-decided state.
	if got.Status != tooltrust.StatusActive && got.Status != tooltrust.StatusRevoked {
		t.Fatalf("want a single terminal-or-active status, got %v", got.Status)
	}
	// If it settled Active, four-eyes must still hold; if Revoked, it must not cover a scope.
	scope := liveScope(sid, tool, fpHex)
	if got.Status == tooltrust.StatusRevoked && scopeApprovalReason(scope) == canary.ScopeApprovalOK {
		t.Fatal("a revoked winner must not leave the scope covered")
	}
	if got.Status == tooltrust.StatusActive && got.ApprovedBy == got.RequestedBy {
		t.Fatal("an active winner must carry four-eyes evidence")
	}
}

// --- §24: mutation campaign — each mutation fails a NAMED gate --------------
//
// Fifteen mutations, each of which MUST be rejected by a named control. Mutations reachable at the
// coordinator/bridge or via a pure canary predicate are exercised here; the three that need direct
// CurrentTarget / durable-write control are pinned in internal/mcp/tooltrust/store_test.go and named
// in the map below:
//
//	 1  shadow approval satisfies live trust          → canary.SatisfiesLiveExecution == TrustNotLiveExecution   (here)
//	 2  live_execution purpose remains unissuable     → RequestLiveApproval(valid) SUCCEEDS                       (here)
//	 3  self-approval succeeds                         → ApproveLive(self) == ReasonApprovalSelfApproval           (here)
//	 4  expiry omitted                                 → RequestLiveApproval(no expiry) == admin_request_invalid   (here)
//	 5  expiry > 24h accepted                          → RequestLiveApproval(>24h) == admin_request_invalid        (here)
//	 6  future approved_at accepted                    → canary.SatisfiesLiveExecution == TrustApprovedInFuture    (here)
//	 7  stale catalog revision approved                → store.Approve == ReasonToolApprovalStale                  (TestLiveApprove_StaleCatalogRevisionRefused)
//	 8  stale server revision approved                 → store.Approve == ReasonToolApprovalStale                  (TestLiveApprove_StaleServerRevisionRefused)
//	 9  F1 approval governs F2                         → scopeApprovalReason != OK after drift                     (here)
//	10  revoked approval satisfies readiness           → scopeApprovalReason != OK after revoke                    (here)
//	11  expired approval satisfies readiness           → scopeApprovalReason != OK after expiry                    (here)
//	12  wrong-tenant approval satisfies scope          → scopeApprovalReason != OK with foreign tenant             (here)
//	13  one approval covers two scoped tools           → scopeApprovalReason != OK with a second uncovered tool    (here)
//	14  audit(durable-write) failure changes state     → store.Approve reverts to pending                         (TestLiveApprove_PersistFailureRevertsState)
//	15  issuing approval arms execution                → liveExecDepsConfigured stays false; mode unchanged        (here + TestLiveTrust_NoActivationCoupling)
func TestLiveTrustMutationCampaign_Roster(t *testing.T) {
	t.Run("m1_shadow_never_satisfies_live", func(t *testing.T) {
		now := time.Unix(1_700_000_000, 0)
		exp := now.Add(time.Hour)
		tgt := canary.LiveTarget{Tenant: "t", ServerID: "s", ToolName: "n", Fingerprint: fpForTest(0x11), FingerprintFormat: 1}
		shadow := &tooltrust.ToolApproval{
			Purpose: tooltrust.PurposeShadowEvaluation, Status: tooltrust.StatusActive,
			RequestedBy: "r", ApprovedBy: "a", ApprovedAt: now, ExpiresAt: &exp,
			Tenant: "t", ServerID: "s", ToolName: "n", Fingerprint: fpForTest(0x11), FingerprintFormatVersion: 1,
		}
		if canary.SatisfiesLiveExecution(shadow, tgt, now) != canary.TrustNotLiveExecution {
			t.Fatal("mutation1: a shadow_evaluation approval must NEVER satisfy live trust")
		}
	})
	t.Run("m2_live_is_issuable_under_governance", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		_ = clk
		if requestLive(t, sid, tool, fpHex, cat.Current().Revision(), liveRequester, time.Hour) == nil {
			t.Fatal("mutation2: live_execution must be issuable under governance")
		}
	})
	t.Run("m3_self_approval_refused", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		_ = clk
		req := requestLive(t, sid, tool, fpHex, cat.Current().Revision(), liveRequester, time.Hour)
		if _, err := mcpToolTrust.ApproveLive(req.ApprovalID, liveRequester, ttTenant); mcperr.ReasonOf(err) != mcperr.ReasonApprovalSelfApproval {
			t.Fatalf("mutation3: self-approval must be refused, got %v", mcperr.ReasonOf(err).Code())
		}
	})
	t.Run("m4_expiry_required", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		_ = clk
		in := toolTrustRequestInput{
			Tenant: ttTenant, ServerID: sid, ToolName: tool,
			ExpectedFingerprint: fpHex, ExpectedCatalogRev: cat.Current().Revision(), RequestedBy: liveRequester,
		}
		if _, err := mcpToolTrust.RequestLiveApproval(in); mcperr.ReasonOf(err) != mcperr.ReasonAdminRequestInvalid {
			t.Fatalf("mutation4: live request without expiry must be refused, got %v", mcperr.ReasonOf(err).Code())
		}
	})
	t.Run("m5_ttl_ceiling", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		_ = clk
		in := toolTrustRequestInput{
			Tenant: ttTenant, ServerID: sid, ToolName: tool,
			ExpectedFingerprint: fpHex, ExpectedCatalogRev: cat.Current().Revision(), RequestedBy: liveRequester,
		}
		tooLong := mcpToolTrust.now().Add(25 * time.Hour)
		in.ExpiresAt = &tooLong
		if _, err := mcpToolTrust.RequestLiveApproval(in); mcperr.ReasonOf(err) != mcperr.ReasonAdminRequestInvalid {
			t.Fatalf("mutation5: a >24h live TTL must be refused, got %v", mcperr.ReasonOf(err).Code())
		}
	})
	t.Run("m6_future_approved_at", func(t *testing.T) {
		now := time.Unix(1_700_000_000, 0)
		exp := now.Add(2 * time.Hour)
		tgt := canary.LiveTarget{Tenant: "t", ServerID: "s", ToolName: "n", Fingerprint: fpForTest(0x11), FingerprintFormat: 1}
		a := &tooltrust.ToolApproval{
			Purpose: tooltrust.PurposeLiveExecution, Status: tooltrust.StatusActive,
			RequestedBy: "r", ApprovedBy: "a", ApprovedAt: now.Add(time.Hour), ExpiresAt: &exp, // ApprovedAt in the future
			Tenant: "t", ServerID: "s", ToolName: "n", Fingerprint: fpForTest(0x11), FingerprintFormatVersion: 1,
		}
		if canary.SatisfiesLiveExecution(a, tgt, now) != canary.TrustApprovedInFuture {
			t.Fatal("mutation6: a future ApprovedAt must be refused")
		}
	})
	t.Run("m9_rug_pull", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		reg, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		_ = clk
		requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
		if _, _, err := cat.Ingest(reg, catalog.DiscoveryInput{
			ServerID: registry.ServerID(sid), Identity: "id",
			Raw: []byte(`{"tools":[{"name":"t","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}]}`),
		}); err != nil {
			t.Fatalf("re-ingest: %v", err)
		}
		if scopeApprovalReason(liveScope(sid, tool, fpHex)) == canary.ScopeApprovalOK {
			t.Fatal("mutation9: an F1 approval must not govern a drifted F2")
		}
	})
	t.Run("m10_revoked", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		_ = clk
		g := requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
		if _, err := mcpToolTrust.Revoke(g.ApprovalID, "sec", ttTenant, "x"); err != nil {
			t.Fatalf("revoke: %v", err)
		}
		if scopeApprovalReason(liveScope(sid, tool, fpHex)) == canary.ScopeApprovalOK {
			t.Fatal("mutation10: a revoked approval must not satisfy readiness")
		}
	})
	t.Run("m11_expired", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
		clk.advance(2 * time.Hour) // past the 1h TTL
		if scopeApprovalReason(liveScope(sid, tool, fpHex)) == canary.ScopeApprovalOK {
			t.Fatal("mutation11: an expired approval must not satisfy readiness")
		}
	})
	t.Run("m12_wrong_tenant", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		_ = clk
		requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
		scope := liveScope(sid, tool, fpHex)
		scope.Tenants = []string{"foreign-tenant"}
		if scopeApprovalReason(scope) == canary.ScopeApprovalOK {
			t.Fatal("mutation12: a wrong-tenant approval must not satisfy a scope")
		}
	})
	t.Run("m13_one_approval_two_tools", func(t *testing.T) {
		resetInventory(t)
		clk, fn := liveFakeClock()
		inv := seedToolTrustInventory2(t)
		composeToolTrust(t, fn)
		_ = clk
		requestAndApproveLive(t, inv.serverID, inv.toolA, inv.fpA, inv.cat.Current().Revision())
		scope := rollout.ScopeSpec{
			Capability: rollout.CapabilityGateway, Tenants: []string{ttTenant}, Servers: []string{inv.serverID},
			Tools: []rollout.ToolSel{
				{Server: inv.serverID, Name: inv.toolA, Fingerprint: inv.fpA},
				{Server: inv.serverID, Name: inv.toolB, Fingerprint: inv.fpB},
			},
			Operations: []rollout.RiskClass{rollout.RiskRead},
		}
		if scopeApprovalReason(scope) == canary.ScopeApprovalOK {
			t.Fatal("mutation13: one approval must not cover two scoped tools")
		}
	})
	t.Run("m15_issuance_arms_nothing", func(t *testing.T) {
		resetInventory(t)
		resetExecDeps(t)
		clk, fn := liveFakeClock()
		_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
		composeToolTrust(t, fn)
		_ = clk
		requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
		if liveExecDepsConfigured(false) {
			t.Fatal("mutation15: issuing a live approval must not arm the live tier")
		}
	})
}

// fpForTest builds a deterministic 32-byte fingerprint digest of a single repeated byte.
func fpForTest(b byte) tooltrust.FingerprintDigest {
	var d tooltrust.FingerprintDigest
	for i := range d {
		d[i] = b
	}
	return d
}

// hexOf is a tiny local hex helper so this file needs no encoding/hex import churn.
func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
