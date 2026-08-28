package main

import (
	"encoding/hex"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// ── harness ──────────────────────────────────────────────────────────────────

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

// composeToolTrust composes the coordinator against a temp data dir with the given
// clock (nil ⇒ real time). It isolates the process-global singleton for the test.
func composeToolTrust(t *testing.T, clk func() time.Time) {
	t.Helper()
	resetMCPToolTrustForTest()
	t.Cleanup(resetMCPToolTrustForTest)
	dir := t.TempDir()
	store, err := tooltrust.NewStore(tooltrust.Config{Path: filepath.Join(dir, "mcp_tooltrust", "approvals.json"), Clock: clk})
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

// live_execution is refused at issue (the firewall's negative half, mutation #10).
func TestToolTrust_LiveExecutionPurposeRefusedAtIssue(t *testing.T) {
	resetInventory(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	in := toolTrustRequestInput{
		Tenant: ttTenant, ServerID: sid, ToolName: tool,
		ExpectedFingerprint: fpHex, ExpectedCatalogRev: cat.Current().Revision(),
		Purpose: tooltrust.PurposeLiveExecution, RequestedBy: "operator@corp",
	}
	_, err := mcpToolTrust.RequestApproval(in)
	if mcperr.ReasonOf(err) != mcperr.ReasonApprovalPurposeUnsupported {
		t.Fatalf("live_execution must be refused at issue, got %v", mcperr.ReasonOf(err).Code())
	}
}

// ── crash / restart recovery (Sec 13, D3) ─────────────────────────────────────

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

// ── revocation demotes immediately (Sec 8) ─────────────────────────────────────

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

// ── HTTP RBAC / tenant scope on the admin routes ──────────────────────────────

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

// ── coordinator not composed ⇒ fail closed ────────────────────────────────────

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
