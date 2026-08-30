package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// PR-UX-4 handler-level guarantees for the standardized MCP dangerous-action
// surface. The UI dialog is proven in the uie2e Playwright suite; these tests pin
// the server-side contracts the dialog depends on: RBAC, capability parsing +
// isolation, the truthful production lock / not-configured responses, and the
// rehearsal evidence flag. They never assert a fabricated success.

// clearMCPKillSwitches resets the process-wide rollout singleton's kill switches
// so an emergency-disable test cannot leak state into another test under
// -shuffle. Evidence flags are node-local and harmless to leave set.
func clearMCPKillSwitches(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		getMCPRollout().clearEmergency(rollout.CapabilityGateway)
		getMCPRollout().clearEmergency(rollout.CapabilityManagement)
	})
}

func TestMCPUX4_EmergencyDisableRBAC(t *testing.T) {
	clearMCPKillSwitches(t)
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		if got := mcpReq(http.MethodPost, "/api/mcp/rollout/emergency", role, `{"capability":"gateway","action":"disable"}`).Code; got != http.StatusForbidden {
			t.Fatalf("%s POST emergency = %d, want 403", role, got)
		}
	}
	// GET is not allowed on the emergency endpoint.
	if got := mcpReq(http.MethodGet, "/api/mcp/rollout/emergency", RoleAdmin, "").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET emergency = %d, want 405", got)
	}
}

func TestMCPUX4_EmergencyDisableAndClear(t *testing.T) {
	clearMCPKillSwitches(t)
	// Admin disable engages the gateway kill switch and returns the real killed state.
	rec := mcpReq(http.MethodPost, "/api/mcp/rollout/emergency", RoleAdmin, `{"capability":"gateway","action":"disable"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin disable = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"killed":true`) {
		t.Fatalf("disable response must report killed=true: %s", rec.Body.String())
	}
	if !getMCPRollout().stateFor(rollout.CapabilityGateway).Killed() {
		t.Fatal("gateway kill switch must be engaged after disable")
	}
	// Capability isolation: management must be untouched by a gateway disable.
	if getMCPRollout().stateFor(rollout.CapabilityManagement).Killed() {
		t.Fatal("gateway disable must not engage the management kill switch")
	}
	// Clear restores admission and reports killed=false.
	rec = mcpReq(http.MethodPost, "/api/mcp/rollout/emergency", RoleAdmin, `{"capability":"gateway","action":"clear"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"killed":false`) {
		t.Fatalf("clear = %d body=%s, want 200 killed=false", rec.Code, rec.Body.String())
	}
	if getMCPRollout().stateFor(rollout.CapabilityGateway).Killed() {
		t.Fatal("gateway kill switch must be released after clear")
	}
}

func TestMCPUX4_EmergencyManagementIsolatedFromGateway(t *testing.T) {
	clearMCPKillSwitches(t)
	// Disabling management must never touch gateway.
	if got := mcpReq(http.MethodPost, "/api/mcp/rollout/emergency", RoleAdmin, `{"capability":"management","action":"disable"}`).Code; got != http.StatusOK {
		t.Fatalf("management disable = %d, want 200", got)
	}
	if !getMCPRollout().stateFor(rollout.CapabilityManagement).Killed() {
		t.Fatal("management kill switch must be engaged")
	}
	if getMCPRollout().stateFor(rollout.CapabilityGateway).Killed() {
		t.Fatal("management disable must not engage the gateway kill switch (isolation)")
	}
}

func TestMCPUX4_EmergencyInvalidCapability(t *testing.T) {
	clearMCPKillSwitches(t)
	rec := mcpReq(http.MethodPost, "/api/mcp/rollout/emergency", RoleAdmin, `{"capability":"bogus","action":"disable"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "rollout_capability_invalid") {
		t.Fatalf("invalid capability = %d body=%s, want 400 rollout_capability_invalid", rec.Code, rec.Body.String())
	}
	// A present-but-invalid capability must fail closed - it must NOT fall back to
	// engaging the default (gateway) kill switch.
	if getMCPRollout().stateFor(rollout.CapabilityGateway).Killed() {
		t.Fatal("an invalid-capability request must not engage any kill switch")
	}
	// Malformed JSON is a 400 as well.
	if got := mcpReq(http.MethodPost, "/api/mcp/rollout/emergency", RoleAdmin, `{bad`).Code; got != http.StatusBadRequest {
		t.Fatalf("malformed emergency JSON = %d, want 400", got)
	}
}

func TestMCPUX4_RehearseCapabilityFromBody(t *testing.T) {
	// The rehearse endpoint now runs the real executable drill (§5), which writes durable
	// rehearsal evidence + rollout state under dataDir; confine those to a temp dir so they never
	// leak to the shared default and pollute another test's dormant-default assertions.
	withTempDataDir(t)
	pinTestBuildVersion(t) // the rehearse POST now refuses a placeholder ("dev") build stamp (Codex P2)
	// The rehearsal must record evidence for the capability named in the body
	// (parity with emergency), so a rehearsal chosen for management can never land
	// on gateway. This pins the PR-UX-4 capability-binding fix.
	before := getMCPRollout().stateFor(rollout.CapabilityGateway).Evidence().RollbackRehearsed
	rec := mcpReq(http.MethodPost, "/api/mcp/rollout/rehearse-rollback", RoleAdmin, `{"capability":"management"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("rehearse management = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"capability":"management"`) || !strings.Contains(rec.Body.String(), `"rollback_rehearsed":true`) {
		t.Fatalf("rehearse response must name management and rollback_rehearsed=true: %s", rec.Body.String())
	}
	if !getMCPRollout().stateFor(rollout.CapabilityManagement).Evidence().RollbackRehearsed {
		t.Fatal("management rehearsal evidence flag must be set")
	}
	// Isolation: a management rehearsal must not flip gateway's evidence flag.
	if got := getMCPRollout().stateFor(rollout.CapabilityGateway).Evidence().RollbackRehearsed; got != before {
		t.Fatalf("management rehearsal changed gateway evidence flag (before=%v after=%v)", before, got)
	}
}

func TestMCPUX4_RehearseRBACAndValidation(t *testing.T) {
	withTempDataDir(t)     // the admin rehearse below runs the real drill, which writes under dataDir
	pinTestBuildVersion(t) // the admin 200 case requires a non-placeholder build stamp (Codex P2)
	// Viewer/operator may not record a rehearsal (admin only).
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		if got := mcpReq(http.MethodPost, "/api/mcp/rollout/rehearse-rollback", role, `{"capability":"gateway"}`).Code; got != http.StatusForbidden {
			t.Fatalf("%s POST rehearse = %d, want 403", role, got)
		}
	}
	// An invalid capability in the body fails closed with 400.
	if got := mcpReq(http.MethodPost, "/api/mcp/rollout/rehearse-rollback", RoleAdmin, `{"capability":"bogus"}`).Code; got != http.StatusBadRequest {
		t.Fatalf("rehearse invalid capability = %d, want 400", got)
	}
	// An empty body still works (back-compat: falls back to the query capability).
	if got := mcpReq(http.MethodPost, "/api/mcp/rollout/rehearse-rollback?capability=gateway", RoleAdmin, "").Code; got != http.StatusOK {
		t.Fatalf("rehearse empty body = %d, want 200", got)
	}
}

// TestMCPUX4_RehearseChunkedBodylessPOST pins the Codex-P2 fix: a bodyless POST
// sent with chunked transfer encoding has ContentLength == -1, which must NOT be
// misread as a malformed body. The empty body decodes to io.EOF and falls back to
// the query-string capability (here: management), returning 200 — not a 400.
func TestMCPUX4_RehearseChunkedBodylessPOST(t *testing.T) {
	withTempDataDir(t)     // the rehearse below runs the real drill, which writes under dataDir
	pinTestBuildVersion(t) // the rehearse POST now refuses a placeholder ("dev") build stamp (Codex P2)
	r := httptest.NewRequest(http.MethodPost, "/api/mcp/rollout/rehearse-rollback?capability=management", http.NoBody)
	r.ContentLength = -1 // simulate chunked transfer encoding (no Content-Length)
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerMCPRoutes(mux)
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("chunked bodyless rehearse = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"capability":"management"`) {
		t.Fatalf("chunked bodyless rehearse must honor the query capability: %s", w.Body.String())
	}
}

// TestMCPUX4_RehearseRefusesUnversionedBuild pins the Codex P2 fix: the rehearse POST must refuse a
// placeholder/non-unique build stamp with 409 and write NO rehearsal record — rather than report
// rollback_rehearsed:true/persisted:true for a record ValidateRehearsal rejects on read (which would
// leave the activation gate rollback_path_unhealthy). Analogous to the Shadow Exit review POST's
// uniquely-versioned-build guard.
func TestMCPUX4_RehearseRefusesUnversionedBuild(t *testing.T) {
	withTempDataDir(t)
	prevVer := version
	version = "dev" // a placeholder stamp ⇒ currentRuntimeIdentity().Valid() is false
	// The rollback-rehearsed evidence flag is process-global and other tests leave it set
	// (documented as node-local + harmless), so swap in a fresh singleton to assert the flag
	// stays false here rather than reading leaked state.
	_ = getMCPRollout()
	prevR := globalMCPRollout
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	t.Cleanup(func() { version = prevVer; globalMCPRollout = prevR })

	rec := mcpReq(http.MethodPost, "/api/mcp/rollout/rehearse-rollback", RoleAdmin, `{"capability":"gateway"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("rehearse on an unversioned build = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "rollback_rehearsal_requires_a_uniquely_versioned_build") {
		t.Fatalf("409 body must name the uniquely-versioned-build requirement: %s", rec.Body.String())
	}
	// A refused rehearsal must write NO durable record and leave the evidence flag false.
	if _, err := os.Stat(rollbackRehearsalPath(rollout.CapabilityGateway)); !os.IsNotExist(err) {
		t.Fatal("a refused rehearsal must not write a durable record")
	}
	if getMCPRollout().stateFor(rollout.CapabilityGateway).Evidence().RollbackRehearsed {
		t.Fatal("a refused rehearsal must not set the evidence flag")
	}
}

func TestMCPUX4_TransitionProductionLockedAndNotConfigured(t *testing.T) {
	// Production always fails closed with rollout_production_locked (403), never a
	// fake acceptance.
	rec := mcpReq(http.MethodPost, "/api/mcp/rollout/transition", RoleAdmin, `{"capability":"gateway","to_mode":"production"}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "rollout_production_locked") {
		t.Fatalf("transition to production = %d body=%s, want 403 rollout_production_locked", rec.Code, rec.Body.String())
	}
	// An executing-mode transition (canary/shadow) in the shipped Observe-only
	// composition fails closed at the execution-dependency precondition — the truthful
	// blocker the operator must see before any distribution concern.
	rec = mcpReq(http.MethodPost, "/api/mcp/rollout/transition", RoleAdmin, `{"capability":"gateway","to_mode":"canary"}`)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "shadow_execution_dependencies_not_configured") {
		t.Fatalf("transition to canary = %d body=%s, want 409 shadow_execution_dependencies_not_configured", rec.Code, rec.Body.String())
	}
	// A non-executing transition (Observe) reaches the signed-distribution gate, which
	// is not wired in the disabled-default posture: truthful 409 distribution_not_configured.
	rec = mcpReq(http.MethodPost, "/api/mcp/rollout/transition", RoleAdmin, `{"capability":"gateway","to_mode":"observe"}`)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "distribution_not_configured") {
		t.Fatalf("transition to observe = %d body=%s, want 409 distribution_not_configured", rec.Code, rec.Body.String())
	}
	// An invalid target mode is a 400.
	if got := mcpReq(http.MethodPost, "/api/mcp/rollout/transition", RoleAdmin, `{"capability":"gateway","to_mode":"bogus"}`).Code; got != http.StatusBadRequest {
		t.Fatalf("transition invalid mode = %d, want 400", got)
	}
	// Viewer may not request a transition.
	if got := mcpReq(http.MethodPost, "/api/mcp/rollout/transition", RoleViewer, `{"capability":"gateway","to_mode":"canary"}`).Code; got != http.StatusForbidden {
		t.Fatalf("viewer transition = %d, want 403", got)
	}
}

// TestMCPUX4_RollbackNoFabrication re-asserts (from the PR-UX-4 perspective) that
// the rollback endpoint never fabricates a rollback: it needs a target, admin
// role, and returns a truthful 409 when distribution is not configured. The UI
// binds the exact retained target and disables submit when none exists; the
// server is the backstop.
func TestMCPUX4_RollbackNoFabrication(t *testing.T) {
	// Missing target hash ⇒ 400 (the UI never submits without a bound target).
	if got := mcpReq(http.MethodPost, "/api/mcp/rollback", RoleAdmin, `{"capability":"gateway"}`).Code; got != http.StatusBadRequest {
		t.Fatalf("rollback without target = %d, want 400", got)
	}
	// With a target but no configured distribution ⇒ truthful 409, never a fake success.
	rec := mcpReq(http.MethodPost, "/api/mcp/rollback", RoleAdmin, `{"capability":"gateway","target_hash":"sha256:deadbeef"}`)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "distribution_not_configured") {
		t.Fatalf("rollback (disabled) = %d body=%s, want 409 distribution_not_configured", rec.Code, rec.Body.String())
	}
}
