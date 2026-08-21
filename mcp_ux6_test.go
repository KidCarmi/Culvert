package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// PR-UX-6 backend contracts for the truthful Production Qualification evidence read
// model. These pin: origin handling (production/synthetic/unset), the typed
// requirement states (met/not_met/not_started/synthetic_non_qualifying/
// not_applicable), server-side elapsed with clamping and not-started-vs-zero
// distinction, exact-boundary semantics, the no-qualification-claim invariant, and
// the read-only handler (capability isolation + no mutation).

var ux6Now = time.Unix(1_000_000_000, 0)

func daysAgo(d int) int64 { return ux6Now.Unix() - int64(d)*24*3600 }

func ux6DTO(ev rollout.EvidenceSummary) mcpEvidenceDTO {
	return buildMCPEvidenceDTO("gateway", "shadow", ev, ux6Now, ux6Now.UnixNano())
}

// TestMCPUX6_Evidence_NotStartedProduction proves the shipped disabled-default
// posture: production origin, no windows started -> every window is not_started
// (never a benign zero-percent "met"), zero-defect is met (0 recorded), rehearsal is
// not_met, false-positive is not_applicable, and Production stays locked.
func TestMCPUX6_Evidence_NotStartedProduction(t *testing.T) {
	dto := ux6DTO(rollout.EvidenceSummary{Origin: rollout.OriginProduction})
	if dto.Origin != "production" {
		t.Fatalf("origin = %q, want production", dto.Origin)
	}
	if dto.ShadowState != mcpReqNotStarted || dto.CanaryState != mcpReqNotStarted || dto.SoakState != mcpReqNotStarted {
		t.Fatalf("windows not not_started: shadow=%s canary=%s soak=%s", dto.ShadowState, dto.CanaryState, dto.SoakState)
	}
	if dto.ZeroDefectState != mcpReqMet {
		t.Fatalf("zero_defect_state = %s, want met (0 defects)", dto.ZeroDefectState)
	}
	if dto.RollbackRehearsalState != mcpReqNotMet {
		t.Fatalf("rehearsal state = %s, want not_met", dto.RollbackRehearsalState)
	}
	if !dto.ProductionLocked || !strings.Contains(dto.ProductionLockMessage, "Production locked") {
		t.Fatalf("production must be locked with message, got %+v", dto.ProductionLockMessage)
	}
	// Summary: 3 not_started + zero_defect met + rehearsal not_met = 5 measured;
	// false_positive is not_applicable and excluded.
	s := dto.Summary
	if s.MeasuredTotal != 5 || s.NotStarted != 3 || s.Met != 1 || s.NotMet != 1 || s.SyntheticNonQualifying != 0 {
		t.Fatalf("summary wrong: %+v", s)
	}
}

// TestMCPUX6_Evidence_WindowBoundaries proves server-side elapsed semantics: a start
// exactly at the floor is met, below is not_met, a future start clamps to zero
// elapsed and is not_met (started) - distinct from not_started (no start).
func TestMCPUX6_Evidence_WindowBoundaries(t *testing.T) {
	// Exactly 14d shadow -> met.
	if got := ux6DTO(rollout.EvidenceSummary{Origin: rollout.OriginProduction, ShadowStartUnix: daysAgo(14)}).ShadowState; got != mcpReqMet {
		t.Fatalf("shadow at exactly target = %s, want met", got)
	}
	// 13d shadow -> not_met.
	if got := ux6DTO(rollout.EvidenceSummary{Origin: rollout.OriginProduction, ShadowStartUnix: daysAgo(13)}).ShadowState; got != mcpReqNotMet {
		t.Fatalf("shadow below target = %s, want not_met", got)
	}
	// Future start (negative delta) clamps to zero elapsed; started so not_met, not not_started.
	future := ux6DTO(rollout.EvidenceSummary{Origin: rollout.OriginProduction, ShadowStartUnix: ux6Now.Unix() + 3600})
	if future.ShadowState != mcpReqNotMet {
		t.Fatalf("future-start shadow = %s, want not_met (clamped)", future.ShadowState)
	}
	if future.ShadowElapsedSeconds != 0 {
		t.Fatalf("future-start elapsed = %d, want 0 (clamped)", future.ShadowElapsedSeconds)
	}
}

// TestMCPUX6_Evidence_SyntheticNonQualifying proves a synthetic-origin window that
// meets the target is NEVER reported as met: it is synthetic_non_qualifying.
func TestMCPUX6_Evidence_SyntheticNonQualifying(t *testing.T) {
	dto := ux6DTO(rollout.EvidenceSummary{Origin: rollout.OriginSynthetic, ShadowStartUnix: daysAgo(30), SoakStartUnix: daysAgo(2)})
	if dto.Origin != "synthetic" {
		t.Fatalf("origin = %q, want synthetic", dto.Origin)
	}
	if dto.ShadowState != mcpReqSyntheticNonQualifying {
		t.Fatalf("synthetic shadow past target = %s, want synthetic_non_qualifying", dto.ShadowState)
	}
	if dto.SoakState != mcpReqSyntheticNonQualifying {
		t.Fatalf("synthetic soak past target = %s, want synthetic_non_qualifying", dto.SoakState)
	}
	if dto.Summary.SyntheticNonQualifying < 2 {
		t.Fatalf("summary must count synthetic non-qualifying: %+v", dto.Summary)
	}
	// No clock-window requirement may be counted met under a synthetic clock (the
	// zero-defect count requirement is not clock-based and may still be met).
	for _, req := range dto.Requirements {
		if strings.HasSuffix(req.Key, "_window") && req.State == mcpReqMet {
			t.Fatalf("synthetic window %q must never be met: %+v", req.Key, req)
		}
	}
}

// TestMCPUX6_Evidence_DefectsAndRehearsal proves the count/bool requirements report
// their real measured state and that false-positive reviews are not_applicable (no
// invented threshold).
func TestMCPUX6_Evidence_DefectsAndRehearsal(t *testing.T) {
	dto := ux6DTO(rollout.EvidenceSummary{Origin: rollout.OriginProduction, OpenCriticalHighDefects: 3, RollbackRehearsed: true, FalsePositiveReviews: 7})
	if dto.ZeroDefectState != mcpReqNotMet {
		t.Fatalf("zero_defect_state with 3 open = %s, want not_met", dto.ZeroDefectState)
	}
	if dto.RollbackRehearsalState != mcpReqMet {
		t.Fatalf("rehearsal state = %s, want met", dto.RollbackRehearsalState)
	}
	if dto.FalsePositiveReviews != 7 {
		t.Fatalf("false_positive_reviews = %d, want 7", dto.FalsePositiveReviews)
	}
	// The false-positive requirement row is not_applicable and excluded from measured.
	for _, req := range dto.Requirements {
		if req.Key == "false_positive_reviews" && req.State != mcpReqNotApplicable {
			t.Fatalf("false_positive requirement state = %s, want not_applicable", req.State)
		}
	}
}

// TestMCPUX6_Evidence_NoQualificationClaim proves the read model never asserts an
// overall qualification, GO, or percentage, and always surfaces the lock.
func TestMCPUX6_Evidence_NoQualificationClaim(t *testing.T) {
	// A fully "met" measured set must still keep Production locked and claim nothing.
	dto := ux6DTO(rollout.EvidenceSummary{
		Origin: rollout.OriginProduction, ShadowStartUnix: daysAgo(30), CanaryStartUnix: daysAgo(10),
		SoakStartUnix: daysAgo(2), RollbackRehearsed: true,
	})
	if dto.ShadowState != mcpReqMet || dto.CanaryState != mcpReqMet || dto.SoakState != mcpReqMet {
		t.Fatalf("expected all windows met: %s/%s/%s", dto.ShadowState, dto.CanaryState, dto.SoakState)
	}
	if !dto.ProductionLocked {
		t.Fatal("Production must remain locked even when every measured requirement is met")
	}
	blob := strings.ToLower(mustJSON(t, dto))
	for _, forbidden := range []string{`"go"`, "qualified", "production ready", "unlock available", "approved for production", "% qualified"} {
		if strings.Contains(blob, forbidden) {
			t.Fatalf("evidence must not claim qualification, found %q in %s", forbidden, blob)
		}
	}
	// The as-of value is echoed deterministically (never a browser clock).
	if dto.AsOfUnixNano != ux6Now.UnixNano() {
		t.Fatalf("as_of not echoed: got %d", dto.AsOfUnixNano)
	}
}

// TestMCPUX6_ApprovalListsReadContract pins the read contract the unified approvals
// list depends on: a viewer may read BOTH the operational and publication lists
// (tenant-scoped), the tenant is required, and decisions stay admin-only (the UI
// combines the two lists client-side, so both must be independently readable).
func TestMCPUX6_ApprovalListsReadContract(t *testing.T) {
	for _, path := range []string{"/api/mcp/approvals?tenant=acme", "/api/mcp/publications?tenant=acme"} {
		if got := mcpReq(http.MethodGet, path, RoleViewer, "").Code; got != http.StatusOK {
			t.Fatalf("viewer GET %s = %d, want 200", path, got)
		}
	}
	// Tenant is required (no cross-tenant/global read).
	if got := mcpReq(http.MethodGet, "/api/mcp/approvals", RoleViewer, "").Code; got == http.StatusOK {
		t.Fatalf("approvals GET without tenant must not be 200")
	}
	if got := mcpReq(http.MethodGet, "/api/mcp/publications", RoleViewer, "").Code; got == http.StatusOK {
		t.Fatalf("publications GET without tenant must not be 200")
	}
	// Decisions remain admin-only (defense-in-depth beyond the durability gate).
	if got := mcpReq(http.MethodPost, "/api/mcp/approval-decision", RoleViewer, `{"request_id":"x","tenant":"acme","action":"approve"}`).Code; got != http.StatusForbidden {
		t.Fatalf("viewer approval-decision = %d, want 403", got)
	}
}

// TestMCPUX6_EvidenceHandler proves the endpoint is viewer-readable, GET-only,
// capability-isolated, and performs NO mutation on a read.
func TestMCPUX6_EvidenceHandler(t *testing.T) {
	// Seed a distinct rehearsal marker on management, then confirm a GET never flips it.
	getMCPRollout().stateFor(rollout.CapabilityManagement).UpdateEvidence(func(e *rollout.EvidenceSummary) { e.RollbackRehearsed = false })
	before := getMCPRollout().stateFor(rollout.CapabilityGateway).Evidence()

	rec := mcpReq(http.MethodGet, "/api/mcp/rollout/evidence?capability=gateway", RoleViewer, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("viewer GET evidence = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`"capability":"gateway"`, `"production_locked":true`, `"requirements"`, `"summary"`, `"shadow_state"`, `"unsupported_categories"`, `"as_of_unix_nano"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("evidence body missing %q: %s", want, body)
		}
	}
	// Capability isolation: management is a distinct read.
	m := mcpReq(http.MethodGet, "/api/mcp/rollout/evidence?capability=management", RoleViewer, "").Body.String()
	if !strings.Contains(m, `"capability":"management"`) {
		t.Fatalf("management evidence not capability-bound: %s", m)
	}
	// No mutation: the GET must not have changed gateway evidence.
	after := getMCPRollout().stateFor(rollout.CapabilityGateway).Evidence()
	if before != after {
		t.Fatalf("evidence GET mutated state: before=%+v after=%+v", before, after)
	}
	if got := mcpReq(http.MethodPost, "/api/mcp/rollout/evidence", RoleAdmin, "").Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("POST evidence = %d, want 405", got)
	}
}
