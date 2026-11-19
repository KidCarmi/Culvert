package evidenceview

import (
	"encoding/json"
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

func ux6DTO(ev rollout.EvidenceSummary) View {
	return Build("gateway", "shadow", ev, ux6Now, ux6Now.UnixNano())
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
	if dto.ShadowState != stateNotStarted || dto.CanaryState != stateNotStarted || dto.SoakState != stateNotStarted {
		t.Fatalf("windows not not_started: shadow=%s canary=%s soak=%s", dto.ShadowState, dto.CanaryState, dto.SoakState)
	}
	if dto.ZeroDefectState != stateMet {
		t.Fatalf("zero_defect_state = %s, want met (0 defects)", dto.ZeroDefectState)
	}
	if dto.RollbackRehearsalState != stateNotMet {
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
	if got := ux6DTO(rollout.EvidenceSummary{Origin: rollout.OriginProduction, ShadowStartUnix: daysAgo(14)}).ShadowState; got != stateMet {
		t.Fatalf("shadow at exactly target = %s, want met", got)
	}
	// 13d shadow -> not_met.
	if got := ux6DTO(rollout.EvidenceSummary{Origin: rollout.OriginProduction, ShadowStartUnix: daysAgo(13)}).ShadowState; got != stateNotMet {
		t.Fatalf("shadow below target = %s, want not_met", got)
	}
	// Future start (negative delta) clamps to zero elapsed; started so not_met, not not_started.
	future := ux6DTO(rollout.EvidenceSummary{Origin: rollout.OriginProduction, ShadowStartUnix: ux6Now.Unix() + 3600})
	if future.ShadowState != stateNotMet {
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
	if dto.ShadowState != stateSyntheticNonQualifying {
		t.Fatalf("synthetic shadow past target = %s, want synthetic_non_qualifying", dto.ShadowState)
	}
	if dto.SoakState != stateSyntheticNonQualifying {
		t.Fatalf("synthetic soak past target = %s, want synthetic_non_qualifying", dto.SoakState)
	}
	if dto.Summary.SyntheticNonQualifying < 2 {
		t.Fatalf("summary must count synthetic non-qualifying: %+v", dto.Summary)
	}
	// No clock-window requirement may be counted met under a synthetic clock (the
	// zero-defect count requirement is not clock-based and may still be met).
	for _, req := range dto.Requirements {
		if strings.HasSuffix(req.Key, "_window") && req.State == stateMet {
			t.Fatalf("synthetic window %q must never be met: %+v", req.Key, req)
		}
	}
}

// TestMCPUX6_Evidence_DefectsAndRehearsal proves the count/bool requirements report
// their real measured state and that false-positive reviews are not_applicable (no
// invented threshold).
func TestMCPUX6_Evidence_DefectsAndRehearsal(t *testing.T) {
	dto := ux6DTO(rollout.EvidenceSummary{Origin: rollout.OriginProduction, OpenCriticalHighDefects: 3, RollbackRehearsed: true, FalsePositiveReviews: 7})
	if dto.ZeroDefectState != stateNotMet {
		t.Fatalf("zero_defect_state with 3 open = %s, want not_met", dto.ZeroDefectState)
	}
	if dto.RollbackRehearsalState != stateMet {
		t.Fatalf("rehearsal state = %s, want met", dto.RollbackRehearsalState)
	}
	if dto.FalsePositiveReviews != 7 {
		t.Fatalf("false_positive_reviews = %d, want 7", dto.FalsePositiveReviews)
	}
	// The false-positive requirement row is not_applicable and excluded from measured.
	for _, req := range dto.Requirements {
		if req.Key == "false_positive_reviews" && req.State != stateNotApplicable {
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
	if dto.ShadowState != stateMet || dto.CanaryState != stateMet || dto.SoakState != stateMet {
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
