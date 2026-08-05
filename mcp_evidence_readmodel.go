package main

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// PR-UX-6 Production Qualification evidence read model.
//
// Truth model: this is a REPORTING projection over the real rollout.EvidenceSummary.
// It never asserts Production qualification (this build ships no qualification
// issuer or verifier, so Production is permanently locked), never mutates evidence
// on a read, never converts synthetic origin into production origin, and never marks
// a synthetic clock-window as qualifying. Elapsed durations are computed on the
// SERVER with the real rollout clock semantics (rollout.EvidenceSummary.*Elapsed,
// which clamps negative to zero and treats a zero start as zero elapsed); the
// browser only formats the server value.
//
// At runtime the only evidence field with a write path is RollbackRehearsed (via the
// rehearse-rollback endpoint); windows are never stamped, defect/review counters
// never move, and origin stays production (the seed). A truthful UI therefore shows
// unmeasured windows as not_started rather than implying measured evidence.

// mcpReqState is the typed state of a single measured evidence requirement. The
// distinctions are load-bearing: not_started (no window began) is not the same as
// not_met (window began but is below floor), synthetic_non_qualifying (measured on
// an injected/test clock, can never qualify) is not the same as met, and unavailable
// (the evidence could not be read) is not the same as not_met.
type mcpReqState string

const (
	mcpReqMet                    mcpReqState = "met"
	mcpReqNotMet                 mcpReqState = "not_met"
	mcpReqNotStarted             mcpReqState = "not_started"
	mcpReqSyntheticNonQualifying mcpReqState = "synthetic_non_qualifying"
	mcpReqUnavailable            mcpReqState = "unavailable"
	mcpReqNotApplicable          mcpReqState = "not_applicable"
)

// mcpEvidenceRequirement is one row of the measured-requirement list. Only
// requirements backed by a real runtime source appear here. Window requirements
// carry measured/target seconds + a start unix; count requirements carry a count.
type mcpEvidenceRequirement struct {
	Key             string      `json:"key"`
	Label           string      `json:"label"`
	State           mcpReqState `json:"state"`
	Origin          string      `json:"origin"`
	MeasuredSeconds *int64      `json:"measured_seconds,omitempty"`
	TargetSeconds   *int64      `json:"target_seconds,omitempty"`
	StartUnix       int64       `json:"start_unix,omitempty"`
	Count           *int        `json:"count,omitempty"`
	NextAction      string      `json:"next_action"`
}

// mcpEvidenceSummaryCounts is the safe tally over the measured requirements. It is
// deliberately NOT a qualification decision and carries no percentage.
type mcpEvidenceSummaryCounts struct {
	MeasuredTotal          int `json:"measured_total"`
	Met                    int `json:"met"`
	NotMet                 int `json:"not_met"`
	NotStarted             int `json:"not_started"`
	SyntheticNonQualifying int `json:"synthetic_non_qualifying"`
	Unavailable            int `json:"unavailable"`
}

// mcpEvidenceDTO is the capability-scoped evidence read model. It is a superset of
// the original evidence response (the original keys are retained verbatim for
// backward compatibility) plus the additive read model.
type mcpEvidenceDTO struct {
	Capability            string `json:"capability"`
	Mode                  string `json:"mode"`
	ProductionLocked      bool   `json:"production_locked"`
	ProductionLockMessage string `json:"production_lock_message"`
	LockReason            string `json:"lock_reason"`
	Origin                string `json:"origin"`
	AsOfUnixNano          int64  `json:"as_of_unix_nano"`

	// Window details (also represented in Requirements; kept flat for convenience).
	ShadowStartUnix      int64       `json:"shadow_start_unix"`
	ShadowElapsedSeconds int64       `json:"shadow_elapsed_seconds"`
	ShadowTargetSeconds  int64       `json:"shadow_target_seconds"`
	ShadowState          mcpReqState `json:"shadow_state"`
	CanaryStartUnix      int64       `json:"canary_start_unix"`
	CanaryElapsedSeconds int64       `json:"canary_elapsed_seconds"`
	CanaryTargetSeconds  int64       `json:"canary_target_seconds"`
	CanaryState          mcpReqState `json:"canary_state"`
	SoakStartUnix        int64       `json:"soak_start_unix"`
	SoakElapsedSeconds   int64       `json:"soak_elapsed_seconds"`
	SoakTargetSeconds    int64       `json:"soak_target_seconds"`
	SoakState            mcpReqState `json:"soak_state"`

	OpenCriticalHigh       int         `json:"open_critical_high"`
	ZeroDefectState        mcpReqState `json:"zero_defect_state"`
	RollbackRehearsed      bool        `json:"rollback_rehearsed"`
	RollbackRehearsalState mcpReqState `json:"rollback_rehearsal_state"`
	FalsePositiveReviews   int         `json:"false_positive_reviews"`

	// Backward-compatible target-hours keys from the original response.
	ShadowWindowTargetH int `json:"shadow_window_target_h"`
	CanaryWindowTargetH int `json:"canary_window_target_h"`
	SoakTargetH         int `json:"soak_target_h"`

	Requirements []mcpEvidenceRequirement `json:"requirements"`
	Summary      mcpEvidenceSummaryCounts `json:"summary"`

	// UnsupportedCategories are broader Production Qualification categories that are
	// NOT represented by any runtime evidence source. They are listed so the UI can
	// state "Not represented by this runtime evidence source" - never passed/failed.
	UnsupportedCategories []string `json:"unsupported_categories"`
}

// mcpUnsupportedQualificationCategories are the broader Production Qualification
// categories with no runtime evidence source in this build. They are reported as
// "not represented" - never as passed, failed, pending, or complete.
var mcpUnsupportedQualificationCategories = []string{
	"Signed SBOM",
	"Build provenance",
	"Privacy review",
	"Support readiness",
	"Operations readiness",
	"Incident-response exercise",
	"Documentation signoff",
	"External penetration testing",
	"Release approval",
	"SLO achievement",
}

// windowReqState classifies a clock-window requirement truthfully. A window that
// never began is not_started (never a zero-percent "met"); a window measured on a
// synthetic/injected clock is synthetic_non_qualifying regardless of elapsed (a
// synthetic figure can never qualify, so it is never reported as met); otherwise it
// is met iff the continuous elapsed time has reached the floor.
func windowReqState(startUnix int64, elapsed, target time.Duration, origin rollout.EvidenceOrigin) mcpReqState {
	if startUnix == 0 {
		return mcpReqNotStarted
	}
	if origin == rollout.OriginSynthetic {
		return mcpReqSyntheticNonQualifying
	}
	if elapsed >= target {
		return mcpReqMet
	}
	return mcpReqNotMet
}

func secs(d time.Duration) int64 { return int64(d / time.Second) }
func i64ptr(v int64) *int64      { return &v }
func intptr(v int) *int          { return &v }

// buildMCPEvidenceDTO builds the read model from a real EvidenceSummary at now. It
// is pure and performs NO mutation. now must be the server's real clock (time.Now())
// so window elapsed uses production clock semantics.
func buildMCPEvidenceDTO(capability, mode string, ev rollout.EvidenceSummary, now time.Time, nowNano int64) mcpEvidenceDTO {
	shadowElapsed := ev.ShadowElapsed(now)
	canaryElapsed := ev.CanaryElapsed(now)
	soakElapsed := ev.SoakElapsed(now)
	shadowState := windowReqState(ev.ShadowStartUnix, shadowElapsed, rollout.ShadowWindowTarget, ev.Origin)
	canaryState := windowReqState(ev.CanaryStartUnix, canaryElapsed, rollout.CanaryWindowTarget, ev.Origin)
	soakState := windowReqState(ev.SoakStartUnix, soakElapsed, rollout.SoakTarget, ev.Origin)

	// Count/bool requirements are not clock-based, so a synthetic clock does not
	// taint them; they report their real measured state.
	zeroDefectState := mcpReqMet
	if ev.OpenCriticalHighDefects > 0 {
		zeroDefectState = mcpReqNotMet
	}
	rehearsalState := mcpReqNotMet
	if ev.RollbackRehearsed {
		rehearsalState = mcpReqMet
	}

	dto := mcpEvidenceDTO{
		Capability:            capability,
		Mode:                  mode,
		ProductionLocked:      true,
		ProductionLockMessage: "Production locked - external qualification required",
		LockReason:            "External qualification required: this build ships no qualification issuer or verifier, so Production is unreachable. No config, env, CLI, API, or GUI control can bypass it.",
		Origin:                ev.Origin.String(),
		AsOfUnixNano:          nowNano,

		ShadowStartUnix:      ev.ShadowStartUnix,
		ShadowElapsedSeconds: secs(shadowElapsed),
		ShadowTargetSeconds:  secs(rollout.ShadowWindowTarget),
		ShadowState:          shadowState,
		CanaryStartUnix:      ev.CanaryStartUnix,
		CanaryElapsedSeconds: secs(canaryElapsed),
		CanaryTargetSeconds:  secs(rollout.CanaryWindowTarget),
		CanaryState:          canaryState,
		SoakStartUnix:        ev.SoakStartUnix,
		SoakElapsedSeconds:   secs(soakElapsed),
		SoakTargetSeconds:    secs(rollout.SoakTarget),
		SoakState:            soakState,

		OpenCriticalHigh:       ev.OpenCriticalHighDefects,
		ZeroDefectState:        zeroDefectState,
		RollbackRehearsed:      ev.RollbackRehearsed,
		RollbackRehearsalState: rehearsalState,
		FalsePositiveReviews:   ev.FalsePositiveReviews,

		ShadowWindowTargetH: int(rollout.ShadowWindowTarget.Hours()),
		CanaryWindowTargetH: int(rollout.CanaryWindowTarget.Hours()),
		SoakTargetH:         int(rollout.SoakTarget.Hours()),

		UnsupportedCategories: mcpUnsupportedQualificationCategories,
	}

	origin := ev.Origin.String()
	dto.Requirements = []mcpEvidenceRequirement{
		{
			Key: "shadow_window", Label: "Shadow window floor", State: shadowState, Origin: origin,
			MeasuredSeconds: i64ptr(secs(shadowElapsed)), TargetSeconds: i64ptr(secs(rollout.ShadowWindowTarget)),
			StartUnix: ev.ShadowStartUnix, NextAction: windowNextAction("shadow", shadowState),
		},
		{
			Key: "canary_window", Label: "Canary window floor", State: canaryState, Origin: origin,
			MeasuredSeconds: i64ptr(secs(canaryElapsed)), TargetSeconds: i64ptr(secs(rollout.CanaryWindowTarget)),
			StartUnix: ev.CanaryStartUnix, NextAction: windowNextAction("canary", canaryState),
		},
		{
			Key: "soak_window", Label: "Stable soak floor", State: soakState, Origin: origin,
			MeasuredSeconds: i64ptr(secs(soakElapsed)), TargetSeconds: i64ptr(secs(rollout.SoakTarget)),
			StartUnix: ev.SoakStartUnix, NextAction: windowNextAction("soak", soakState),
		},
		{
			Key: "zero_open_defects", Label: "Zero open critical/high defects", State: zeroDefectState, Origin: origin,
			Count: intptr(ev.OpenCriticalHighDefects), NextAction: zeroDefectNextAction(zeroDefectState),
		},
		{
			Key: "rollback_rehearsal", Label: "Rollback rehearsal recorded", State: rehearsalState, Origin: origin,
			NextAction: rehearsalNextAction(rehearsalState),
		},
		{
			// No accepted design contract defines a numeric threshold, so this is a
			// recorded count, never a pass/fail requirement.
			Key: "false_positive_reviews", Label: "Recorded false-positive reviews", State: mcpReqNotApplicable, Origin: origin,
			Count: intptr(ev.FalsePositiveReviews), NextAction: "Informational: recorded reviews (no defined threshold).",
		},
	}
	dto.Summary = summarizeMCPRequirements(dto.Requirements)
	return dto
}

// summarizeMCPRequirements tallies only the measured requirements (not_applicable
// rows are excluded from the measured total). It never produces an overall decision.
func summarizeMCPRequirements(reqs []mcpEvidenceRequirement) mcpEvidenceSummaryCounts {
	var s mcpEvidenceSummaryCounts
	for i := range reqs {
		switch reqs[i].State {
		case mcpReqNotApplicable:
			continue
		case mcpReqMet:
			s.Met++
		case mcpReqNotMet:
			s.NotMet++
		case mcpReqNotStarted:
			s.NotStarted++
		case mcpReqSyntheticNonQualifying:
			s.SyntheticNonQualifying++
		case mcpReqUnavailable:
			s.Unavailable++
		}
		s.MeasuredTotal++
	}
	return s
}

func windowNextAction(window string, state mcpReqState) string {
	switch state {
	case mcpReqNotStarted:
		switch window {
		case "shadow":
			return "Enter Shadow to begin the window."
		case "canary":
			return "Complete Shadow, then enter Canary to begin the window."
		default:
			return "The soak window begins on the next mode entry."
		}
	case mcpReqNotMet:
		switch window {
		case "shadow":
			return "Remain in Shadow until the window floor is reached."
		case "canary":
			return "Continue Canary observation until the floor is reached."
		default:
			return "Wait for the soak window to reach its floor."
		}
	case mcpReqSyntheticNonQualifying:
		return "Synthetic evidence cannot qualify Production; production-origin measurement is required."
	case mcpReqMet:
		return "Floor reached (does not qualify Production on its own)."
	default:
		return "Inspect unavailable evidence."
	}
}

func zeroDefectNextAction(state mcpReqState) string {
	if state == mcpReqNotMet {
		return "Resolve open critical/high defects."
	}
	return "No open critical/high defects recorded."
}

func rehearsalNextAction(state mcpReqState) string {
	if state == mcpReqNotMet {
		return "Rehearse rollback to record this evidence."
	}
	return "Rollback rehearsal recorded."
}
