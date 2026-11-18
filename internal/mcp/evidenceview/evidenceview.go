package evidenceview

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// State is the typed state of a single measured evidence requirement. The
// distinctions are load-bearing: not_started (no window began) is not the same as
// not_met (window began but is below floor), synthetic_non_qualifying (measured on
// an injected/test clock, can never qualify) is not the same as met, and unavailable
// (the evidence could not be read) is not the same as not_met.
type State string

const (
	stateMet                    State = "met"
	stateNotMet                 State = "not_met"
	stateNotStarted             State = "not_started"
	stateSyntheticNonQualifying State = "synthetic_non_qualifying"
	stateUnavailable            State = "unavailable"
	stateNotApplicable          State = "not_applicable"
)

// Requirement is one row of the measured-requirement list. Only
// requirements backed by a real runtime source appear here. Window requirements
// carry measured/target seconds + a start unix; count requirements carry a count.
type Requirement struct {
	Key             string `json:"key"`
	Label           string `json:"label"`
	State           State  `json:"state"`
	Origin          string `json:"origin"`
	MeasuredSeconds *int64 `json:"measured_seconds,omitempty"`
	TargetSeconds   *int64 `json:"target_seconds,omitempty"`
	StartUnix       int64  `json:"start_unix,omitempty"`
	Count           *int   `json:"count,omitempty"`
	NextAction      string `json:"next_action"`
}

// Summary is the safe tally over the measured requirements. It is
// deliberately NOT a qualification decision and carries no percentage.
type Summary struct {
	MeasuredTotal          int `json:"measured_total"`
	Met                    int `json:"met"`
	NotMet                 int `json:"not_met"`
	NotStarted             int `json:"not_started"`
	SyntheticNonQualifying int `json:"synthetic_non_qualifying"`
	Unavailable            int `json:"unavailable"`
}

// View is the capability-scoped evidence read model. It is a superset of
// the original evidence response (the original keys are retained verbatim for
// backward compatibility) plus the additive read model.
type View struct {
	Capability            string `json:"capability"`
	Mode                  string `json:"mode"`
	ProductionLocked      bool   `json:"production_locked"`
	ProductionLockMessage string `json:"production_lock_message"`
	LockReason            string `json:"lock_reason"`
	Origin                string `json:"origin"`
	AsOfUnixNano          int64  `json:"as_of_unix_nano"`

	// Window details (also represented in Requirements; kept flat for convenience).
	ShadowStartUnix      int64 `json:"shadow_start_unix"`
	ShadowElapsedSeconds int64 `json:"shadow_elapsed_seconds"`
	ShadowTargetSeconds  int64 `json:"shadow_target_seconds"`
	ShadowState          State `json:"shadow_state"`
	CanaryStartUnix      int64 `json:"canary_start_unix"`
	CanaryElapsedSeconds int64 `json:"canary_elapsed_seconds"`
	CanaryTargetSeconds  int64 `json:"canary_target_seconds"`
	CanaryState          State `json:"canary_state"`
	SoakStartUnix        int64 `json:"soak_start_unix"`
	SoakElapsedSeconds   int64 `json:"soak_elapsed_seconds"`
	SoakTargetSeconds    int64 `json:"soak_target_seconds"`
	SoakState            State `json:"soak_state"`

	OpenCriticalHigh       int   `json:"open_critical_high"`
	ZeroDefectState        State `json:"zero_defect_state"`
	RollbackRehearsed      bool  `json:"rollback_rehearsed"`
	RollbackRehearsalState State `json:"rollback_rehearsal_state"`
	FalsePositiveReviews   int   `json:"false_positive_reviews"`

	// Backward-compatible target-hours keys from the original response.
	ShadowWindowTargetH int `json:"shadow_window_target_h"`
	CanaryWindowTargetH int `json:"canary_window_target_h"`
	SoakTargetH         int `json:"soak_target_h"`

	Requirements []Requirement `json:"requirements"`
	Summary      Summary       `json:"summary"`

	// UnsupportedCategories are broader Production Qualification categories that are
	// NOT represented by any runtime evidence source. They are listed so the UI can
	// state "Not represented by this runtime evidence source" - never passed/failed.
	UnsupportedCategories []string `json:"unsupported_categories"`
}

// unsupportedCategories returns the broader Production Qualification
// categories with no runtime evidence source in this build, as a fresh slice per
// call so no caller can alias or mutate a shared list. They are reported as
// "not represented" - never as passed, failed, pending, or complete.
func unsupportedCategories() []string {
	return []string{
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
}

// windowReqState classifies a clock-window requirement truthfully. A window that
// never began is not_started (never a zero-percent "met"); a window measured on a
// synthetic/injected clock is synthetic_non_qualifying regardless of elapsed (a
// synthetic figure can never qualify, so it is never reported as met); otherwise it
// is met iff the continuous elapsed time has reached the floor.
func windowReqState(startUnix int64, elapsed, target time.Duration, origin rollout.EvidenceOrigin) State {
	if startUnix == 0 {
		return stateNotStarted
	}
	if origin == rollout.OriginSynthetic {
		return stateSyntheticNonQualifying
	}
	if elapsed >= target {
		return stateMet
	}
	return stateNotMet
}

func secs(d time.Duration) int64 { return int64(d / time.Second) }
func i64ptr(v int64) *int64      { return &v }
func intptr(v int) *int          { return &v }

// Build builds the read model from a real EvidenceSummary at now. It
// is pure and performs NO mutation. now must be the server's real clock (time.Now())
// so window elapsed uses production clock semantics.
func Build(capability, mode string, ev rollout.EvidenceSummary, now time.Time, nowNano int64) View {
	shadowElapsed := ev.ShadowElapsed(now)
	canaryElapsed := ev.CanaryElapsed(now)
	soakElapsed := ev.SoakElapsed(now)
	shadowState := windowReqState(ev.ShadowStartUnix, shadowElapsed, rollout.ShadowWindowTarget, ev.Origin)
	canaryState := windowReqState(ev.CanaryStartUnix, canaryElapsed, rollout.CanaryWindowTarget, ev.Origin)
	soakState := windowReqState(ev.SoakStartUnix, soakElapsed, rollout.SoakTarget, ev.Origin)

	// Count/bool requirements are not clock-based, so a synthetic clock does not
	// taint them; they report their real measured state.
	zeroDefectState := stateMet
	if ev.OpenCriticalHighDefects > 0 {
		zeroDefectState = stateNotMet
	}
	rehearsalState := stateNotMet
	if ev.RollbackRehearsed {
		rehearsalState = stateMet
	}

	dto := View{
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

		UnsupportedCategories: unsupportedCategories(),
	}

	dto.Requirements = buildRequirements(ev, now, shadowState, canaryState, soakState, zeroDefectState, rehearsalState)
	dto.Summary = summarize(dto.Requirements)
	return dto
}

// buildRequirements assembles the ordered measured-requirement rows from
// the pre-classified states. Only requirements backed by a real runtime source are
// included; false-positive reviews is a recorded count (not_applicable), never a
// pass/fail requirement.
func buildRequirements(ev rollout.EvidenceSummary, now time.Time, shadowState, canaryState, soakState, zeroDefectState, rehearsalState State) []Requirement {
	origin := ev.Origin.String()
	return []Requirement{
		{
			Key: "shadow_window", Label: "Shadow window floor", State: shadowState, Origin: origin,
			MeasuredSeconds: i64ptr(secs(ev.ShadowElapsed(now))), TargetSeconds: i64ptr(secs(rollout.ShadowWindowTarget)),
			StartUnix: ev.ShadowStartUnix, NextAction: windowNextAction("shadow", shadowState),
		},
		{
			Key: "canary_window", Label: "Canary window floor", State: canaryState, Origin: origin,
			MeasuredSeconds: i64ptr(secs(ev.CanaryElapsed(now))), TargetSeconds: i64ptr(secs(rollout.CanaryWindowTarget)),
			StartUnix: ev.CanaryStartUnix, NextAction: windowNextAction("canary", canaryState),
		},
		{
			Key: "soak_window", Label: "Stable soak floor", State: soakState, Origin: origin,
			MeasuredSeconds: i64ptr(secs(ev.SoakElapsed(now))), TargetSeconds: i64ptr(secs(rollout.SoakTarget)),
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
			Key: "false_positive_reviews", Label: "Recorded false-positive reviews", State: stateNotApplicable, Origin: origin,
			Count: intptr(ev.FalsePositiveReviews), NextAction: "Informational: recorded reviews (no defined threshold).",
		},
	}
}

// summarize tallies only the measured requirements (not_applicable
// rows are excluded from the measured total). It never produces an overall decision.
func summarize(reqs []Requirement) Summary {
	var s Summary
	for i := range reqs {
		switch reqs[i].State {
		case stateNotApplicable:
			continue
		case stateMet:
			s.Met++
		case stateNotMet:
			s.NotMet++
		case stateNotStarted:
			s.NotStarted++
		case stateSyntheticNonQualifying:
			s.SyntheticNonQualifying++
		case stateUnavailable:
			s.Unavailable++
		}
		s.MeasuredTotal++
	}
	return s
}

func windowNextAction(window string, state State) string {
	switch state {
	case stateNotStarted:
		switch window {
		case "shadow":
			return "Enter Shadow to begin the window."
		case "canary":
			return "Complete Shadow, then enter Canary to begin the window."
		default:
			return "The soak window begins on the next mode entry."
		}
	case stateNotMet:
		switch window {
		case "shadow":
			return "Remain in Shadow until the window floor is reached."
		case "canary":
			return "Continue Canary observation until the floor is reached."
		default:
			return "Wait for the soak window to reach its floor."
		}
	case stateSyntheticNonQualifying:
		return "Synthetic evidence cannot qualify Production; production-origin measurement is required."
	case stateMet:
		return "Floor reached (does not qualify Production on its own)."
	default:
		return "Inspect unavailable evidence."
	}
}

func zeroDefectNextAction(state State) string {
	if state == stateNotMet {
		return "Resolve open critical/high defects."
	}
	return "No open critical/high defects recorded."
}

func rehearsalNextAction(state State) string {
	if state == stateNotMet {
		return "Rehearse rollback to record this evidence."
	}
	return "Rollback rehearsal recorded."
}
