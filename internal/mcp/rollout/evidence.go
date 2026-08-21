package rollout

import "time"

// Design-target evidence windows (ROLLOUT-AND-ROLLBACK.md §1). These are MEASURED,
// never fabricated: the machinery below reports elapsed continuous time against
// them, but Production remains locked behind the separate Production Qualification
// gate regardless of what these report. Tests use an injected clock and MUST label
// synthetic elapsed time as test evidence.
const (
	// ShadowWindowTarget is the continuous Shadow window floor (≥14 days).
	ShadowWindowTarget = 14 * 24 * time.Hour
	// CanaryWindowTarget is the continuous Canary window floor (≥7 days).
	CanaryWindowTarget = 7 * 24 * time.Hour
	// SoakTarget is the stable-soak floor at every promotion boundary (≥24 hours).
	SoakTarget = 24 * time.Hour
)

// EvidenceOrigin marks whether an evidence figure came from real production
// operation or a synthetic (injected-clock) test. A synthetic figure MUST NEVER be
// reported as production evidence.
type EvidenceOrigin uint8

const (
	// OriginUnset is the zero value.
	OriginUnset EvidenceOrigin = iota
	// OriginProduction is real, measured production operation.
	OriginProduction
	// OriginSynthetic is injected-clock/test time; never production-qualifying.
	OriginSynthetic
)

// String returns a stable token.
func (o EvidenceOrigin) String() string {
	switch o {
	case OriginProduction:
		return "production"
	case OriginSynthetic:
		return "synthetic"
	default:
		return "unset"
	}
}

// EvidenceSummary is the bounded, restart-durable rollout evidence for one
// capability. It records when the current mode window began, the continuous
// elapsed time (computed with an injected clock), the open-defect count, and the
// origin label. It NEVER stores tenant/subject/argument/URL/token content.
type EvidenceSummary struct {
	Version                 int            `json:"version"`
	Origin                  EvidenceOrigin `json:"origin"`
	ShadowStartUnix         int64          `json:"shadow_start_unix,omitempty"`
	CanaryStartUnix         int64          `json:"canary_start_unix,omitempty"`
	SoakStartUnix           int64          `json:"soak_start_unix,omitempty"`
	OpenCriticalHighDefects int            `json:"open_critical_high_defects"`
	RollbackRehearsed       bool           `json:"rollback_rehearsed"`
	FalsePositiveReviews    int            `json:"false_positive_reviews"`
}

const evidenceVersion = 1

func newEvidenceSummary() EvidenceSummary {
	return EvidenceSummary{Version: evidenceVersion, Origin: OriginProduction}
}

func (e EvidenceSummary) valid() bool { return e.Version == evidenceVersion }

// BeginWindow stamps the start of a mode window (Shadow/Canary) and the soak
// window at nowUnix. It is idempotent per mode (re-stamping only on first entry so
// the CONTINUOUS window is preserved across re-applies of the same mode).
func (e *EvidenceSummary) BeginWindow(mode Mode, nowUnix int64, origin EvidenceOrigin) {
	if origin != OriginUnset {
		e.Origin = origin
	}
	switch mode {
	case ModeShadow:
		if e.ShadowStartUnix == 0 {
			e.ShadowStartUnix = nowUnix
		}
		e.CanaryStartUnix = 0
	case ModeCanary, ModeProduction:
		if e.CanaryStartUnix == 0 {
			e.CanaryStartUnix = nowUnix
		}
	default:
		// Disabled/Observe reset the enforcement windows (a demotion breaks continuity).
		e.ShadowStartUnix = 0
		e.CanaryStartUnix = 0
	}
	e.SoakStartUnix = nowUnix
}

// ShadowElapsed returns the continuous Shadow window elapsed at now.
func (e EvidenceSummary) ShadowElapsed(now time.Time) time.Duration {
	return elapsed(e.ShadowStartUnix, now)
}

// CanaryElapsed returns the continuous Canary window elapsed at now.
func (e EvidenceSummary) CanaryElapsed(now time.Time) time.Duration {
	return elapsed(e.CanaryStartUnix, now)
}

// SoakElapsed returns the soak elapsed at now.
func (e EvidenceSummary) SoakElapsed(now time.Time) time.Duration {
	return elapsed(e.SoakStartUnix, now)
}

func elapsed(startUnix int64, now time.Time) time.Duration {
	if startUnix == 0 {
		return 0
	}
	d := now.Sub(time.Unix(startUnix, 0))
	if d < 0 {
		return 0
	}
	return d
}

// PromotionEvidenceMet reports whether the evidence FLOORS for a from→to promotion
// are satisfied at now (window + soak + zero open critical/high). This is a
// REPORTING gate only — it never authorizes Production (the qualification verifier
// does). It returns (met, reason) where reason is a fail-closed classification when
// not met.
func (e EvidenceSummary) PromotionEvidenceMet(from, to Mode, now time.Time) (met bool, reason string) {
	if e.OpenCriticalHighDefects > 0 {
		return false, "open critical/high defects"
	}
	if e.SoakElapsed(now) < SoakTarget {
		return false, "soak window not met"
	}
	switch {
	case from == ModeShadow && to == ModeCanary:
		if e.ShadowElapsed(now) < ShadowWindowTarget {
			return false, "shadow window not met"
		}
		if !e.RollbackRehearsed {
			return false, "rollback not rehearsed"
		}
	case from == ModeCanary && to == ModeProduction:
		if e.CanaryElapsed(now) < CanaryWindowTarget {
			return false, "canary window not met"
		}
	}
	return true, ""
}

// AddFalsePositiveReview increments the bounded false-positive review counter.
func (e *EvidenceSummary) AddFalsePositiveReview(lim Limits) {
	if e.FalsePositiveReviews < lim.MaxReviewEntries() {
		e.FalsePositiveReviews++
	}
}
