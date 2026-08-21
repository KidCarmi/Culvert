package profile

import "time"

// CachePolicy controls whether a profile's material may be cached (encrypted) and,
// for low-risk operations only, whether a still-valid cached entry may satisfy a
// request without a fresh provider fetch. Freshness bounds how old such a low-risk
// cache hit may be.
type CachePolicy struct {
	Enabled   bool          // may the broker cache an encrypted envelope for this profile?
	Freshness time.Duration // maximum age of a low-risk cache hit (0 ⇒ no low-risk fallback)
}

// RotationPolicy controls rotation. Grace is the bounded window during which the
// previous version stays usable AFTER a validated successor becomes active.
type RotationPolicy struct {
	Enabled     bool
	Grace       time.Duration
	MaxAttempts int
}

// FailurePolicy captures the profile's failure posture. High-risk operations
// ALWAYS fail closed (this is not configurable — it is asserted true). The only
// discretionary control is whether a low-risk operation may fall back to a valid,
// fresh cached credential.
type FailurePolicy struct {
	HighRiskFailClosed         bool // must be true; a profile that sets false is rejected
	AllowLowRiskCachedFallback bool // low-risk requests may use a valid, fresh cache entry
}

// validatePolicies checks cross-field policy consistency. It returns a stable
// sanitized reason on any inconsistency.
func validatePolicies(cache CachePolicy, rot RotationPolicy, fail FailurePolicy, maxTTL, graceCap, freshCap time.Duration) error {
	if !fail.HighRiskFailClosed {
		return policyErr("failure policy must fail closed for high-risk operations")
	}
	if cache.Enabled {
		if cache.Freshness < 0 {
			return policyErr("cache freshness must not be negative")
		}
		if cache.Freshness > freshCap {
			return policyErr("cache freshness exceeds the configured maximum")
		}
		if cache.Freshness > maxTTL {
			return policyErr("cache freshness cannot exceed the maximum credential TTL")
		}
	}
	// Low-risk cached fallback requires caching enabled AND a positive freshness.
	if fail.AllowLowRiskCachedFallback {
		if !cache.Enabled {
			return policyErr("low-risk cached fallback requires cache to be enabled")
		}
		if cache.Freshness <= 0 {
			return policyErr("low-risk cached fallback requires a positive cache freshness")
		}
	}
	if rot.Enabled {
		if rot.Grace < 0 {
			return policyErr("rotation grace must not be negative")
		}
		if rot.Grace > graceCap {
			return policyErr("rotation grace exceeds the configured maximum")
		}
		if rot.Grace > maxTTL {
			return policyErr("rotation grace cannot exceed the maximum credential TTL")
		}
		if rot.MaxAttempts <= 0 {
			return policyErr("rotation policy requires a positive attempt count")
		}
	}
	return nil
}
