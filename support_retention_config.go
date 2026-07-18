package main

import (
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

// support_retention_config.go — admin-configurable support-bundle retention
// (Slice B, built on the Slice A hardening). The two retention caps (count +
// max-age) are runtime-tunable, durable in admin_settings.json, and GUI-managed.
//
// SCOPE DECISION (node-local, NOT CP→DP synced): retention is a node-local
// OPERATIONAL tuning like the auto-exclusion tunables — durable in
// admin_settings.json but OFF export/import, version-rollback, and CP→DP
// propagation. Each node's effective caps are surfaced read-only (fleet
// VISIBILITY) so divergence is never silent; they are not synchronised. This
// mirrors the autoexclude-tunables precedent and avoids the config-rollback
// mass-eviction hazard a synced surface would carry (a rollback would evict
// forensic evidence fleet-wide).
//
// DATA-LOSS POSTURE: the caps govern DURABLE forensic evidence, so every design
// choice here favours NOT deleting. Case-bound (evidence) bundles stay exempt from
// EVERY cap; pending (unapproved) bundles are exempt from the COUNT cap only, so a
// tightened age cap can still age a stale never-approved bundle out (Slice A). A PUT
// that would tighten a cap enough to evict a bundle
// requires a typed confirm_evict matching the projected count, and it NEVER
// immediate-sweeps — the next janitor tick (≤ supportRetentionTick) applies the
// tightened age/size caps, giving an operator a window to reconsider.

const (
	// Defaults preserve the pre-Slice-B const behaviour (keep=10, 30d).
	defaultSupportRetentionKeep       = 10
	defaultSupportRetentionMaxAgeDays = 30

	// Bounds are REJECT-not-clamp (validate-before-convert). The max-age upper
	// bound (3650 days ≈ 10y) keeps the days→duration conversion far below the
	// int64-nanosecond overflow point, so a persisted value can never silently
	// wrap negative and disable the age cap.
	supportRetentionKeepMin = 1
	supportRetentionKeepMax = 10000
	supportRetentionDaysMin = 1
	supportRetentionDaysMax = 3650
)

// supportRetentionConfig is an IMMUTABLE snapshot of the two caps. Readers load
// the whole struct once per use via currentSupportRetention() so a (keep,maxAge)
// pair is never observed half-applied.
type supportRetentionConfig struct {
	Keep       int `json:"keep"`
	MaxAgeDays int `json:"max_age_days"`
}

// supportRetentionCfg holds the live config. nil ⇒ nothing applied yet ⇒ the
// compiled defaults (so feature-off / pre-feature files are byte-identical).
var supportRetentionCfg atomic.Pointer[supportRetentionConfig]

// currentSupportRetention returns the effective caps, falling back to the
// compiled defaults when nothing durable has been applied.
func currentSupportRetention() supportRetentionConfig {
	if p := supportRetentionCfg.Load(); p != nil {
		return *p
	}
	return supportRetentionConfig{Keep: defaultSupportRetentionKeep, MaxAgeDays: defaultSupportRetentionMaxAgeDays}
}

// supportRetentionKeepVal is the count-cap read accessor (single-load snapshot).
func supportRetentionKeepVal() int { return currentSupportRetention().Keep }

// supportRetentionMaxAgeVal is the age-cap read accessor as a Duration.
func supportRetentionMaxAgeVal() time.Duration {
	return time.Duration(currentSupportRetention().MaxAgeDays) * 24 * time.Hour
}

// setSupportRetention publishes a new config. The caller MUST have validated it.
// A defensive copy is stored so a later mutation of the argument can't race the
// published pointer.
func setSupportRetention(cfg supportRetentionConfig) {
	c := cfg
	supportRetentionCfg.Store(&c)
}

// validateSupportRetention rejects (never clamps) an out-of-range config. Run
// BEFORE any days→duration conversion so an overflow-prone value never reaches
// the engine.
func validateSupportRetention(c supportRetentionConfig) error {
	if c.Keep < supportRetentionKeepMin || c.Keep > supportRetentionKeepMax {
		return fmt.Errorf("keep must be in [%d,%d]", supportRetentionKeepMin, supportRetentionKeepMax)
	}
	if c.MaxAgeDays < supportRetentionDaysMin || c.MaxAgeDays > supportRetentionDaysMax {
		return fmt.Errorf("max_age_days must be in [%d,%d]", supportRetentionDaysMin, supportRetentionDaysMax)
	}
	return nil
}

// supportRetentionPatch is the PUT body: partial, pointer fields so an OMITTED
// field means "leave unchanged" — never "reset to default". Only an explicit
// value mutates a cap, so PUT-ing keep can't silently reset max_age.
type supportRetentionPatch struct {
	Keep         *int `json:"keep"`
	MaxAgeDays   *int `json:"max_age_days"`
	ConfirmEvict *int `json:"confirm_evict"`
}

// resolve applies the non-nil patch fields onto the current config.
func (p supportRetentionPatch) resolve(cur supportRetentionConfig) supportRetentionConfig {
	out := cur
	if p.Keep != nil {
		out.Keep = *p.Keep
	}
	if p.MaxAgeDays != nil {
		out.MaxAgeDays = *p.MaxAgeDays
	}
	return out
}

// projectRetentionEvictionSet returns the set of on-disk bundle dirs that the
// given caps WOULD remove against the current store, WITHOUT deleting anything.
// It applies the same exemptions as the live prune passes (Slice A): case-bound
// evidence is exempt from both caps; pending bundles are exempt from the count
// cap. Used for the typed-confirm projection and the read-only "pending" figure.
func projectRetentionEvictionSet(cfg supportRetentionConfig, now time.Time) map[string]bool {
	sums := listSupportBundles() // newest-first
	evicted := make(map[string]bool)

	// Count cap: keep the newest cfg.Keep EVICTABLE bundles; the rest overflow.
	kept := 0
	for i := range sums {
		s := &sums[i]
		if retentionExemptFromCountCap(s) {
			continue
		}
		kept++
		if kept > cfg.Keep {
			evicted[s.dirName] = true
		}
	}

	// Age cap: any non-evidence bundle older than maxAge. Fail-safe on an
	// unparseable timestamp (keep), matching pruneSupportBundlesByAge.
	maxAge := time.Duration(cfg.MaxAgeDays) * 24 * time.Hour
	for i := range sums {
		s := &sums[i]
		if retentionEvidence(s) {
			continue
		}
		created, err := time.Parse(time.RFC3339, s.CreatedAt)
		if err != nil {
			continue
		}
		if now.Sub(created) > maxAge {
			evicted[s.dirName] = true
		}
	}
	return evicted
}

// incrementalRetentionEvictions is how many MORE bundles the new caps would
// evict than the current caps already would — i.e. the additional forensic loss
// THIS change causes. A loosening (or a change that only re-doomed already-doomed
// bundles) returns 0 and needs no confirmation.
func incrementalRetentionEvictions(newCfg, curCfg supportRetentionConfig, now time.Time) int {
	newSet := projectRetentionEvictionSet(newCfg, now)
	curSet := projectRetentionEvictionSet(curCfg, now)
	n := 0
	for d := range newSet {
		if !curSet[d] {
			n++
		}
	}
	return n
}

// snapshotSupportRetention copies the effective caps into s so the durable file
// always reflects what is (or is about to be) applied. override lets the PUT
// persist the TARGET values BEFORE applying them (persist-before-apply): a
// persist failure then leaves the live config — and every bundle — untouched.
// nil ⇒ snapshot the current live values (every other caller).
func snapshotSupportRetention(s *AdminSettings, override *supportRetentionConfig) {
	c := currentSupportRetention()
	if override != nil {
		c = *override
	}
	s.SupportRetentionSaved = true
	s.SupportRetentionKeep = c.Keep
	s.SupportRetentionMaxAgeDays = c.MaxAgeDays
}

// applyAdminSupportRetention restores the persisted caps on load, ONLY when the
// sentinel is set (a pre-feature file leaves the compiled defaults intact —
// feature-off is byte-identical). A hand-edited out-of-range value is REFUSED
// (fail-closed to defaults) rather than applied, so a corrupt keep=0 can never
// wipe every bundle.
func applyAdminSupportRetention(s *AdminSettings) {
	if !s.SupportRetentionSaved {
		return
	}
	cfg := supportRetentionConfig{Keep: s.SupportRetentionKeep, MaxAgeDays: s.SupportRetentionMaxAgeDays}
	if err := validateSupportRetention(cfg); err != nil {
		logger.Printf("AdminSettings: ignoring invalid persisted support retention (%v) — keeping defaults", err)
		return
	}
	setSupportRetention(cfg)
}

// apiSupportRetention is the retention-tuning surface:
//   - GET (viewer): current caps + defaults + bounds + how many bundles the
//     CURRENT caps would remove (a read-only projection, single source of truth).
//   - PUT (admin): partial {keep, max_age_days}; validate → (typed-confirm if the
//     change would evict evidence-exempt bundles) → persist target → apply. The
//     apply is lazy — the next janitor tick sweeps under the new caps; PUT never
//     immediate-sweeps.
func apiSupportRetention(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		cur := currentSupportRetention()
		pending := len(projectRetentionEvictionSet(cur, time.Now()))
		jsonOK(w, map[string]any{
			"keep":         cur.Keep,
			"max_age_days": cur.MaxAgeDays,
			"defaults": map[string]int{
				"keep": defaultSupportRetentionKeep, "max_age_days": defaultSupportRetentionMaxAgeDays,
			},
			"bounds": map[string]map[string]int{
				"keep":         {"min": supportRetentionKeepMin, "max": supportRetentionKeepMax},
				"max_age_days": {"min": supportRetentionDaysMin, "max": supportRetentionDaysMax},
			},
			// Bundles the CURRENT caps would remove on the next sweep/build.
			"pending_evictions": pending,
			"note":              "PUT accepts a partial {keep, max_age_days}; an omitted field is left unchanged. A change that would evict additional bundles requires confirm_evict=<evict_count> (returned as 409). Case-bound (evidence) bundles are exempt from every cap; pending bundles are exempt from the count cap only (a tightened age cap can still evict one). Disabling a cap is not supported and the 2 GiB store ceiling is always active.",
		})

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var patch supportRetentionPatch
		if err := decodeJSON(r, &patch); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		// Reject an empty/no-op body for this destructive endpoint rather than
		// silently resetting anything to default.
		if patch.Keep == nil && patch.MaxAgeDays == nil {
			http.Error(w, "no changes: provide keep and/or max_age_days", http.StatusBadRequest)
			return
		}
		cur := currentSupportRetention()
		resolved := patch.resolve(cur)
		if err := validateSupportRetention(resolved); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Destructive-tightening typed-confirm: if the change would evict bundles
		// that aren't already doomed under the current caps, require an exact
		// confirm_evict. A stale/mismatched count is refused (the store may have
		// changed since the client's GET), so the operator always re-confirms the
		// current projection.
		now := time.Now()
		incr := incrementalRetentionEvictions(resolved, cur, now)
		if incr > 0 && (patch.ConfirmEvict == nil || *patch.ConfirmEvict != incr) {
			w.Header().Set("X-Evict-Count", strconv.Itoa(incr))
			writeJSONStatus(w, http.StatusConflict, map[string]any{
				"error":       "confirmation required",
				"evict_count": incr,
				"hint":        "resubmit with confirm_evict set to evict_count to acknowledge the eviction",
			})
			return
		}
		// VALIDATE (done) → PERSIST target → APPLY runtime. Persist first: a write
		// failure must not leave the live caps changed vs disk (persist-before-apply).
		// The apply runs via applyOnSuccess INSIDE the save's lock, so a concurrent
		// omnibus save can't snapshot the old caps and then clobber the just-written
		// new caps on disk (the serialize-apply-with-saves race).
		if err := saveAdminSettingsWithOverrides(adminSaveOverrides{
			supportRetention: &resolved,
			applyOnSuccess:   func() { setSupportRetention(resolved) },
		}); err != nil {
			logger.Printf("support retention: persist failed, runtime unchanged: %v", err)
			http.Error(w, "failed to persist retention config", http.StatusInternalServerError)
			return
		}
		auditEventDiff(r, "support.retention.set", "retention",
			"updated support-bundle retention caps", cur, resolved)
		jsonOK(w, map[string]any{
			"keep": resolved.Keep, "max_age_days": resolved.MaxAgeDays, "projected_evictions": incr,
		})

	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
