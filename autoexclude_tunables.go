package main

// autoexclude_tunables.go — F10 PR2: the operator-facing tunable set for the
// adaptive decryption-exclusion cache, plus its bounds, defaults, resolver, and
// validator. This is package-main GLUE shared by the persistence layer (this PR)
// and the admin API (PR3). It is DARK in PR2: nothing reachable through normal
// administration calls it yet — only the settings LOAD path (which is gated by the
// AutoExcludeTunablesSaved sentinel) and focused tests.
//
// The learned cache itself stays VOLATILE and node-local (off every config
// surface); only these five PARAMETERS are durable, and they are deliberately OFF
// export/import, version-rollback, and CP→DP propagation.

import (
	"fmt"
	"time"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// autoExcludeTunables is the operator-facing tunable set in the PERSISTED unit
// convention: durations are integer SECONDS (matching the autoexclude.Stats() JSON
// contract), so one unit convention runs end-to-end (file ↔ API ↔ Stats). A zero
// field means "unset ⇒ use the engine default" (resolveAutoExcludeTunables).
type autoExcludeTunables struct {
	ConfirmN      int `json:"confirm_n"`
	TTLSecs       int `json:"ttl_secs"`
	PinnedTTLSecs int `json:"pinned_ttl_secs"`
	WindowSecs    int `json:"window_secs"`
	MaxEntries    int `json:"max_entries"`
}

// Accepted range for each tunable — the SECURITY contract for a guardrail-relaxing
// subsystem, enforced by validateAutoExcludeTunables on the RESOLVED set.
//   - confirmN floors at 2: a value of 1 permits single-client self-promotion, which
//     defeats the distinct-client anti-poisoning guarantee (ADR-0008). 1 is not an
//     acceptable production posture and is rejected.
//   - maxEntries ceils at 262144: keeps the memory-DoS bound tight (worst-case
//     active+pending is ~2× this many small structs) while staying far above any
//     real learn rate.
//   - pinnedTTL additionally must be <= ttl (cross-field), checked in the validator.
const (
	autoExcludeConfirmNMin   = 2
	autoExcludeConfirmNMax   = 10
	autoExcludeTTLSecsMin    = 60         // 1m
	autoExcludeTTLSecsMax    = 168 * 3600 // 7d
	autoExcludePinnedSecsMin = 60         // 1m (upper bound is ttl, cross-field)
	autoExcludeWindowSecsMin = 10
	autoExcludeWindowSecsMax = 24 * 3600 // 24h
	autoExcludeMaxEntriesMin = 256
	autoExcludeMaxEntriesMax = 262144
)

// defaultAutoExcludeTunables returns the engine's built-in defaults in seconds —
// the "reset to default" target and the value a never-configured node reports.
func defaultAutoExcludeTunables() autoExcludeTunables {
	return autoExcludeTunables{
		ConfirmN:      autoexclude.DefaultConfirmN,
		TTLSecs:       int(autoexclude.DefaultTTL / time.Second),
		PinnedTTLSecs: int(autoexclude.DefaultPinnedTTL / time.Second),
		WindowSecs:    int(autoexclude.DefaultWindow / time.Second),
		MaxEntries:    autoexclude.DefaultMaxEntries,
	}
}

// resolveAutoExcludeTunables fills every zero/omitted field with its engine default
// and returns the fully-resolved effective set (no zeros). "Zero ⇒ default" is the
// single, consistent rule: it is how a settings file predating this feature (all
// fields absent) lands on defaults, AND how "reset to default" is expressed (write a
// zero). It does NOT validate — callers validate the resolved set. It never reads
// hidden state, so it is pure and order-independent.
func resolveAutoExcludeTunables(t autoExcludeTunables) autoExcludeTunables {
	d := defaultAutoExcludeTunables()
	out := t
	if out.ConfirmN <= 0 {
		out.ConfirmN = d.ConfirmN
	}
	if out.TTLSecs <= 0 {
		out.TTLSecs = d.TTLSecs
	}
	if out.PinnedTTLSecs <= 0 {
		out.PinnedTTLSecs = d.PinnedTTLSecs
	}
	if out.WindowSecs <= 0 {
		out.WindowSecs = d.WindowSecs
	}
	if out.MaxEntries <= 0 {
		out.MaxEntries = d.MaxEntries
	}
	return out
}

// validateAutoExcludeTunables checks a RESOLVED set (call resolve first) against the
// bounds contract. It returns a field-named error for API 400 feedback. It is the
// OUTER validation layer; the engine's Reconfigure independently clamps as a last
// line of defense, so a value that slips past here can still never corrupt cache
// state — but a value rejected here never reaches the engine at all.
func validateAutoExcludeTunables(t autoExcludeTunables) error {
	switch {
	case t.ConfirmN < autoExcludeConfirmNMin || t.ConfirmN > autoExcludeConfirmNMax:
		return fmt.Errorf("confirm_n=%d out of range [%d,%d] (1 defeats the anti-poisoning guarantee)",
			t.ConfirmN, autoExcludeConfirmNMin, autoExcludeConfirmNMax)
	case t.TTLSecs < autoExcludeTTLSecsMin || t.TTLSecs > autoExcludeTTLSecsMax:
		return fmt.Errorf("ttl_secs=%d out of range [%d,%d]", t.TTLSecs, autoExcludeTTLSecsMin, autoExcludeTTLSecsMax)
	case t.PinnedTTLSecs < autoExcludePinnedSecsMin:
		return fmt.Errorf("pinned_ttl_secs=%d below minimum %d", t.PinnedTTLSecs, autoExcludePinnedSecsMin)
	case t.PinnedTTLSecs > t.TTLSecs:
		return fmt.Errorf("pinned_ttl_secs=%d must not exceed ttl_secs=%d", t.PinnedTTLSecs, t.TTLSecs)
	case t.WindowSecs < autoExcludeWindowSecsMin || t.WindowSecs > autoExcludeWindowSecsMax:
		return fmt.Errorf("window_secs=%d out of range [%d,%d]", t.WindowSecs, autoExcludeWindowSecsMin, autoExcludeWindowSecsMax)
	case t.MaxEntries < autoExcludeMaxEntriesMin || t.MaxEntries > autoExcludeMaxEntriesMax:
		return fmt.Errorf("max_entries=%d out of range [%d,%d]", t.MaxEntries, autoExcludeMaxEntriesMin, autoExcludeMaxEntriesMax)
	}
	return nil
}

// engineConfig converts a resolved tunable set to an autoexclude.Config for
// Reconfigure (seconds → durations). Now is left nil (Reconfigure ignores it).
func (t autoExcludeTunables) engineConfig() autoexclude.Config {
	return autoexclude.Config{
		ConfirmN:   t.ConfirmN,
		TTL:        time.Duration(t.TTLSecs) * time.Second,
		PinnedTTL:  time.Duration(t.PinnedTTLSecs) * time.Second,
		Window:     time.Duration(t.WindowSecs) * time.Second,
		MaxEntries: t.MaxEntries,
	}
}

// currentAutoExcludeTunables snapshots the live engine tunables (from Stats, the
// existing read-only source of truth) into the persisted shape. Used by
// SaveAdminSettings so the durable file always reflects the applied values.
func currentAutoExcludeTunables() autoExcludeTunables {
	s := autoExclude().Stats()
	return autoExcludeTunables{
		ConfirmN:      s.ConfirmN,
		TTLSecs:       s.TTLSecs,
		PinnedTTLSecs: s.PinnedSecs,
		WindowSecs:    s.WindowSecs,
		MaxEntries:    s.MaxEntries,
	}
}
