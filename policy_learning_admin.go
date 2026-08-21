package main

// policy_learning_admin.go — M5A root lifecycle for Policy Learning Mode
// (ADR-0025): governed enablement, session-transition serialization, the
// recommendable-category guardrail, and the canonical access-policy CONTENT
// identity the learning baseline pins.
//
// Product state model (M5A §1): FEATURE ENABLED ≠ LEARNING ACTIVE.
//
//	disabled            — singleton nil: the request path pays one atomic load
//	enabled, idle       — engine constructed but no Learning session: the
//	                      adapters gate on Engine.LearningActive() BEFORE any
//	                      Observation is built (two atomic loads, zero allocs)
//	enabled, learning   — the qualified M2 observation path
//
// Concurrency model: policyLearnAdminMu serializes every ADMIN TRANSITION
// (enable/disable/start/stop/cancel/generate/guardrail change) so check-then-
// act sequences ("409 if a session is active") cannot interleave. The small
// policyLearnStateMu guards only the desired-state snapshot so the omnibus
// SaveAdminSettings (any unrelated admin mutation, any goroutine) can read it
// without touching the transition lock (no lock-ordering coupling with
// adminSettingsMu).
//
// Disable safety (M5A §3): disabling with an active Learning session is
// REFUSED (409) — the feature toggle never implicitly completes or cancels a
// session, and disable never deletes state: the store, subject key, sessions,
// and recommendations stay on disk for the next enable.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/policylearn"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// Transition errors surfaced as deterministic 409s by the API layer.
var (
	errPolicyLearnDisabled      = errors.New("policy learning is disabled")
	errPolicyLearnActiveSession = errors.New("a learning session is active — complete or cancel it first")
	errPolicyLearnUnavailable   = errors.New("policy learning engine unavailable (see server log)")
)

// policyLearnSettings is the governed durable state (AdminSettings-backed,
// node-local: OFF export/import, version-rollback, and CP→DP).
type policyLearnSettings struct {
	Enabled bool
	// Categories is the governed recommendable-category allowlist. nil =
	// never governed ⇒ the embedded business-category seed; non-nil (including
	// EMPTY — a legitimate fail-closed choice) = admin-owned verbatim value.
	// Once saved, the materialized list is authoritative and does not auto-
	// extend when a later build ships a larger seed (governance beats seed).
	Categories []string
}

var (
	policyLearnAdminMu sync.Mutex // serializes lifecycle transitions (see header)

	policyLearnStateMu sync.Mutex
	policyLearnState   policyLearnSettings
	policyLearnSaved   bool   // sentinel source: an admin (or a restored file) governed the feature
	policyLearnRunErr  string // non-empty when enabled but the engine failed to construct (honest degradation)

	policyLearnPaths policyLearningStartupConfig // resolved once at startup
)

// policyLearnSnapshotState returns the durable desired state for persistence.
func policyLearnSnapshotState() (s policyLearnSettings, saved bool) {
	policyLearnStateMu.Lock()
	defer policyLearnStateMu.Unlock()
	s = policyLearnState
	s.Categories = append([]string(nil), policyLearnState.Categories...)
	return s, policyLearnSaved
}

func policyLearnSetState(s policyLearnSettings, saved bool) {
	policyLearnStateMu.Lock()
	defer policyLearnStateMu.Unlock()
	policyLearnState = s
	policyLearnState.Categories = append([]string(nil), s.Categories...)
	policyLearnSaved = saved
}

func policyLearnSetRunErr(msg string) {
	policyLearnStateMu.Lock()
	defer policyLearnStateMu.Unlock()
	policyLearnRunErr = msg
}

func policyLearnGetRunErr() string {
	policyLearnStateMu.Lock()
	defer policyLearnStateMu.Unlock()
	return policyLearnRunErr
}

// policyLearnEffectiveCategories resolves the governed allowlist: nil (never
// governed) ⇒ the embedded business-category seed; otherwise the admin-owned
// value verbatim (fail-closed: empty means nothing recommendable).
func policyLearnEffectiveCategories(s policyLearnSettings) []string {
	if s.Categories != nil {
		// Always non-nil (even for a governed EMPTY list) so persistence writes
		// [] rather than null — the explicit-empty fail-closed choice survives.
		out := make([]string, 0, len(s.Categories))
		return append(out, s.Categories...)
	}
	return urlcat.DefaultBusinessCategoryNames()
}

// buildPolicyLearnEngine constructs the engine with the production wiring
// (paths from the startup slice, live category resolver/epoch, quarantine
// seam) and the supplied recommendable allowlist.
func buildPolicyLearnEngine(cats []string) (*policylearn.Engine, error) {
	return policylearn.New(policylearn.Config{
		StorePath:      policyLearnPaths.StorePath,
		SubjectKeyPath: policyLearnPaths.SubjectKeyPath,
		Now:            time.Now,
		Baseline: func() policylearn.Baseline {
			gen, _ := policyStore.policyVersion()
			return policylearn.Baseline{
				PolicyGeneration:  gen,
				DefaultAction:     defaultPolicyAction(),
				PolicyContentHash: policyContentIdentity(),
			}
		},
		Categories: func(host string) (string, string) {
			category, tier, _ := lookupHostCategory(host)
			return category, tier
		},
		CategoryEpoch:           learnCategoryEpoch,
		RecommendableCategories: cats,
		Quarantine: func(path string, err error) {
			quarantineCorruptStateFile("policy_learning", path, err)
		},
		MaxRetainedSessions: policyLearnPaths.MaxRetainedSessions,
		MaxSessionDuration:  policyLearnPaths.MaxSessionDuration,
	})
}

// policyLearnApplyDesiredLocked reconciles the RUNTIME to the desired state:
// build/replace or close the engine. Caller holds policyLearnAdminMu and has
// already enforced the active-session refusals. A construction failure leaves
// the singleton nil and records an honest runtime error (the governed desired
// state is NOT silently rewritten).
func policyLearnApplyDesiredLocked(desired policyLearnSettings) {
	old := policyLearnEngine.Load()
	if !desired.Enabled {
		policyLearnEngine.Store(nil)
		if old != nil {
			if err := old.Close(); err != nil { // drains queued observations + flushes
				logger.Printf("Policy learning: close on disable: %v", err)
			}
		}
		policyLearnSetRunErr("")
		return
	}
	cats := policyLearnEffectiveCategories(desired)
	if old != nil {
		// Same canonical allowlist ⇒ the running engine already matches (the
		// guardrails hash is a pure function of the canonical list).
		if policylearn.GuardrailsHashForCategories(cats) == old.GuardrailsHash() {
			policyLearnSetRunErr("")
			return
		}
		// Allowlist changed (no active session — caller enforced): close the
		// old engine first (final flush), then rebuild over the same store.
		policyLearnEngine.Store(nil)
		if err := old.Close(); err != nil {
			logger.Printf("Policy learning: close for guardrail change: %v", err)
		}
	}
	eng, err := buildPolicyLearnEngine(cats)
	if err != nil {
		// Fail-safe + honest: advisory learning must never block the proxy or
		// silently flip governed config. Runtime stays off; status surfaces it.
		logger.Printf("Policy learning: engine unavailable: %v", err)
		policyLearnSetRunErr(err.Error())
		return
	}
	policyLearnEngine.Store(eng)
	policyLearnSetRunErr("")
}

// ── Canonical access-policy content identity (M5A §6) ────────────────────────

// policyContentIdentity is the deterministic CONTENT identity of the running
// access policy: default action + the ordered rulebase with the volatile
// display fields (hit counters / last-hit stamps) zeroed. Unlike the persisted
// policy generation counter (robust across restarts via the .meta sidecar,
// but a counter — a meta-file loss or a same-content re-import moves it
// without/despite a content change), this hashes what the policy SAYS.
//
// A recommendation therefore goes stale (policy_content_changed) exactly when
// the enforced rulebase content or the default action differs from what was
// running while its evidence was observed — including rule edits, reorders,
// enables/disables, adds/deletes, rollbacks, and imports; and NOT for hit-count
// churn, restarts, metadata-only version bumps, or a no-op re-save (Codex fix:
// stampRuleMetadataForWrite restamps ModifiedAt/By on EVERY save, so the
// provenance stamps must be canonicalized out exactly as the draft comparator
// sameRuleContent does — otherwise a semantically identical re-save staled
// every recommendation). Domain tag v2: pre-fix pinned hashes covered the
// stamps, so they mismatch v2 values and go stale exactly once at upgrade —
// never reinterpreted (the epoch-scheme upgrade precedent).
func policyContentIdentity() string {
	rules := policyStore.List()
	for i := range rules {
		rules[i].HitCount = 0
		rules[i].LastHit = ""
		rules[i].CreatedAt = ""
		rules[i].ModifiedAt = ""
		rules[i].ModifiedBy = ""
	}
	h := sha256.New()
	h.Write([]byte("culvert-policy-content-v2\x00"))
	h.Write([]byte(defaultPolicyAction()))
	h.Write([]byte{0})
	if err := json.NewEncoder(h).Encode(rules); err != nil {
		return "marshal-error" // structurally impossible (fixed struct slice)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// policyLearnStaleInputs assembles the CURRENT identities for server-side
// staleness evaluation (M5A §10). Requires a live engine (guardrails + policy
// + key identities are engine-scoped).
func policyLearnStaleInputs(eng *policylearn.Engine) policylearn.StaleInputs {
	gen, _ := policyStore.policyVersion()
	return policylearn.StaleInputs{
		PolicyGeneration:         gen,
		CategoryEpoch:            learnCategoryEpoch(),
		GuardrailsHash:           eng.GuardrailsHash(),
		SubjectKeyID:             eng.SubjectKeyID(),
		RecommendationPolicyHash: eng.RecommendationPolicyHash(),
		PolicyContentHash:        policyContentIdentity(),
	}
}

// policyLearnCanonicalCategories mirrors the engine's canonical allowlist form
// (trim/dedupe/sort) for display and change detection at the API layer.
func policyLearnCanonicalCategories(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
