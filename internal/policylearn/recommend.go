package policylearn

// M4 — deterministic recommendation generation + immutable evidence.
//
// A Recommendation is DATA, never authority (ADR-0025): it proposes exactly one
// born-safe rule shape (Allow + Inspect + Enabled=false) for one REAL group ×
// one ALLOWLISTED category, carrying its evidence copied BY VALUE from the
// terminal session's aggregate. Nothing in this file (or package — see the root
// wall test) can reach the policy store, the draft pipeline, or any enforcement
// state; M5 translates accepted recommendations into draft rules at the trust
// boundary OUTSIDE this package.
//
// Determinism contract: generation is a pure function of
// (terminal Completed session snapshot, canonical recommendable-category
// allowlist, thresholds, clock instant). Same inputs ⇒ byte-identical
// recommendation content and order. There is no randomness: IDs are
// content-derived hashes, ordering is sorted cell-key order, and every DTO is
// maps-free so json.Marshal is deterministic.
//
// Evidence-honesty contract (ADR-0025 PEI): the M3 positive-evidence sets
// (subjects, days, hosts, first/last seen) are ALLOWED-only, and the DTO field
// names say so (AllowedRequests, ObservedAllowedSubjects, TopAllowedHosts, …).
// Blocked traffic surfaces as request COUNTS only — the model has no field that
// could state or imply "N users were blocked", because no such fact was ever
// collected. Coverage carries facts, never fabricated denominators: there is no
// percentage field and MembershipDenominatorKnown is structurally false until a
// real membership input exists. Confidence is a named-predicate level
// (high/medium/low) with the supporting Reasons and constraining Limits listed —
// never a composite, weighted, or percentage score.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Recommendation lifecycle states. Staleness is deliberately COMPUTED, not
// latched: a recommendation's pins (Baseline + SubjectKeyID) are compared
// against current identities via the pure StaleReasons helper, so there is no
// mutation path that could rot or race. Superseded IS latched — it records the
// historical fact that a later generation replaced this content, which no
// current-state comparison could recover.
const (
	RecStateGenerated  = "generated"
	RecStateSuperseded = "superseded"
)

// Confidence levels — a closed three-value set (never a score).
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// DefaultActionRuleKey is the RuleHits attribution key recorded when a decision
// carried no RuleID (the default action decided). Exported so evidence readers
// can distinguish default-action attribution from any real rule ULID — a ULID
// can never equal this sentinel.
const DefaultActionRuleKey = "_default_"

// Fixed ProposedRule semantics (ADR-0025 born-safe shape). Constants, not
// inputs: generation cannot be asked to propose anything else.
const (
	proposedActionAllow     = "Allow"
	proposedSSLInspect      = "Inspect"
	defaultCommunityTier    = "community" // tier string the root resolver uses for the UT1/community DB
	guardrailsHashDomainTag = "policylearn-guardrails-v1"
	recIDDomainTag          = "policylearn-rec-v1"
)

// Recommendation bounds.
const (
	maxRecommendationsPerGeneration = 64  // eligible cells beyond this are truncated (counted, deterministic order)
	maxRetainedRecommendations      = 256 // durable store cap (superseded evicted first, then FIFO)
)

// Sentinel errors for generation.
var (
	ErrSessionNotFound = errors.New("policylearn: session not found")
	// ErrSessionNotCompleted: only a terminal COMPLETED session generates —
	// never Learning (evidence still moving) and never Cancelled
	// (non-authoritative by definition).
	ErrSessionNotCompleted = errors.New("policylearn: recommendations require a completed session")
	// ErrNoGuardrailBaseline: the session predates guardrail pinning (schema v2
	// store) — without a pinned allowlist identity the evidence cannot be
	// interpreted against ANY guardrail set; fail closed, never guess.
	ErrNoGuardrailBaseline = errors.New("policylearn: session has no pinned guardrails baseline (pre-M4 session) — start a new session")
	// ErrGuardrailsChanged: the current recommendable-category allowlist differs
	// from the one pinned at session start. Never silently regenerate or
	// reinterpret old evidence under new guardrails.
	ErrGuardrailsChanged = errors.New("policylearn: recommendable-category guardrails changed since this session was pinned — evidence is stale for generation; start a new session")
	// ErrSubjectKeyChanged: the pseudonym key rotated mid-session, so the same
	// user may hold two disjoint tokens — distinct-subject counts can OVERSTATE
	// diversity, the one direction evidence must never err in (ADR-0025).
	// Ineligible (the safer disposition vs. a capped-LOW recommendation, whose
	// subject figures would still be presented while known-unsound).
	ErrSubjectKeyChanged = errors.New("policylearn: subject pseudonym key changed mid-session — distinct-subject evidence may double-count; session ineligible for recommendations")
)

// Thresholds are the explicit, testable confidence predicates (spec: named
// deterministic predicates, no composite scores). Zero fields take the defaults
// below. HIGH structurally requires distinct-subject AND distinct-day diversity
// in addition to request volume — volume alone can never reach HIGH.
type Thresholds struct {
	HighMinAllowedRequests   int64 // default 30
	HighMinSubjects          int   // default 5
	HighMinDays              int   // default 5
	MediumMinAllowedRequests int64 // default 5
	MediumMinSubjects        int   // default 2
	MediumMinDays            int   // default 2
	// CommunityTiers names the category-resolution tiers treated as
	// community/UT1-sourced for the community-majority confidence cap. Tier
	// strings are opaque to the engine; the default matches the root resolver's
	// taxonomy. Empty ⇒ default.
	CommunityTiers []string
}

func (t Thresholds) withDefaults() Thresholds {
	if t.HighMinAllowedRequests <= 0 {
		t.HighMinAllowedRequests = 30
	}
	if t.HighMinSubjects <= 0 {
		t.HighMinSubjects = 5
	}
	if t.HighMinDays <= 0 {
		t.HighMinDays = 5
	}
	if t.MediumMinAllowedRequests <= 0 {
		t.MediumMinAllowedRequests = 5
	}
	if t.MediumMinSubjects <= 0 {
		t.MediumMinSubjects = 2
	}
	if t.MediumMinDays <= 0 {
		t.MediumMinDays = 2
	}
	if len(t.CommunityTiers) == 0 {
		t.CommunityTiers = []string{defaultCommunityTier}
	}
	return t
}

// ProposedRule is the engine-owned rule-shape DTO — deliberately NOT the root
// policy-rule type (the wall makes importing it impossible). Fixed semantics:
// Action=Allow, SSLAction=Inspect, Enabled=false; only the group/category pair
// varies, and both are copied exactly from the observed evidence.
type ProposedRule struct {
	Action       string `json:"action"`     // always "Allow"
	SSLAction    string `json:"ssl_action"` // always "Inspect"
	Enabled      bool   `json:"enabled"`    // always false (born disabled)
	SourceGroup  string `json:"source_group"`
	DestCategory string `json:"dest_category"`
}

// HostCount / AttributionCount are the deterministic (sorted-slice) forms of
// the aggregate's bounded maps — the recommendation DTOs carry no maps so
// marshal order is fixed.
type HostCount struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

type AttributionCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Evidence is the by-value copy of one cell's facts at generation time,
// independent of the live aggregate. Field naming carries the evidence
// direction: every subject/day/host/first-last figure is ALLOWED-only by M3
// construction. Blocked traffic appears as request counts ONLY — there is no
// field for blocked users/subjects because that fact is never collected.
type Evidence struct {
	AllowedRequests       int64 `json:"allowed_requests"`
	PolicyBlockedRequests int64 `json:"policy_blocked_requests,omitempty"` // request count — NOT a user count
	ThreatBlockedRequests int64 `json:"threat_blocked_requests,omitempty"` // request count — NOT a user count

	ObservedAllowedSubjects int   `json:"observed_allowed_subjects"`         // exact distinct pseudonymous tokens admitted
	SubjectsIsLowerBound    bool  `json:"subjects_is_lower_bound,omitempty"` // overflow occurred: true count ≥ the figure
	SubjectOverflow         int64 `json:"subject_overflow,omitempty"`

	AllowedObservationDays int   `json:"allowed_observation_days"`
	DaysIsLowerBound       bool  `json:"days_is_lower_bound,omitempty"`
	DayOverflow            int64 `json:"day_overflow,omitempty"`

	AllowedFirstSeen int64 `json:"allowed_first_seen,omitempty"` // unix seconds
	AllowedLastSeen  int64 `json:"allowed_last_seen,omitempty"`

	TopAllowedHosts   []HostCount `json:"top_allowed_hosts,omitempty"` // admission-bounded representatives
	OtherAllowedHosts int64       `json:"other_allowed_hosts,omitempty"`

	// RuleHits attributes the WHOLE cell (all evidence directions) by matched
	// RuleID; DefaultActionRuleKey marks default-action decisions and can never
	// collide with a real ULID. Factual only — no redundancy/obsolescence
	// inference is derived or stored.
	RuleHits   []AttributionCount `json:"rule_hits,omitempty"`
	OtherRules int64              `json:"other_rules,omitempty"`
	TierHits   []AttributionCount `json:"tier_hits,omitempty"` // category-resolution tiers (whole cell)
	OtherTiers int64              `json:"other_tiers,omitempty"`
}

// CoverageEvidence is facts about how much of the population/window was
// observed — DISTINCT from Confidence. No fabricated denominators: there is no
// percentage field, and MembershipDenominatorKnown is structurally false in M4
// because no IdP membership input exists ("Confidence: HIGH / membership
// denominator unavailable" is a legitimate, honest pairing).
type CoverageEvidence struct {
	ObservedSubjects           int             `json:"observed_subjects"`
	SubjectsIsLowerBound       bool            `json:"subjects_is_lower_bound,omitempty"`
	ObservationDays            int             `json:"observation_days"`
	DaysIsLowerBound           bool            `json:"days_is_lower_bound,omitempty"`
	SessionWindowDays          int             `json:"session_window_days,omitempty"` // whole session span (calendar days, inclusive)
	TransportLoss              TransportWindow `json:"transport_loss,omitempty"`      // session-window loss accounting (deltas)
	TransportDegraded          bool            `json:"transport_degraded,omitempty"`
	MembershipDenominatorKnown bool            `json:"membership_denominator_known"` // constant false in M4 — no membership input exists
}

// Recommendation is the immutable durable advisory object. Evidence, coverage,
// and baseline are copied BY VALUE at generation — later reads show generation-
// time facts regardless of live-cell churn. The only field that ever changes
// after creation is State (generated → superseded, the supersession latch).
type Recommendation struct {
	ID                string           `json:"id"` // content-derived (deterministic); see recID
	SessionID         string           `json:"session_id"`
	State             string           `json:"state"`
	Group             string           `json:"group"`    // exact observed real group (no scope prefix)
	Category          string           `json:"category"` // exact allowlisted category
	ProposedRule      ProposedRule     `json:"proposed_rule"`
	Confidence        string           `json:"confidence"`
	ConfidenceReasons []string         `json:"confidence_reasons,omitempty"` // named predicates supporting the level
	ConfidenceLimits  []string         `json:"confidence_limits,omitempty"`  // named caps/limitations constraining it
	Coverage          CoverageEvidence `json:"coverage"`
	Evidence          Evidence         `json:"evidence"`
	// Generation-identity pins (by-value): Baseline carries PolicyGeneration,
	// DefaultAction, CategoryEpoch and GuardrailsHash as pinned at session
	// start; SubjectKeyID pins the pseudonym-key identity the subject evidence
	// was minted under; EngineSchema pins the store schema at generation.
	Baseline     Baseline `json:"baseline"`
	SubjectKeyID string   `json:"subject_key_id,omitempty"`
	EvidenceHash string   `json:"evidence_hash"` // canonical content hash (identity/idempotency anchor)
	EngineSchema int      `json:"engine_schema"`
	GeneratedAt  string   `json:"generated_at"` // RFC3339 UTC (injected clock)
}

func (r *Recommendation) clone() Recommendation {
	c := *r
	c.ConfidenceReasons = append([]string(nil), r.ConfidenceReasons...)
	c.ConfidenceLimits = append([]string(nil), r.ConfidenceLimits...)
	c.Evidence.TopAllowedHosts = append([]HostCount(nil), r.Evidence.TopAllowedHosts...)
	c.Evidence.RuleHits = append([]AttributionCount(nil), r.Evidence.RuleHits...)
	c.Evidence.TierHits = append([]AttributionCount(nil), r.Evidence.TierHits...)
	return c
}

// GenerateResult is the per-call accounting for one generation pass. Every
// bound and skip is COUNTED (no silent truncation — the no-silent-caps house
// rule); the recommendations returned are deep copies of the CURRENT generated
// set for the session, sorted by (group, category).
type GenerateResult struct {
	SessionID                string
	Recommendations          []Recommendation
	EligibleCells            int // cells that passed every eligibility gate
	TruncatedCells           int // eligible cells beyond maxRecommendationsPerGeneration
	SkippedSyntheticScope    int // s:unauth / s:groupless — evidence-only populations
	SkippedCategory          int // empty or non-allowlisted category (fail-closed)
	SkippedNoAllowedEvidence int // no positive allowed evidence in the cell
	SupersededCount          int // prior recommendations replaced by changed content
	UnchangedCount           int // idempotent hits (identical content already stored)
}

// ── Guardrails (fail-closed allowlist) ───────────────────────────────────────

// canonicalizeCategories produces the deterministic canonical allowlist form:
// whitespace-trimmed, empties dropped, deduplicated, sorted. Matching is EXACT
// (case-sensitive) — the allowlist is a fail-closed ALLOWLIST, so any mismatch
// (case, spacing, rename) makes a category non-recommendable, never the
// reverse.
func canonicalizeCategories(in []string) []string {
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

// guardrailsHashFor is the deterministic identity of a canonical allowlist —
// pinned into every session Baseline at Start and compared at generation. A
// pure function: same canonical list ⇒ same hash on every node and restart.
func guardrailsHashFor(canonical []string) string {
	h := sha256.New()
	h.Write([]byte(guardrailsHashDomainTag))
	var l [4]byte
	for _, c := range canonical {
		binary.BigEndian.PutUint32(l[:], uint32(len(c)))
		h.Write(l[:])
		h.Write([]byte(c))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// GuardrailsHash exposes the engine's current guardrail identity (read-only).
func (e *Engine) GuardrailsHash() string { return e.guardrailsHash }

// RecommendableCategories returns the canonical allowlist (copy).
func (e *Engine) RecommendableCategories() []string {
	return append([]string(nil), e.allowlist...)
}

// ── Generation ───────────────────────────────────────────────────────────────

// GenerateRecommendations deterministically generates recommendations from the
// COMPLETED session sessionID. Eligibility gates (each named, each fail-closed;
// note blocked traffic is deliberately NOT a gate — negative evidence never
// rejects a cell, it only appears as factual counts):
//
//	session_completed    — State == Completed (Learning/Cancelled refuse)
//	guardrails_pinned    — Baseline.GuardrailsHash present (pre-M4 sessions refuse)
//	guardrails_match     — pinned hash == current hash (stale ⇒ refuse, never reinterpret)
//	subject_key_stable   — no mid-session pseudonym-key change (see ErrSubjectKeyChanged)
//	real_group_scope     — cell scope is g:<group> (synthetic scopes are evidence-only)
//	category_allowlisted — cell category non-empty AND on the canonical allowlist
//	allowed_evidence     — cell.Allowed > 0 (something was actually observed allowed)
//
// Repeated generation is idempotent: identical content (same EvidenceHash) is
// kept, not duplicated; changed content supersedes the prior object. Persists
// before returning (rollback on failure).
func (e *Engine) GenerateRecommendations(sessionID string) (GenerateResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.readOnly {
		return GenerateResult{}, ErrStoreReadOnly
	}
	now := e.cfg.Now()
	e.maybeExpireLocked(now)
	var sess *Session
	for _, s := range e.sessions {
		if s.ID == sessionID {
			sess = s
			break
		}
	}
	switch {
	case sess == nil:
		return GenerateResult{}, ErrSessionNotFound
	case sess.State != StateCompleted:
		return GenerateResult{}, ErrSessionNotCompleted
	case sess.Baseline.GuardrailsHash == "":
		return GenerateResult{}, ErrNoGuardrailBaseline
	case sess.Baseline.GuardrailsHash != e.guardrailsHash:
		return GenerateResult{}, ErrGuardrailsChanged
	case sess.Agg != nil && sess.Agg.SubjectKeyChanged:
		return GenerateResult{}, ErrSubjectKeyChanged
	}

	res := GenerateResult{SessionID: sessionID}
	built := buildRecommendations(sess, e.allowSet, e.th, now, &res)

	// Merge with the durable set: idempotent on identical content, supersede on
	// changed content, at most one "generated" per (session, group, category).
	// Copy-on-write so a failed persist rolls back cleanly.
	builtByID := make(map[string]bool, len(built))
	builtTriple := make(map[string]bool, len(built))
	for _, b := range built {
		builtByID[b.ID] = true
		builtTriple[tripleKey(b.SessionID, b.Group, b.Category)] = true
	}
	satisfied := make(map[string]bool, len(built))
	merged := make([]*Recommendation, 0, len(e.recs)+len(built))
	for _, r := range e.recs {
		switch {
		case builtByID[r.ID]:
			// This exact content is the current generation output. Keep the
			// original object (original GeneratedAt — idempotency); if a later
			// generation had superseded it and the content is current again,
			// restore it to generated so the triple has exactly one live object.
			satisfied[r.ID] = true
			res.UnchangedCount++
			if r.State != RecStateGenerated {
				c := r.clone()
				c.State = RecStateGenerated
				merged = append(merged, &c)
				continue
			}
			merged = append(merged, r)
		case r.SessionID == sessionID && builtTriple[tripleKey(r.SessionID, r.Group, r.Category)] && r.State == RecStateGenerated:
			// Same triple, different content: superseded by this generation.
			c := r.clone()
			c.State = RecStateSuperseded
			merged = append(merged, &c)
			res.SupersededCount++
		default:
			merged = append(merged, r)
		}
	}
	for _, b := range built {
		if !satisfied[b.ID] {
			merged = append(merged, b)
		}
	}
	merged = pruneRecommendations(merged)

	prev := e.recs
	e.recs = merged
	if err := e.saveLocked(); err != nil {
		e.recs = prev
		return GenerateResult{}, err
	}

	// Result: deep copies of the CURRENT generated set for this session,
	// deterministic (group, category) order.
	for _, r := range e.recs {
		if r.SessionID == sessionID && r.State == RecStateGenerated {
			res.Recommendations = append(res.Recommendations, r.clone())
		}
	}
	sort.Slice(res.Recommendations, func(i, j int) bool {
		a, b := res.Recommendations[i], res.Recommendations[j]
		if a.Group != b.Group {
			return a.Group < b.Group
		}
		return a.Category < b.Category
	})
	return res, nil
}

// Recommendations returns deep copies of every retained recommendation in
// durable-store order.
func (e *Engine) Recommendations() []Recommendation {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Recommendation, 0, len(e.recs))
	for _, r := range e.recs {
		out = append(out, r.clone())
	}
	return out
}

// buildRecommendations is the PURE deterministic core: terminal session
// snapshot + allowlist set + thresholds + instant ⇒ ordered recommendations.
// It reads nothing but its inputs and mutates nothing but the result counters.
func buildRecommendations(sess *Session, allowSet map[string]bool, th Thresholds, now time.Time, res *GenerateResult) []*Recommendation {
	if sess.Agg == nil || len(sess.Agg.Cells) == 0 {
		return nil
	}
	keys := make([]string, 0, len(sess.Agg.Cells))
	for k := range sess.Agg.Cells {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic cell order ⇒ deterministic output order

	var out []*Recommendation
	for _, key := range keys {
		scope, category := SplitCellKey(key)
		if !strings.HasPrefix(scope, scopeGroupPrefix) {
			res.SkippedSyntheticScope++
			continue
		}
		if category == "" || !allowSet[category] {
			res.SkippedCategory++ // fail-closed: unknown or off-allowlist never recommends
			continue
		}
		cell := sess.Agg.Cells[key]
		if cell.Allowed <= 0 {
			res.SkippedNoAllowedEvidence++
			continue
		}
		res.EligibleCells++
		if len(out) >= maxRecommendationsPerGeneration {
			res.TruncatedCells++ // counted, never silent; deterministic sorted-order selection
			continue
		}
		out = append(out, newRecommendation(sess, strings.TrimPrefix(scope, scopeGroupPrefix), category, cell, th, now))
	}
	return out
}

// newRecommendation assembles one immutable recommendation from one eligible
// cell — evidence copied by value, confidence from named predicates, identity
// content-derived.
func newRecommendation(sess *Session, group, category string, cell *Cell, th Thresholds, now time.Time) *Recommendation {
	level, reasons, limits := confidenceFor(sess, cell, th)
	r := &Recommendation{
		SessionID: sess.ID,
		State:     RecStateGenerated,
		Group:     group,
		Category:  category,
		ProposedRule: ProposedRule{
			Action:       proposedActionAllow,
			SSLAction:    proposedSSLInspect,
			Enabled:      false,
			SourceGroup:  group,
			DestCategory: category,
		},
		Confidence:        level,
		ConfidenceReasons: reasons,
		ConfidenceLimits:  limits,
		Coverage: CoverageEvidence{
			ObservedSubjects:           len(cell.Subjects),
			SubjectsIsLowerBound:       cell.SubjectOverflow > 0,
			ObservationDays:            len(cell.Days),
			DaysIsLowerBound:           cell.DayOverflow > 0,
			SessionWindowDays:          sessionWindowDays(sess),
			TransportLoss:              sess.Transport,
			TransportDegraded:          sess.Transport.Degraded(),
			MembershipDenominatorKnown: false, // no membership input exists in M4 — never fabricate a denominator
		},
		Evidence: Evidence{
			AllowedRequests:         cell.Allowed,
			PolicyBlockedRequests:   cell.Blocked,
			ThreatBlockedRequests:   cell.ThreatBlocked,
			ObservedAllowedSubjects: len(cell.Subjects),
			SubjectsIsLowerBound:    cell.SubjectOverflow > 0,
			SubjectOverflow:         cell.SubjectOverflow,
			AllowedObservationDays:  len(cell.Days),
			DaysIsLowerBound:        cell.DayOverflow > 0,
			DayOverflow:             cell.DayOverflow,
			AllowedFirstSeen:        cell.FirstSeen,
			AllowedLastSeen:         cell.LastSeen,
			TopAllowedHosts:         sortedHostCounts(cell.TopHosts),
			OtherAllowedHosts:       cell.OtherHosts,
			RuleHits:                sortedAttribution(cell.RuleHits),
			OtherRules:              cell.OtherRules,
			TierHits:                sortedAttribution(cell.TierHits),
			OtherTiers:              cell.OtherTiers,
		},
		Baseline:     sess.Baseline,
		SubjectKeyID: sess.SubjectKeyID,
		EngineSchema: SchemaVersion,
		GeneratedAt:  rfc3339(now),
	}
	r.EvidenceHash = evidenceHash(r)
	r.ID = recID(r.SessionID, r.Group, r.Category, r.EvidenceHash)
	return r
}

// confidenceFor derives the confidence level from the named predicates, then
// applies the honesty caps. Every cap is recorded as a limit even when the
// level is already below HIGH (the loss must be identified, not just acted on).
// Subject/day OVERFLOW is deliberately NOT a cap: the exact admitted count is
// an honest lower bound (spec: overflow affects coverage exactness, and the
// figures used here are the exact admitted counts, never estimates).
func confidenceFor(sess *Session, c *Cell, th Thresholds) (level string, reasons, limits []string) {
	subjects := len(c.Subjects)
	days := len(c.Days)
	switch {
	case c.Allowed >= th.HighMinAllowedRequests && subjects >= th.HighMinSubjects && days >= th.HighMinDays:
		level = ConfidenceHigh
		reasons = append(reasons,
			fmt.Sprintf("allowed_requests:%d>=%d", c.Allowed, th.HighMinAllowedRequests),
			fmt.Sprintf("distinct_allowed_subjects:%d>=%d", subjects, th.HighMinSubjects),
			fmt.Sprintf("distinct_allowed_days:%d>=%d", days, th.HighMinDays))
	case c.Allowed >= th.MediumMinAllowedRequests && subjects >= th.MediumMinSubjects && days >= th.MediumMinDays:
		level = ConfidenceMedium
		reasons = append(reasons,
			fmt.Sprintf("allowed_requests:%d>=%d", c.Allowed, th.MediumMinAllowedRequests),
			fmt.Sprintf("distinct_allowed_subjects:%d>=%d", subjects, th.MediumMinSubjects),
			fmt.Sprintf("distinct_allowed_days:%d>=%d", days, th.MediumMinDays))
	default:
		level = ConfidenceLow
		reasons = append(reasons, fmt.Sprintf("allowed_requests:%d", c.Allowed))
		if c.Allowed < th.MediumMinAllowedRequests {
			limits = append(limits, fmt.Sprintf("below_medium_allowed_requests:%d<%d", c.Allowed, th.MediumMinAllowedRequests))
		}
		if subjects < th.MediumMinSubjects {
			limits = append(limits, fmt.Sprintf("below_medium_subject_diversity:%d<%d", subjects, th.MediumMinSubjects))
		}
		if days < th.MediumMinDays {
			limits = append(limits, fmt.Sprintf("below_medium_day_diversity:%d<%d", days, th.MediumMinDays))
		}
	}

	capBelowHigh := func(limit string) {
		limits = append(limits, limit)
		if level == ConfidenceHigh {
			level = ConfidenceMedium
		}
	}
	if sess.Transport.Degraded() {
		capBelowHigh(fmt.Sprintf("transport_loss:dropped=%d,rejected=%d,panics=%d",
			sess.Transport.Dropped, sess.Transport.Rejected, sess.Transport.ConsumerPanics))
	}
	churnOverflow := int64(0)
	if sess.Agg != nil {
		churnOverflow = sess.Agg.ChurnOverflow
	}
	if len(sess.CategoryChurn) > 0 || churnOverflow > 0 {
		capBelowHigh(fmt.Sprintf("category_churn:changes=%d,overflow=%d", len(sess.CategoryChurn), churnOverflow))
	}
	if communityTierMajority(c, th) {
		capBelowHigh("community_tier_majority")
	}
	return level, reasons, limits
}

// communityTierMajority reports whether a strict majority of the cell's
// tier-attributed observations resolved through a community/UT1 tier — the
// lower-trust source whose miscategorizations must not carry a HIGH claim.
// OtherTiers (unattributed overflow) counts in the denominator only: unknown
// provenance can weaken the majority, never establish it.
func communityTierMajority(c *Cell, th Thresholds) bool {
	var community, total int64
	commSet := make(map[string]bool, len(th.CommunityTiers))
	for _, t := range th.CommunityTiers {
		commSet[t] = true
	}
	for tier, n := range c.TierHits {
		total += n
		if commSet[tier] {
			community += n
		}
	}
	total += c.OtherTiers
	return total > 0 && community*2 > total
}

// sessionWindowDays computes the inclusive calendar-day span of the session
// window from its RFC3339 stamps (0 when unparseable — a fact omitted is safer
// than a fact invented).
func sessionWindowDays(sess *Session) int {
	start, err1 := time.Parse(time.RFC3339, sess.StartedAt)
	stop, err2 := time.Parse(time.RFC3339, sess.StoppedAt)
	if err1 != nil || err2 != nil || stop.Before(start) {
		return 0
	}
	startDay := start.UTC().Truncate(24 * time.Hour)
	stopDay := stop.UTC().Truncate(24 * time.Hour)
	return int(stopDay.Sub(startDay)/(24*time.Hour)) + 1
}

func sortedHostCounts(m map[string]int64) []HostCount {
	if len(m) == 0 {
		return nil
	}
	out := make([]HostCount, 0, len(m))
	for h, n := range m {
		out = append(out, HostCount{Host: h, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	return out
}

func sortedAttribution(m map[string]int64) []AttributionCount {
	if len(m) == 0 {
		return nil
	}
	out := make([]AttributionCount, 0, len(m))
	for k, n := range m {
		out = append(out, AttributionCount{Key: k, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// evidenceHash is the canonical content identity: everything EXCEPT the fields
// derived from it (ID, EvidenceHash) and the volatile ones (State,
// GeneratedAt). Maps-free DTOs make json.Marshal deterministic, so identical
// content always hashes identically — the idempotency/supersession anchor.
func evidenceHash(r *Recommendation) string {
	content := struct {
		SessionID         string           `json:"sid"`
		Group             string           `json:"g"`
		Category          string           `json:"c"`
		ProposedRule      ProposedRule     `json:"rule"`
		Confidence        string           `json:"conf"`
		ConfidenceReasons []string         `json:"reasons"`
		ConfidenceLimits  []string         `json:"limits"`
		Coverage          CoverageEvidence `json:"cov"`
		Evidence          Evidence         `json:"ev"`
		Baseline          Baseline         `json:"base"`
		SubjectKeyID      string           `json:"skid"`
		EngineSchema      int              `json:"schema"`
	}{
		r.SessionID, r.Group, r.Category, r.ProposedRule, r.Confidence,
		r.ConfidenceReasons, r.ConfidenceLimits, r.Coverage, r.Evidence,
		r.Baseline, r.SubjectKeyID, r.EngineSchema,
	}
	raw, err := json.Marshal(content)
	if err != nil {
		// Structurally impossible (fixed struct of marshalable fields); a fixed
		// marker beats a panic in a persistence path.
		return "marshal-error"
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

// recID derives the deterministic recommendation identity (length-framed so no
// field-boundary ambiguity — the pseudonym.go framing precedent).
func recID(sessionID, group, category, evidenceHash string) string {
	h := sha256.New()
	h.Write([]byte(recIDDomainTag))
	var l [4]byte
	for _, s := range []string{sessionID, group, category, evidenceHash} {
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		h.Write(l[:])
		h.Write([]byte(s))
	}
	return hex.EncodeToString(h.Sum(nil)[:12])
}

func tripleKey(sessionID, group, category string) string {
	return sessionID + cellKeySep + group + cellKeySep + category
}

// pruneRecommendations enforces the durable cap deterministically: superseded
// objects are evicted first (store order = oldest first), then generated FIFO.
// Eviction only ever discards history — it can never change a surviving
// object's content or state.
func pruneRecommendations(recs []*Recommendation) []*Recommendation {
	over := len(recs) - maxRetainedRecommendations
	if over <= 0 {
		return recs
	}
	kept := make([]*Recommendation, 0, maxRetainedRecommendations)
	for _, r := range recs { // pass 1: drop superseded, oldest first
		if over > 0 && r.State == RecStateSuperseded {
			over--
			continue
		}
		kept = append(kept, r)
	}
	if over > 0 { // pass 2: still over cap — FIFO on what remains
		kept = kept[over:]
	}
	return kept
}

// ── Staleness (pure helper for M5 — deliberately unwired) ────────────────────

// StaleInputs are the CURRENT identities a recommendation's pins are compared
// against. The caller (M5's surface, eventually) supplies them explicitly —
// this package cannot and does not read live state.
type StaleInputs struct {
	PolicyGeneration int64
	CategoryEpoch    string
	GuardrailsHash   string
	SubjectKeyID     string
}

// StaleReasons is the pure staleness computation: the named pin mismatches
// between a recommendation's generation-time identities and the supplied
// current ones. Empty ⇒ fresh. Computed on demand — never latched, never
// persisted — so it cannot rot or race.
func StaleReasons(r *Recommendation, cur StaleInputs) []string {
	var out []string
	if r.Baseline.PolicyGeneration != cur.PolicyGeneration {
		out = append(out, "policy_generation_changed")
	}
	if r.Baseline.CategoryEpoch != cur.CategoryEpoch {
		out = append(out, "category_epoch_changed")
	}
	if r.Baseline.GuardrailsHash != cur.GuardrailsHash {
		out = append(out, "guardrails_changed")
	}
	if r.SubjectKeyID != "" && cur.SubjectKeyID != "" && r.SubjectKeyID != cur.SubjectKeyID {
		out = append(out, "subject_key_changed")
	}
	return out
}
