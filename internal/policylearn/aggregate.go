package policylearn

// M3 — bounded FACTUAL aggregation: Group × Category cells built in the drain
// (never on the request hot path). Facts only — no confidence, no readiness,
// no recommendation semantics.
//
// Evidence-direction invariant (ADR-0025): every bound is enforced with
// admission/eviction semantics whose failure direction WEAKENS future claims —
// an overflow discards the new contribution and counts the loss; nothing is
// ever folded into an existing figure in a way that could raise coverage or
// distinct-subject counts. Blocked traffic is structurally separated from
// allowed traffic (distinct counters; the allowed-evidence sets — subjects,
// days, hosts, first/last seen — are updated by ALLOWED observations only), so
// blocked observations can never later surface as positive ALLOW evidence.
//
// Scope-key namespace (multi-group semantics): a real IdP group aggregates
// under "g:<name>"; synthetic populations use the reserved "s:" prefix —
// "s:unauth" (no resolved subject) and "s:groupless" (authenticated, no
// groups). A hostile or unlucky IdP group literally named "unauth" lands under
// "g:unauth" and can never collide with the synthetic scope.

import (
	"strings"
	"time"
	"unicode"
)

// Aggregation bounds (all package constants — deterministic, admin-independent).
const (
	maxCells              = 8192  // distinct (scope, category) cells per session
	maxSubjectsPerCell    = 512   // exact distinct-subject tokens per cell
	maxSubjectTokensTotal = 65536 // global token budget across all cells (~2 MB ceiling)
	maxDaysPerCell        = 92    // distinct UTC observation days per cell
	maxTopHosts           = 10    // representative destinations per cell
	maxRuleHits           = 8     // per-cell rule-attribution entries
	maxTierHits           = 8     // per-cell category-tier entries (defensive; tiers are a small closed set)
	maxCategoryChurn      = 8     // recorded category-epoch changes per session

	flushEvery = 1024 // drain-side persist cadence (aggregated observations)
)

// Scope-key construction. The "g:"/"s:" prefixes are the collision wall.
const (
	scopeGroupPrefix = "g:"
	ScopeUnauth      = "s:unauth"
	ScopeGroupless   = "s:groupless"
	cellKeySep       = "\x1f" // unit separator between scope and category
)

// Cell is one bounded Group × Category evidence cell. Maps marshal with
// sorted keys, so persistence is deterministic.
type Cell struct {
	// Factual counters, structurally split by evidence direction. Requests =
	// Allowed + Blocked + ThreatBlocked for THIS cell (an observation carrying
	// N groups contributes to N cells — per-cell counts are per-population
	// views, deliberately not summable across cells; session-level totals live
	// on the session transport counters).
	Requests      int64 `json:"requests"`
	Allowed       int64 `json:"allowed"`
	Blocked       int64 `json:"blocked"`        // policy-plane blocks (POLICY_*/FILE_BLOCKED/…)
	ThreatBlocked int64 `json:"threat_blocked"` // pre-dispatch threat/blocklist/plugin blocks

	// Allowed-evidence sets (updated by ALLOWED observations only).
	Subjects        map[string]bool  `json:"subjects,omitempty"` // pseudonymous tokens — never raw subjects
	SubjectOverflow int64            `json:"subject_overflow,omitempty"`
	Days            map[string]bool  `json:"days,omitempty"` // distinct UTC dates (YYYY-MM-DD)
	DayOverflow     int64            `json:"day_overflow,omitempty"`
	FirstSeen       int64            `json:"first_seen,omitempty"` // unix seconds, allowed evidence
	LastSeen        int64            `json:"last_seen,omitempty"`
	TopHosts        map[string]int64 `json:"top_hosts,omitempty"` // admission-bounded representative destinations
	OtherHosts      int64            `json:"other_hosts,omitempty"`

	// Attribution breakdowns (all evidence directions; bounded).
	RuleHits   map[string]int64 `json:"rule_hits,omitempty"` // ruleID → count ("" = default action, keyed "_default_")
	OtherRules int64            `json:"other_rules,omitempty"`
	TierHits   map[string]int64 `json:"tier_hits,omitempty"` // category tier → count
	OtherTiers int64            `json:"other_tiers,omitempty"`
}

// EpochChurn records one category-generation change observed mid-session.
type EpochChurn struct {
	At string `json:"at"` // RFC3339 UTC
	To string `json:"to"` // the new epoch value (opaque)
}

// Aggregate is the per-session bounded aggregation state.
type Aggregate struct {
	Cells map[string]*Cell `json:"cells,omitempty"` // key: scope + \x1f + category

	// Loss/degradation accounting (evidence can only weaken on overflow).
	CellsDropped        int64 `json:"cells_dropped,omitempty"`       // contributions refused at the cell cap
	SubjectBudgetUsed   int64 `json:"subject_budget_used,omitempty"` // global token budget consumption
	ChurnOverflow       int64 `json:"churn_overflow,omitempty"`
	PolicyChurnOverflow int64 `json:"policy_churn_overflow,omitempty"` // policy-content changes past the bounded list (schema v8)
	SubjectKeyChanged   bool  `json:"subject_key_changed,omitempty"`   // key rotated/lost mid-session — token populations before/after are disjoint
}

func newAggregate() *Aggregate {
	return &Aggregate{Cells: map[string]*Cell{}}
}

// evidence direction classes, derived from the decision Status ONLY (server-
// derived taxonomy; Action is not consulted).
type evidenceClass int

const (
	classAllowed evidenceClass = iota
	classBlocked
	classThreat
)

func classifyStatus(status string) evidenceClass {
	switch status {
	case "OK":
		return classAllowed
	case "THREAT_BLOCKED", "BLOCKED":
		// Pre-dispatch plane: threat feed, blocklist, plugin. Context/negative
		// evidence only.
		return classThreat
	default:
		// POLICY_BLOCK / POLICY_DROP / POLICY_REDIRECT / POLICY_DEFAULT_DENY /
		// FILE_BLOCKED / anything unknown: policy-plane block. Unknown statuses
		// deliberately land here — fail toward negative evidence.
		return classBlocked
	}
}

// foldGroup returns the canonical representative of a group name under the
// enforcement comparison's EQUIVALENCE (containsGroupCI: trim + EqualFold).
// strings.ToLower alone is NOT that equivalence for Unicode — Σ/ς/σ (and
// S/ſ, K/U+212A) compare equal under EqualFold but lower to different
// strings (Codex fix). EqualFold's per-rune equivalence classes are the
// unicode.SimpleFold cycles, so the canonical rune is a fixed member of the
// cycle: the cycle's minimum, replaced by its ToLower form ONLY when that
// form belongs to the SAME cycle (Codex round-11 fix — an unconditional
// ToLower merged DISTINCT cycles: İ/U+0130 is a singleton cycle,
// EqualFold("İ","i") is false, yet ToLower maps it onto ASCII i, so a group
// named İ would be recommended as — and authorize — the different ASCII-I
// population). The representative is always a member of its own cycle, so
// distinct cycles keep distinct representatives, ASCII keeps its familiar
// lowercase form, and two strings map equal exactly when EqualFold reports
// them equal.
func foldGroup(g string) string {
	return strings.Map(canonicalFoldRune, strings.TrimSpace(g))
}

func canonicalFoldRune(r rune) rune {
	rep := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < rep {
			rep = f
		}
	}
	if low := unicode.ToLower(rep); low != rep {
		for f := unicode.SimpleFold(rep); f != rep; f = unicode.SimpleFold(f) {
			if f == low {
				return low
			}
		}
	}
	return rep
}

// scopesFor returns the population scopes an observation contributes to.
// scratch is reused to keep the drain allocation-light.
func scopesFor(o *Observation, scratch []string) []string {
	scratch = scratch[:0]
	if o.Subject == "" {
		return append(scratch, ScopeUnauth)
	}
	// An EMPTY group name must never mint the real-group scope "g:" (Codex
	// fix): generation would strip the prefix into an empty source group,
	// which the enforcement layer treats as "any source" — an IdP emitting an
	// empty array entry would turn an accepted per-group recommendation into
	// an allow-for-everyone rule. Empty entries are skipped; an identity
	// whose groups are ALL empty aggregates as groupless.
	for _, g := range o.Groups {
		// Canonical population key (Codex fix): enforcement compares groups
		// TRIMMED and CASE-INSENSITIVELY (containsGroupCI), so case and
		// whitespace variants of one group name are ONE population — folding
		// here makes them share one cell across observations instead of
		// splitting evidence (or minting duplicate, semantically identical
		// recommendations; a generated rule's SourceGroup is the folded form,
		// which enforcement matches case-insensitively).
		g = foldGroup(g)
		if g == "" {
			continue
		}
		// A group name asserted MORE THAN ONCE in one identity (the OIDC/SAML
		// extractors preserve duplicate claim values) must contribute exactly
		// one scope (Codex fix): duplicate scope keys would apply the single
		// observation repeatedly to the same cell, inflating counts — the one
		// direction evidence must never err in. Bounded O(n²) over at most
		// MaxObservationGroups entries.
		dup := false
		for _, s := range scratch {
			if s[len(scopeGroupPrefix):] == g {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		scratch = append(scratch, scopeGroupPrefix+g)
	}
	if len(scratch) == 0 {
		return append(scratch, ScopeGroupless)
	}
	return scratch
}

// aggregate folds one drained observation into the session aggregate. Called
// from the drain goroutine under e.mu (see consumeGuarded). sess is the
// session that was Learning when the observation was ACCEPTED — it may have
// gone terminal since (queued events still belong to it).
func (e *Engine) aggregateLocked(sess *Session, o *Observation) {
	if sess.Agg == nil {
		sess.Agg = newAggregate()
	}
	agg := sess.Agg
	if agg.Cells == nil {
		// A session persisted before its first cell round-trips Agg as {}
		// (every field omitempty), which decodes to a non-nil Aggregate with a
		// nil Cells map — same decoded-empty shape the Cell maps below handle
		// lazily. Without this init every post-restart observation of the
		// recovered session dies in per-event panic containment.
		agg.Cells = map[string]*Cell{}
	}

	category, tier := "", "none"
	if e.cfg.Categories != nil {
		category, tier = e.cfg.Categories(o.Host)
	}
	cls := classifyStatus(o.Status)
	token := ""
	if cls == classAllowed {
		token = e.subjKey.token(o.AuthSource, o.Subject)
	}
	day := time.Unix(o.At, 0).UTC().Format("2006-01-02")

	e.scopeScratch = scopesFor(o, e.scopeScratch)
	for _, scope := range e.scopeScratch {
		key := scope + cellKeySep + category
		cell, ok := agg.Cells[key]
		if !ok {
			if len(agg.Cells) >= maxCells {
				agg.CellsDropped++ // admission refused: the loss weakens claims, never inflates
				continue
			}
			cell = &Cell{}
			agg.Cells[key] = cell
		}
		cell.apply(agg, o, cls, token, day, tier)
	}
}

// apply folds one contribution into the cell under the evidence-direction
// invariant (allowed-only evidence sets).
func (c *Cell) apply(agg *Aggregate, o *Observation, cls evidenceClass, token, day, tier string) { //nolint:cyclop,nestif // one explicit admission branch per bounded evidence set (M3 spec)
	c.Requests++
	switch cls {
	case classAllowed:
		c.Allowed++
	case classThreat:
		c.ThreatBlocked++
	default:
		c.Blocked++
	}

	// Attribution breakdowns (all directions, bounded). A pre-dispatch block
	// never reached the policy evaluator, so it must not masquerade as a
	// default-action hit (Codex round 26).
	ruleKey := o.RuleID
	if ruleKey == "" {
		if o.Action == "predispatch" {
			ruleKey = PreDispatchRuleKey
		} else {
			ruleKey = DefaultActionRuleKey
		}
	}
	boundedCount(&c.RuleHits, &c.OtherRules, ruleKey, maxRuleHits)
	boundedCount(&c.TierHits, &c.OtherTiers, tier, maxTierHits)

	if cls != classAllowed {
		return // blocked/threat traffic contributes NO positive evidence
	}

	if c.FirstSeen == 0 || o.At < c.FirstSeen {
		c.FirstSeen = o.At
	}
	if o.At > c.LastSeen {
		c.LastSeen = o.At
	}
	if token != "" { //nolint:nestif // bounded-admission branches per evidence set (M3 spec)
		if c.Subjects == nil {
			c.Subjects = map[string]bool{}
		}
		if !c.Subjects[token] {
			if len(c.Subjects) >= maxSubjectsPerCell || agg.SubjectBudgetUsed >= maxSubjectTokensTotal {
				c.SubjectOverflow++ // unseen subject beyond the bound: counted, never estimated upward
			} else {
				c.Subjects[token] = true
				agg.SubjectBudgetUsed++
			}
		}
	}
	if c.Days == nil {
		c.Days = map[string]bool{}
	}
	if !c.Days[day] {
		if len(c.Days) >= maxDaysPerCell {
			c.DayOverflow++
		} else {
			c.Days[day] = true
		}
	}
	if c.TopHosts == nil {
		c.TopHosts = map[string]int64{}
	}
	if n, ok := c.TopHosts[o.Host]; ok {
		c.TopHosts[o.Host] = n + 1
	} else if len(c.TopHosts) < maxTopHosts {
		c.TopHosts[o.Host] = 1
	} else {
		c.OtherHosts++ // admission-bounded: the tail is counted, not sampled upward
	}
}

// boundedCount increments m[key], admitting at most bound distinct keys;
// overflow keys are counted in other.
func boundedCount(m *map[string]int64, other *int64, key string, bound int) { //nolint:gocritic // ptrToRefParam: the pointer is required — the nil map is lazily REPLACED (decoded-empty shape), not just written through
	if *m == nil {
		*m = map[string]int64{}
	}
	if n, ok := (*m)[key]; ok {
		(*m)[key] = n + 1
		return
	}
	if len(*m) >= bound {
		*other++
		return
	}
	(*m)[key] = 1
}

// checkEpochLocked records category-generation churn against the session
// baseline (bounded; overflow counted). Called under e.mu from the drain
// cadence and at session stop.
// checkEpochLocked latches category-epoch and policy-content churn. catEpoch/
// policyID, when non-empty, are the observation's DECISION-TIME stamps (Codex
// round 15) — a transient change completing while the event sat queued is
// visible only in the stamp, never in a consume-time seam read; empty values
// (the finish-time final check, or a seam-less test engine) fall back to the
// current seam reads. Caller holds e.mu.
func (e *Engine) checkEpochLocked(sess *Session, now time.Time, catEpoch, policyID string) {
	if sess == nil {
		return
	}
	if e.cfg.CategoryEpoch != nil {
		if catEpoch == "" {
			catEpoch = e.cfg.CategoryEpoch()
		}
		e.latchChurnLocked(sess, now, catEpoch, sess.Baseline.CategoryEpoch,
			&sess.CategoryChurn, func(a *Aggregate) *int64 { return &a.ChurnOverflow })
	}
	// Policy-content churn (schema v8, Codex round 13): an A→B→A policy round
	// trip during the session collects evidence under B; at generation time
	// the restored content hash matches the baseline again, so the round trip
	// is invisible to the identity comparison — it must be latched HERE, as
	// it happens, exactly like category churn.
	if e.cfg.PolicyContent != nil {
		if policyID == "" {
			policyID = e.cfg.PolicyContent()
		}
		e.latchChurnLocked(sess, now, policyID, sess.Baseline.PolicyContentHash,
			&sess.PolicyChurn, func(a *Aggregate) *int64 { return &a.PolicyChurnOverflow })
	}
}

// latchChurnLocked appends a churn record when cur differs from the LAST seen
// value (the pinned baseline, or the newest recorded churn — so a full A→B→A
// round trip records both edges); overflow past the bound is counted, never
// silent. Caller holds e.mu.
func (e *Engine) latchChurnLocked(sess *Session, now time.Time, cur, baseline string, churn *[]EpochChurn, overflow func(*Aggregate) *int64) {
	last := baseline
	if n := len(*churn); n > 0 {
		last = (*churn)[n-1].To
	}
	if cur == last {
		return
	}
	if len(*churn) >= maxCategoryChurn {
		if sess.Agg == nil {
			sess.Agg = newAggregate()
		}
		p := overflow(sess.Agg)
		*p++
		e.dirty = true
		return
	}
	*churn = append(*churn, EpochChurn{At: rfc3339(now), To: cur})
	e.dirty = true
}

// DistinctSubjects returns the exact tokenized count for a cell (callers must
// pair it with SubjectOverflow — ">= N" semantics once overflowed).
func (c *Cell) DistinctSubjects() int { return len(c.Subjects) }

// CellKey builds/splits the aggregate map key.
func CellKey(scope, category string) string { return scope + cellKeySep + category }

// SplitCellKey returns (scope, category).
func SplitCellKey(key string) (scope, category string) {
	if i := strings.IndexByte(key, 0x1f); i >= 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}
