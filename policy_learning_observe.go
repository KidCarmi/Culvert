package main

// M2 — the ONE runtime→learning adapter (ADR-0025). handleRequest calls
// learnObserveDecision once per policy decision; this is the only reference
// the request path holds to the learning subsystem (pinned by
// policylearn_wall_test.go). The transport is strictly one-way: runtime →
// observation → learning. Learning has no path back into enforcement.
//
// Disabled posture (the production default until the governed enablement
// slice lands): the singleton is nil, so this costs one atomic load and a
// predicted branch — no allocation, no goroutine, no I/O (benchgate-pinned).

import (
	"strconv"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

// learnObserveDecision emits one server-derived observation for a Stage-2
// policy decision. Every field comes from typed server-side state (the F6
// contract): the resolved auth context and the policy match — never a header
// or any client-supplied value. Non-blocking under every condition.
// learnObservePreDispatch emits one observation for a request blocked BEFORE
// policy evaluation (threat feed / blocklist / plugin / global file-extension
// gate). Context/negative evidence only — the aggregation model classifies
// these by their status and they can never contribute positive ALLOW evidence.
func learnObservePreDispatch(auth authOutcome, host, method, status string) {
	eng := policyLearnEngine.Load()
	if eng == nil || !eng.LearningActive() {
		// Disabled (nil) or enabled-but-idle: gate BEFORE any Observation is
		// built — no DTO, no group copy, no enqueue (M5A §1; benchgate-pinned).
		return
	}
	eng.Observe(policylearn.Observation{
		Subject:    auth.identity,
		AuthSource: auth.source,
		Groups:     auth.groups,
		Host:       host,
		Method:     method,
		Action:     "predispatch",
		Status:     status,
	})
}

// learnCategoryEpoch composes the opaque category-generation identity the
// learning engine pins per session (ADR-0025 §6): the signed SaaS feed's
// generation + overrides revision (atomically-swapped immutable view,
// unchanged from scheme v1) and the admin taxonomy's SEMANTIC content
// fingerprint (urlcat.Store.ContentFingerprint — QB-2 corrective slice).
// Opaque — the engine only compares equality. The community UT1 DB carries no
// generation identity today (recorded M3 finding); its churn is NOT
// represented here.
//
// Scheme v2 ("v2|" prefix): the admin component was previously the
// process-local urlcat revision COUNTER, which restarts reset, so an
// unchanged taxonomy produced a different epoch after every restart and
// staled every recommendation of any session that spanned one (preview
// qualification finding QB-2). The content fingerprint is restart-stable:
// same effective admin taxonomy ⇒ same identity; different ⇒ different. The
// "v2|" tag makes the scheme change explicit — a session or recommendation
// pinned under the old counter scheme can never compare equal to a v2 value,
// so pre-upgrade objects go stale exactly ONCE at upgrade (documented in the
// preview qualification record) instead of being silently reinterpreted.
// learnEpochMemo caches the composed epoch string keyed by its two components
// — the saas VIEW POINTER (each view is immutable after construction, so
// pointer identity implies content identity) and the cached admin
// fingerprint string (Codex round 15: Observe stamps the DECISION-TIME epoch
// on every enqueued observation, so the composition must be alloc-free on
// the request path — the concat re-runs only when a component actually
// changed).
type learnEpochMemoEntry struct {
	view  *effectiveCategoryView
	admin string
	epoch string
}

var learnEpochMemo atomic.Pointer[learnEpochMemoEntry]

func learnCategoryEpoch() string {
	view := saasEffectiveView.Current()
	admin := catStore.ContentFingerprint()
	if m := learnEpochMemo.Load(); m != nil && m.view == view && m.admin == admin {
		return m.epoch
	}
	saas := "none"
	if view != nil {
		saas = view.GenerationID + ":" + view.ConfigRevision
	}
	epoch := "v2|saas:" + saas + "|admin:" + admin
	learnEpochMemo.Store(&learnEpochMemoEntry{view: view, admin: admin, epoch: epoch})
	return epoch
}

// learnDecisionKey is the decision-identity fence: the policy identity key
// (rulebase generation, category-group revision, packed default-action word)
// PLUS the taxonomy the evaluation resolved host categories through — the
// effective saas view POINTER (each view is immutable and the key holds the
// pointer, so it cannot be recycled while captured: equality proves the same
// view) and the admin urlcat store's monotonic semantic-mutation counter
// (Codex round 22: the content fingerprint is ABA-blind — a taxonomy A→B→A
// round trip inside the bracket restores the same string, so only a counter
// can witness it). The community UT1 DB carries no change identity (recorded
// M3 limitation — the category epoch has never represented it); its churn
// remains outside this fence.
type learnDecisionKey struct {
	policy   policyContentKey
	saasView *effectiveCategoryView
	catRev   uint64
}

func learnDecisionKeyNow() learnDecisionKey {
	return learnDecisionKey{
		policy:   policyContentKeyNow(),
		saasView: saasEffectiveView.Current(),
		catRev:   catStore.Revision(),
	}
}

// learnDecisionKeySnapshot captures the full decision key for the
// evaluation→stamp bracket, gated on learning being active so the
// idle/disabled request path pays at most two atomic loads. handleRequest
// calls it BEFORE policy evaluation; the adapter fences both identity stamps
// against it AFTER the decision.
func learnDecisionKeySnapshot() (learnDecisionKey, bool) {
	eng := policyLearnEngine.Load()
	if eng == nil || !eng.LearningActive() {
		return learnDecisionKey{}, false
	}
	return learnDecisionKeyNow(), true
}

// pk is the full decision key captured BEFORE policy evaluation
// (havePK=false ⇒ no capture — falls back to the engine's enqueue-time seam
// stamps). Codex rounds 20–22: stamping the identities from post-decision
// reads let a full change-and-restore inside the evaluation→stamp window
// pair transient-window evidence with the restored baseline identities,
// latching no churn — and the decision depends on the WHOLE config (rulebase,
// category groups, default action, AND the taxonomy category resolution ran
// through), for matched and unmatched decisions alike. Each fence half is
// checked independently: sub-key equality with the current value PROVES no
// mutation of that half intervened anywhere in the bracket — the current
// memoized identity is then the decision identity; inequality proves one DID,
// and the stamp becomes a unique change witness that can never equal any
// content hash, epoch, or baseline, so the consume-time comparison latches
// the churn we know happened. (Halves are fenced separately so a
// default-action flip does not fabricate CATEGORY churn and vice versa.)
func learnObserveDecision(auth authOutcome, host, method string, match *PolicyMatch, status, sslAction string, pk learnDecisionKey, havePK bool) {
	eng := policyLearnEngine.Load()
	if eng == nil || !eng.LearningActive() {
		// Disabled (nil) or enabled-but-idle: gate BEFORE any Observation is
		// built — no DTO, no group copy, no enqueue (M5A §1; benchgate-pinned).
		return
	}
	ruleID := ""
	var action string
	switch {
	case match != nil && match.Rule != nil:
		ruleID = match.Rule.ID
		action = string(match.Action)
	case status == "POLICY_DEFAULT_DENY":
		// Derive the default-action label from the ENFORCEMENT's own recorded
		// status, never a re-read of the atomic (Codex round 16): a default-
		// action flip landing between applyPolicyDecision and this callback
		// mislabeled the observation against the decision that actually ran.
		// Static literals: no concat allocation on the hot path.
		action = "default:deny"
	default:
		action = "default:allow"
	}
	policyID, catEpoch := "", ""
	if havePK {
		cur := learnDecisionKeyNow()
		if cur.policy == pk.policy {
			// No policy-config mutation intervened since before evaluation:
			// the memoized identity IS the decision identity (0-alloc —
			// memoized string).
			policyID = policyContentIdentityCached()
		} else {
			// A mutation provably landed inside the evaluation→stamp bracket.
			// The decision-time identity is unrecoverable, so stamp a witness
			// unique to the captured key (allocates — config-change-rate
			// only, never steady-state).
			policyID = "policy-flip@" + strconv.FormatInt(pk.policy.gen, 16) + ":" +
				strconv.FormatUint(pk.policy.catgroupRev, 16) + ":" + strconv.FormatUint(pk.policy.defaultRev, 16)
		}
		if cur.saasView == pk.saasView && cur.catRev == pk.catRev {
			// Taxonomy unchanged across the bracket: the memoized epoch is the
			// one evaluation resolved through (0-alloc — memoized string).
			catEpoch = learnCategoryEpoch()
		} else {
			// A taxonomy swap or admin-store mutation landed inside the
			// bracket — the content-derived epoch is ABA-blind to a round
			// trip, so stamp a witness unique to the captured taxonomy state.
			catEpoch = "category-flip@" + strconv.FormatUint(pk.catRev, 16)
		}
	}
	eng.Observe(policylearn.Observation{
		Subject:    auth.identity,
		AuthSource: auth.source, // verbatim opaque provenance
		Groups:     auth.groups, // engine makes the bounded copy
		Host:       host,
		Method:     method,
		RuleID:     ruleID,
		Action:     action,
		Status:     status,
		SSLAction:  sslAction,
		PolicyID:   policyID, // "" ⇒ engine seam stamp at enqueue
		CatEpoch:   catEpoch, // "" ⇒ engine seam stamp at enqueue
	})
}
