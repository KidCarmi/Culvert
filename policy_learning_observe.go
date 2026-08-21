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

// daWord is the packed default-action state word applyPolicyDecision's
// DEFAULT branch loaded to make its decision (0 = not a default-branch
// decision, or no capture — falls back to the engine's enqueue-time seam
// stamp). Codex round 20: stamping the policy identity from a post-decision
// read let a full flip-and-restore inside the decision→stamp window pair
// transient-window evidence with the restored baseline identity, latching no
// churn. The word is strictly increasing, so equality with the current word
// PROVES no default-action set intervened — the current memoized identity is
// then the decision identity; inequality proves one DID, and the stamp
// becomes a unique change witness that can never equal any content hash or
// baseline, so the consume-time comparison latches the churn we know
// happened.
func learnObserveDecision(auth authOutcome, host, method string, match *PolicyMatch, status, sslAction string, daWord uint64) {
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
	policyID := ""
	if (match == nil || match.Rule == nil) && daWord != 0 {
		if defaultPolicyActionState.Load() == daWord {
			// No set intervened since the enforcement load: the memoized
			// identity IS the decision identity (0-alloc — memoized string).
			policyID = policyContentIdentityCached()
		} else {
			// A set provably landed between the decision and this stamp. The
			// decision-time identity is unrecoverable, so stamp a witness
			// unique to that decision word (allocates — flip-rate only,
			// never steady-state).
			policyID = "default-action-flip@" + strconv.FormatUint(daWord, 16)
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
	})
}
