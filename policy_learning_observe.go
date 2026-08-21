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
	policy policyContentKey
	tax    learnTaxKey
}

// learnTaxKey is the taxonomy half of the fence (compared independently of
// the policy half so a default-action flip never fabricates category churn
// and vice versa).
type learnTaxKey struct {
	saasView *effectiveCategoryView
	catRev   uint64
}

func learnTaxKeyNow() learnTaxKey {
	return learnTaxKey{saasView: saasEffectiveView.Current(), catRev: catStore.Revision()}
}

// learnTaxonomyToken is the engine's Config.TaxonomyKey seam (Codex round
// 24): the same monotonic taxonomy state as learnTaxKey, shaped as the
// engine's opaque token so the drain can bracket each observation's category
// RESOLUTION — the content-derived epoch is ABA-blind, so only these
// monotonic components can witness a round trip completing within one
// resolution. The token HOLDS the view pointer (no reuse while captured).
func learnTaxonomyToken() policylearn.TaxonomyToken {
	return policylearn.TaxonomyToken{View: saasEffectiveView.Current(), Rev: catStore.Revision()}
}

func learnDecisionKeyNow() learnDecisionKey {
	return learnDecisionKey{policy: policyContentKeyNow(), tax: learnTaxKeyNow()}
}

// learnFencedStamp returns identity() as the decision-time stamp ONLY when
// the sub-key equals want both BEFORE and AFTER the identity read (Codex
// round 23): the identity helpers re-read live state, so a config restore
// landing between the sub-key check and the identity read would stamp the
// RESTORED identity for evidence the decision derived under the transient
// state — and with the restore completing the round trip, consumption and
// the close-time check would both see the baseline and latch no churn. The
// post-read recheck closes that: every key component is monotonic, so
// equality on both sides proves no mutation overlapped the read and the
// returned identity describes exactly the captured state. ok=false ⇒ the
// caller stamps its flip witness.
func learnFencedStamp[K comparable](want K, keyNow func() K, identity func() string) (string, bool) {
	if keyNow() != want {
		return "", false
	}
	id := identity()
	if keyNow() != want {
		return "", false
	}
	return id, true
}

// learnDecisionCtx is the full decision-time capture: the identity fence key
// PLUS the engine and acceptance-window generation the decision ran under
// (Codex round 24 — a decision made while session A was active must never
// aggregate into a session B whose window opened mid-dispatch; A's finish
// barrier cannot wait for a producer that has not registered yet, so the
// adapter observes on the CAPTURED engine with the CAPTURED window stamp and
// a rotated window resolves as a counted drop, never as B's evidence).
type learnDecisionCtx struct {
	key learnDecisionKey
	eng *policylearn.Engine
	gen uint64
}

// learnDecisionSnapshot captures the full decision context for the
// evaluation→stamp bracket, gated on learning being active so the
// idle/disabled request path pays at most two atomic loads. handleRequest
// calls it BEFORE policy evaluation; the adapter fences both identity stamps
// against the key AFTER the decision and stamps into the captured window.
func learnDecisionSnapshot() (learnDecisionCtx, bool) {
	eng := policyLearnEngine.Load()
	if eng == nil || !eng.LearningActive() {
		return learnDecisionCtx{}, false
	}
	return learnDecisionCtx{key: learnDecisionKeyNow(), eng: eng, gen: eng.WindowGeneration()}, true
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
func learnObserveDecision(auth authOutcome, host, method string, match *PolicyMatch, status, sslAction string, ctx learnDecisionCtx, haveCtx bool) {
	if !haveCtx || ctx.eng == nil {
		// No decision-time capture: learning was disabled or idle when the
		// decision was made. A session that started MID-DISPATCH must not
		// receive evidence from a decision that predates its window (round
		// 24), so this is a strict no-op — never a fresh engine load.
		return
	}
	eng := ctx.eng // the engine the decision ran under — never reloaded
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
	// Each half fenced on BOTH sides of its identity read (round 23; see
	// learnFencedStamp). Steady state returns the memoized strings —
	// 0-alloc; the witnesses allocate only at config-change rate.
	if id, ok := learnFencedStamp(ctx.key.policy, policyContentKeyNow, policyContentIdentityCached); ok {
		policyID = id
	} else {
		// A mutation provably overlapped the evaluation→stamp bracket.
		// The decision-time identity is unrecoverable, so stamp a witness
		// unique to the captured key.
		policyID = "policy-flip@" + strconv.FormatInt(ctx.key.policy.gen, 16) + ":" +
			strconv.FormatUint(ctx.key.policy.catgroupRev, 16) + ":" + strconv.FormatUint(ctx.key.policy.defaultRev, 16)
	}
	if ep, ok := learnFencedStamp(ctx.key.tax, learnTaxKeyNow, learnCategoryEpoch); ok {
		catEpoch = ep
	} else {
		// The content-derived epoch is ABA-blind to a round trip, so
		// stamp a witness unique to the captured taxonomy state.
		catEpoch = "category-flip@" + strconv.FormatUint(ctx.key.tax.catRev, 16)
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
		WindowGen:  ctx.gen,  // the captured window — a rotation resolves as a counted drop
	})
}
