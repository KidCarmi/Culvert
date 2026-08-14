package main

// policy_learning_accept.go — THE M5B trust boundary (ADR-0025). This file is
// the ONLY place in the repository where a learning Recommendation is
// translated into a real PolicyRule and the only policy-learning file that may
// touch the draft pipeline (pinned by the wall tests). Everything here is
// DRAFT-ONLY: acceptance can never write into the running rulebase, even
// disabled — RequireCommit must be armed and the write store is PROVEN to be
// the draft candidate before any mutation.
//
// Cross-store protocol (two durable domains — the learning store and the
// policy draft — with no shared transaction):
//
//	generated ──(1) BeginAccept persists intent {accepting, TargetRuleID}──►
//	accepting ──(2) draft candidate gains the ONE translated rule (ID =
//	              TargetRuleID)──► (3) FinalizeAccept latches accepted.
//
// The intent is persisted BEFORE the policy side effect, so a crash at any
// instruction boundary reconciles deterministically on the next ADMIN retry
// (no background mutation; reads stay side-effect-free):
//
//	accepting + exact target rule PRESENT (draft or running — a committed
//	  draft counts) with the expected translated content ⇒ finalize, idempotent.
//	accepting + target present with DIFFERENT content ⇒ integrity conflict:
//	  refuse 409 + audit; NEVER overwrite.
//	accepting + target ABSENT + fences fresh ⇒ redo the draft mutation.
//	accepting + target ABSENT + fences stale ⇒ AbortAccept (back to
//	  generated) + 409 with the stale reasons — evidence is never re-pinned.
//
// The strongest invariant (M5B §14): after any crash/retry sequence a
// recommendation has either zero matching draft rules and is not Accepted, or
// exactly one matching DISABLED draft rule whose ID it records. Duplicates are
// impossible because every attempt converges on the single persisted
// TargetRuleID and an existing target is never re-added.

import (
	"errors"
	"fmt"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

var (
	errAcceptRequiresDraftMode = errors.New("accept requires Draft Mode (RequireCommit): acceptance creates a disabled rule in the Policy Draft only — arm Require Commit in Policy settings first")
	errAcceptVersionConflict   = errors.New("policy/draft changed since the fence was read — reload and retry with the current version")
	errAcceptIntegrityConflict = errors.New("a rule with this recommendation's target ID exists with DIFFERENT content — refusing to overwrite; resolve the draft rule manually")
)

// plAcceptOutcome carries the result of one accept attempt for the API layer.
type plAcceptOutcome struct {
	Recommendation policylearn.Recommendation
	RuleID         string
	AlreadyDone    bool // idempotent re-accept of an accepted recommendation
}

// plTranslateRecommendation is the ONLY DTO → PolicyRule conversion in the
// repository (wall-pinned). Born-safe semantics are FIXED here — no caller
// field reaches the rule: Action=Allow, SSLAction=Inspect, Enabled=false, and
// the exact observed group/category from the recommendation evidence. Name is
// deterministic (recommendation-ID-suffixed for uniqueness and retry
// idempotency); priority is deliberately zero (the store assigns the next
// free slot — identity lives in the preallocated rule ID, not the slot).
func plTranslateRecommendation(rec *policylearn.Recommendation) PolicyRule {
	disabled := false
	return PolicyRule{
		ID:           rec.TargetRuleID,
		Name:         fmt.Sprintf("Learned: %s -> %s [%s]", rec.Group, rec.Category, rec.ID),
		SourceGroup:  rec.Group,
		DestCategory: URLCategory(rec.Category),
		Action:       ActionAllow,
		SSLAction:    SSLInspect,
		Enabled:      &disabled,
	}
}

// plRuleMatchesTranslation reports whether an existing rule is EXACTLY the
// expected translated content — the five born-safe fields. Deliberately
// excluded: priority (store-assigned), name and metadata stamps (rename or
// annotation by an admin must not block finalize; flipping Action/SSLAction/
// Enabled/scope MUST).
func plRuleMatchesTranslation(rule *PolicyRule, rec *policylearn.Recommendation) bool {
	return rule.Action == ActionAllow &&
		rule.SSLAction == SSLInspect &&
		!ruleIsEnabled(rule) &&
		rule.SourceGroup == rec.Group &&
		string(rule.DestCategory) == rec.Category
}

// plFindTargetRule looks for the recommendation's target rule ID in the draft
// candidate AND the running store. Running matters for the committed-while-
// accepting crash window: the draft (with our rule) was committed before the
// finalize latch persisted — the acceptance still happened, through the
// canonical commit path.
func plFindTargetRule(targetID string) *PolicyRule {
	if policyDraftEngaged() {
		cand := policyDraft.candidateList()
		for i := range cand {
			if cand[i].ID == targetID {
				r := cand[i]
				return &r
			}
		}
	}
	return policyStore.findByIDCopy(targetID)
}

// plAcceptRecommendation executes (or resumes) one acceptance under
// policyLearnAdminMu (held by the caller / API handler). ifVersion is the
// REQUIRED optimistic fence the client echoed from the effective policy view
// (the same generation family every policy write handler uses).
func plAcceptRecommendation(eng *policylearn.Engine, recID string, ifVersion int64, actor string) (plAcceptOutcome, error) { //nolint:cyclop // the reconcile decision table is intentionally explicit
	rec, ok := eng.RecommendationByID(recID)
	if !ok {
		return plAcceptOutcome{}, policylearn.ErrRecommendationNotFound
	}
	switch rec.State {
	case policylearn.RecStateAccepted:
		// Explicit deterministic behavior: idempotent success with the
		// recorded rule (concurrent double-accept converges here).
		return plAcceptOutcome{Recommendation: rec, RuleID: rec.TargetRuleID, AlreadyDone: true}, nil
	case policylearn.RecStateGenerated, policylearn.RecStateAccepting:
		// proceed (fresh accept, or resume of an unresolved intent)
	default:
		return plAcceptOutcome{}, stateRefusal(rec.State)
	}

	// Resume path first: if the intent's rule already exists, the ONLY correct
	// moves are finalize (content matches) or refuse (content differs) — the
	// fences fence the MUTATION, and the mutation already happened.
	if rec.State == policylearn.RecStateAccepting {
		if existing := plFindTargetRule(rec.TargetRuleID); existing != nil {
			if !plRuleMatchesTranslation(existing, &rec) {
				return plAcceptOutcome{}, errAcceptIntegrityConflict
			}
			// M5B.1 durability gate: the latch may only follow a target that is
			// durably recoverable — already committed to running (the canonical
			// commit path), or present in the persisted draft document. A rule
			// that reached candidate MEMORY under a failed best-effort persist
			// is re-persisted durably first; if that write fails too, the
			// intent stays pending (retryable), never Accepted.
			if policyStore.findByIDCopy(rec.TargetRuleID) == nil {
				if err := policyDraft.ensureDurableTarget(rec.TargetRuleID); err != nil {
					return plAcceptOutcome{}, err
				}
			}
			fin, err := eng.FinalizeAccept(rec.ID, actor)
			if err != nil {
				return plAcceptOutcome{}, err
			}
			return plAcceptOutcome{Recommendation: fin, RuleID: fin.TargetRuleID}, nil
		}
	}

	// Revalidate every pinned identity at the last responsible moment (§4).
	// Any stale reason: 409 — and a pending intent whose rule was never
	// created is safely reverted to generated (evidence untouched).
	if stale := policylearn.StaleReasons(&rec, policyLearnStaleInputs(eng)); len(stale) > 0 {
		if rec.State == policylearn.RecStateAccepting {
			if _, err := eng.AbortAccept(rec.ID); err != nil {
				return plAcceptOutcome{}, err
			}
		}
		return plAcceptOutcome{}, fmt.Errorf("recommendation is stale (%v): %w", stale, errStaleRecommendation)
	}

	// Draft-only enforcement (§1): RequireCommit must be armed and the write
	// store PROVEN to be the candidate — identity check, not inference.
	if !requireCommitEnabled() {
		return plAcceptOutcome{}, errAcceptRequiresDraftMode
	}
	// Optimistic fence (§6): the same effective-generation family the draft
	// pipeline uses; a concurrent policy/draft edit moved it ⇒ 409, no retry
	// against the new candidate.
	if cur, _ := effectivePolicyVersion(); cur != ifVersion {
		return plAcceptOutcome{}, fmt.Errorf("expected version %d, current %d: %w", ifVersion, cur, errAcceptVersionConflict)
	}

	// Persist the durable intent BEFORE the policy side effect (§3). On resume
	// the persisted TargetRuleID wins and the fresh ULID is discarded.
	rec, err := eng.BeginAccept(rec.ID, newRuleID())
	if err != nil {
		return plAcceptOutcome{}, err
	}

	rule := plTranslateRecommendation(&rec)
	if err := validatePolicyRule(rule, effectivePolicyList(), -1); err != nil {
		// Structural refusal (e.g. name collision with an admin-created rule).
		// The intent stays pending; a retry after the operator resolves the
		// collision converges on the same target.
		return plAcceptOutcome{}, fmt.Errorf("translated rule failed validation: %w", err)
	}
	stampRuleMetadataForWrite(&rule, nil, actor)

	// M5B.1: the coordinator's durable check-and-mutate primitive — fence,
	// append, and DURABLE persist under one lock. Structurally candidate-only
	// (the primitive never touches the running store), and success means the
	// rule is recoverable from policy_draft.json after a restart; a persist
	// failure rolled the append back and is returned, so Learning is never
	// told a durable rule exists when it does not. The intent stays pending
	// (retryable); FinalizeAccept is unreachable on this path.
	added, err := policyDraft.stageDurableAppend(actor, ifVersion, rule)
	if err != nil {
		if errors.Is(err, errDraftVersionConflict) {
			return plAcceptOutcome{}, fmt.Errorf("%v: %w", err, errAcceptVersionConflict)
		}
		return plAcceptOutcome{}, err
	}
	if added.ID != rec.TargetRuleID {
		// Add() re-mints on invalid/duplicate IDs; both are precluded (fresh
		// ULID + presence check), so this is wiring drift — refuse loudly
		// rather than finalize a linkage that does not hold.
		return plAcceptOutcome{}, fmt.Errorf("draft store assigned rule ID %s instead of the preallocated %s: %w",
			added.ID, rec.TargetRuleID, errAcceptIntegrityConflict)
	}

	fin, err := eng.FinalizeAccept(rec.ID, actor)
	if err != nil {
		// The rule exists and the intent is durable: a retry finalizes
		// idempotently. Surface the failure; nothing is lost.
		return plAcceptOutcome{}, fmt.Errorf("draft rule %s created but the acceptance latch failed (retry to finalize): %w", rec.TargetRuleID, err)
	}
	return plAcceptOutcome{Recommendation: fin, RuleID: fin.TargetRuleID}, nil
}

// errStaleRecommendation is the API-visible stale refusal.
var errStaleRecommendation = errors.New("stale recommendation — regenerate from a new learning session")

// stateRefusal maps a recommendation state to its engine sentinel (for states
// the accept path refuses outright).
func stateRefusal(state string) error {
	switch state {
	case policylearn.RecStateSuperseded:
		return policylearn.ErrRecommendationSuperseded
	case policylearn.RecStateRejected:
		return policylearn.ErrRecommendationRejected
	default:
		return policylearn.ErrRecommendationNotFound
	}
}
