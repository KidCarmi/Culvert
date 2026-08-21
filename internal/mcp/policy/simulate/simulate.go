// Package simulate is the PR-6 policy simulator. It evaluates decision inputs
// against immutable policy snapshots using the EXACT SAME compiled evaluator the
// runtime uses (policy.Engine.Evaluate) — there is no second "simulation
// evaluator" — and computes deterministic single-case results, bounded-corpus
// results, old-vs-new revision comparisons (blast radius) and side-by-side shadow
// comparisons. It is PURE: it publishes nothing, activates no policy, modifies no
// runtime, calls no provider, executes no tool, performs no I/O, and retains no raw
// arguments. It never mutates either snapshot.
package simulate

import (
	"sort"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// Simulator runs the shared evaluator over inputs/snapshots. It holds no mutable
// state beyond the bounds.
type Simulator struct {
	engine *policy.Engine
	lim    policy.Limits
}

// New returns a simulator bounded by lim, backed by the shared policy engine.
func New(lim policy.Limits) *Simulator {
	return &Simulator{engine: policy.NewEngine(lim), lim: lim}
}

// Case is one named decision input in a simulation corpus.
type Case struct {
	ID    string
	Input policy.DecisionInput
}

// Result is a single-case simulation result: the runtime-safe decision plus the
// internal explain trace.
type Result struct {
	Decision policy.Decision
	Trace    policy.ExplainTrace
}

// Single evaluates one input against one snapshot (decision + explain trace).
func (s *Simulator) Single(snap *policy.Snapshot, in *policy.DecisionInput) Result {
	d, tr, _ := s.engine.Evaluate(snap, in)
	return Result{Decision: d, Trace: tr}
}

// CaseResult is a corpus case's decision (bounded, no trace to keep it compact).
type CaseResult struct {
	ID       string
	Decision policy.Decision
}

func simErr(detail string) error {
	return mcperr.New(mcperr.ReasonPolicyLimitExceeded, "policy.simulate", detail)
}

// Corpus evaluates a bounded set of cases against one snapshot. It rejects an
// over-limit corpus (deterministic, no silent truncation).
func (s *Simulator) Corpus(snap *policy.Snapshot, cases []Case) ([]CaseResult, error) {
	if len(cases) > s.lim.MaxSimCases() {
		return nil, simErr("simulator corpus exceeds the case bound")
	}
	out := make([]CaseResult, len(cases))
	for i := range cases {
		in := cases[i].Input
		d, _, _ := s.engine.Evaluate(snap, &in)
		out[i] = CaseResult{ID: cases[i].ID, Decision: d}
	}
	return out, nil
}

// ChangedCase is a bounded evidence sample of a decision that changed between
// snapshots. It carries only safe metadata.
type ChangedCase struct {
	ID            string
	OldAction     policy.Action
	NewAction     policy.Action
	OldReason     policy.ReasonCode
	NewReason     policy.ReasonCode
	OldRule       policy.RuleID
	NewRule       policy.RuleID
	NewAllowClass bool // the candidate newly permits — a security-sensitive blast-radius class
}

// Comparison is the deterministic blast-radius summary of evaluating one corpus
// against an old and a proposed snapshot.
type Comparison struct {
	Total               int
	Unchanged           int
	ActionChanges       int
	ReasonChanges       int
	RuleChanges         int
	ObligationChanges   int // same action/reason/rule but a different obligation payload
	NewAllow            int // NEW ALLOW-class decisions (security-sensitive)
	NewDeny             int
	NewQuarantine       int
	NewApprovalRequired int
	AffectedRules       []policy.RuleID // sorted, deduped
	Samples             []ChangedCase   // bounded by MaxCompareSamples
	ByTenant            map[string]int  // changed-case counts per tenant
	ByServer            map[string]int  // changed-case counts per server
	ByTool              map[string]int  // changed-case counts per tool
}

// Compare evaluates the same corpus against oldSnap and newSnap and returns a
// deterministic blast-radius summary. New ALLOW-class decisions are highlighted
// (NewAllow) as the security-sensitive class. It mutates neither snapshot and does
// no I/O.
func (s *Simulator) Compare(oldSnap, newSnap *policy.Snapshot, cases []Case) (Comparison, error) {
	if len(cases) > s.lim.MaxSimCases() {
		return Comparison{}, simErr("simulator corpus exceeds the case bound")
	}
	cmp := Comparison{
		Total:    len(cases),
		ByTenant: map[string]int{}, ByServer: map[string]int{}, ByTool: map[string]int{},
	}
	affected := map[policy.RuleID]struct{}{}
	for i := range cases {
		in := cases[i].Input
		oldD, _, _ := s.engine.Evaluate(oldSnap, &in)
		newD, _, _ := s.engine.Evaluate(newSnap, &in)
		s.tally(&cmp, cases[i], oldD, newD, affected)
	}
	cmp.AffectedRules = sortedRuleIDs(affected)
	return cmp, nil
}

// tally folds one case's old/new decisions into the comparison. A decision is
// "changed" if its action, reason, matched rule OR its OBLIGATION payload differs —
// so a candidate that only weakens an obligation (e.g. a longer session TTL or
// max-calls, same action/reason/rule) is not silently reported as zero-impact.
func (s *Simulator) tally(cmp *Comparison, c Case, oldD, newD policy.Decision, affected map[policy.RuleID]struct{}) {
	oblChanged := !oldD.Obligations.Equal(newD.Obligations)
	changed := oldD.Action != newD.Action || oldD.Reason != newD.Reason ||
		oldD.MatchedRule != newD.MatchedRule || oblChanged
	if !changed {
		cmp.Unchanged++
		return
	}
	if oldD.Action != newD.Action {
		cmp.ActionChanges++
	}
	if oldD.Reason != newD.Reason {
		cmp.ReasonChanges++
	}
	if oldD.MatchedRule != newD.MatchedRule {
		cmp.RuleChanges++
	}
	if oblChanged {
		cmp.ObligationChanges++
	}
	newAllow := s.tallyNewClasses(cmp, oldD, newD)
	if newD.MatchedRule != "" {
		affected[newD.MatchedRule] = struct{}{}
	}
	if oldD.MatchedRule != "" {
		affected[oldD.MatchedRule] = struct{}{}
	}
	s.aggregate(cmp, c.Input)
	if len(cmp.Samples) < s.lim.MaxCompareSamples() {
		cmp.Samples = append(cmp.Samples, ChangedCase{
			ID: c.ID, OldAction: oldD.Action, NewAction: newD.Action,
			OldReason: oldD.Reason, NewReason: newD.Reason,
			OldRule: oldD.MatchedRule, NewRule: newD.MatchedRule, NewAllowClass: newAllow,
		})
	}
}

// tallyNewClasses bumps the new-decision-class counters (candidate action vs old)
// and reports whether the candidate is a NEW ALLOW-class decision.
func (s *Simulator) tallyNewClasses(cmp *Comparison, oldD, newD policy.Decision) bool {
	newAllow := newD.IsAllowClass() && !oldD.IsAllowClass()
	if newAllow {
		cmp.NewAllow++
	}
	if newD.Action == policy.ActionDeny && oldD.Action != policy.ActionDeny {
		cmp.NewDeny++
	}
	if newD.Action == policy.ActionQuarantine && oldD.Action != policy.ActionQuarantine {
		cmp.NewQuarantine++
	}
	if newD.Action == policy.ActionRequireApproval && oldD.Action != policy.ActionRequireApproval {
		cmp.NewApprovalRequired++
	}
	return newAllow
}

// aggregate bumps the per-tenant/server/tool changed-case counters (safe ids only).
func (s *Simulator) aggregate(cmp *Comparison, in policy.DecisionInput) {
	if in.Principal.Tenant != "" {
		cmp.ByTenant[in.Principal.Tenant]++
	}
	if in.Server != nil && in.Server.ServerID != "" {
		cmp.ByServer[in.Server.ServerID]++
	}
	if in.Tool != nil && in.Tool.Name != "" {
		cmp.ByTool[in.Tool.Name]++
	}
}

// Relation is the permissiveness relation of a candidate decision to the active one.
type Relation uint8

const (
	// RelEqual — same action.
	RelEqual Relation = iota
	// RelBroader — the candidate is more permissive than the active decision.
	RelBroader
	// RelNarrower — the candidate is more restrictive than the active decision.
	RelNarrower
	// RelIncomparable — same permissiveness rank but a different action/reason.
	RelIncomparable
)

// String returns the relation label.
func (r Relation) String() string {
	switch r {
	case RelBroader:
		return "broader"
	case RelNarrower:
		return "narrower"
	case RelIncomparable:
		return "incomparable"
	default:
		return "equal"
	}
}

// ShadowResult is a side-by-side evaluation of the active and candidate snapshots
// for one input. It never changes the active decision.
type ShadowResult struct {
	Active    policy.Decision
	Candidate policy.Decision
	Relation  Relation
	Changed   bool
}

// Shadow evaluates one input against BOTH the active and candidate snapshots and
// returns both decisions plus their permissiveness relation. It is a pure function
// and mutates neither snapshot — a foundation for later shadow/canary work, not a
// rollout mechanism.
func (s *Simulator) Shadow(active, candidate *policy.Snapshot, in *policy.DecisionInput) ShadowResult {
	a, _, _ := s.engine.Evaluate(active, in)
	c, _, _ := s.engine.Evaluate(candidate, in)
	return ShadowResult{
		Active: a, Candidate: c, Relation: relate(a, c),
		Changed: a.Action != c.Action || a.Reason != c.Reason || a.MatchedRule != c.MatchedRule,
	}
}

// relate computes the permissiveness relation of candidate to active.
func relate(active, candidate policy.Decision) Relation {
	if active.Action == candidate.Action {
		return RelEqual
	}
	ra, rc := permRank(active.Action), permRank(candidate.Action)
	switch {
	case rc > ra:
		return RelBroader
	case rc < ra:
		return RelNarrower
	default:
		return RelIncomparable
	}
}

// permRank ranks actions by permissiveness: denied/quarantined (0) < pending (1) <
// allow-class (2).
func permRank(a policy.Action) int {
	switch {
	case a.IsAllowClass():
		return 2
	case a == policy.ActionRequireApproval || a == policy.ActionRequireConfirmation:
		return 1
	default:
		return 0
	}
}

func sortedRuleIDs(m map[policy.RuleID]struct{}) []policy.RuleID {
	out := make([]policy.RuleID, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
