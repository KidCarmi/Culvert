package main

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// policy_tie_order.go — precedence of rules that share a priority.
//
// Contract (POL-001, amended): rules are evaluated in ascending priority, and
// rules with EQUAL priority are evaluated in STORED order — the order of the
// policy file, the config-version snapshot, the backup or the CP→DP snapshot
// that installed them. Contract POL-006: the API, import and draft-commit
// writers cannot create a new duplicate priority. Load, config-version rollback
// and CP→DP sync are faithful restores: they keep an existing tie and only
// report it (log warning, culvert_policy_priority_ties, diagnostics row).
// Nothing is ever renumbered automatically.
//
// Why stable, and why it is not a behaviour change for a steady-state rulebase:
// the previous publication used sort.Slice (pdqsort), which is not stable. With
// the go.mod toolchain it is nevertheless the IDENTITY on every already-sorted
// input (zero pivot swaps → partialInsertionSort returns without swapping) and
// a strict-less insertion sort — therefore stable — for n <= 12. Every file
// Culvert has written is sorted, and every writer that keeps priorities
// (UpdateByID, the cascades, ReplaceAll of List()-derived input) feeds sorted
// input, so the stable sort below yields exactly the same order there. The two
// differ only for an UNSORTED input with ties and n >= 13 (a gap Add, a
// priority edit or a move on a tied rulebase, or the first load of a
// hand-edited unsorted file), where the old order was a pdqsort artefact
// nobody chose. TestPolicyTieOrder_StableSortMatchesLegacyWhereItMustAgree is
// the differential proof.

// policyRulePriorityCmp orders rules by priority alone. Rules that share a
// priority compare equal, so a stable sort keeps them in input order.
func policyRulePriorityCmp(a, b *PolicyRule) int { return cmp.Compare(a.Priority, b.Priority) }

// pdqsortInsertionMax is the length up to which sort.Slice runs a plain
// strict-less insertion sort (sort/zsortfunc.go, pdqsort_func: length <= 12),
// so for these lengths the legacy order was already stable.
const pdqsortInsertionMax = 12

// orderPolicyRulesForPublication sorts next by priority in place, keeping
// rules that share a priority in their input (stored) order. input is the
// sequence next was copied from; it is only read, for the one-release legacy
// comparison. Runs under the PolicyStore writer lock (sortLocked).
//
// Cost: an already-sorted input — every steady-state publication — is one
// O(n) scan and no sort at all. slices.SortStableFunc is generic and does not
// allocate, unlike sort.Slice, whose reflect-based swapper allocated on every
// publication.
func orderPolicyRulesForPublication(next, input []*PolicyRule) {
	if sortPolicyRulesStoredOrder(next) {
		warnLegacyTieOrderDivergence(input, next)
	}
}

// sortPolicyRulesStoredOrder is the ordering itself, with no reporting. It
// returns whether the input was out of order (and was therefore sorted).
func sortPolicyRulesStoredOrder(rules []*PolicyRule) (sorted bool) {
	if slices.IsSortedFunc(rules, policyRulePriorityCmp) {
		return false
	}
	slices.SortStableFunc(rules, policyRulePriorityCmp)
	return true
}

// legacyPolicySortOrder returns input ordered exactly as the previous release
// published it: sort.Slice with a priority-only comparator. Kept for the
// one-release upgrade warning below and as the differential-test oracle.
//
// LEGACY-TIE-ORDER: remove the warning (and this helper's production caller)
// in the release after the one that ships stable tie order. The gauge and the
// diagnostics row stay.
func legacyPolicySortOrder(input []*PolicyRule) []*PolicyRule {
	out := slices.Clone(input)
	sort.Slice(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// policyTieOrderDivergence describes the first place where stored-order
// precedence and the previous release's order disagree.
type policyTieOrderDivergence struct {
	Priority int    // the shared priority
	Rules    int    // rules holding it
	Now      string // rule that now evaluates first at that position
	Was      string // rule the previous release evaluated there
}

// legacyTieOrderDivergence compares stable (input sorted with stored-order
// precedence) with the previous release's order of the same input. ok is false
// when they agree: always for n <= 12, and whenever no priority is shared.
func legacyTieOrderDivergence(input, stable []*PolicyRule) (policyTieOrderDivergence, bool) {
	if len(stable) <= pdqsortInsertionMax || !sortedRulesHaveTie(stable) {
		return policyTieOrderDivergence{}, false
	}
	legacy := legacyPolicySortOrder(input)
	for i := range stable {
		if stable[i] == legacy[i] {
			continue
		}
		p := stable[i].Priority
		n := 0
		for _, r := range stable {
			if r.Priority == p {
				n++
			}
		}
		return policyTieOrderDivergence{Priority: p, Rules: n, Now: stable[i].Name, Was: legacy[i].Name}, true
	}
	return policyTieOrderDivergence{}, false
}

// warnLegacyTieOrderDivergence logs when the evaluation order of tied rules
// differs from what the previous release would have used for the same input.
// It never changes the order and never renumbers.
func warnLegacyTieOrderDivergence(input, stable []*PolicyRule) {
	d, ok := legacyTieOrderDivergence(input, stable)
	if !ok {
		return
	}
	logWarnf("Policy: %d rule(s) share priority %d; evaluation order now follows stored order (%q before %q), which differs from the previous release",
		d.Rules, d.Priority, sanitizeLog(d.Now), sanitizeLog(d.Was))
}

// sortedRulesHaveTie reports whether two adjacent rules of a priority-sorted
// slice share a priority.
func sortedRulesHaveTie(sorted []*PolicyRule) bool {
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Priority == sorted[i-1].Priority {
			return true
		}
	}
	return false
}

// priorityTiedRuleCount returns the number of rules that share their priority
// with at least one other rule (culvert_policy_priority_ties). It walks the
// published slice, which is priority-sorted whenever ps.mu is not held for
// writing (sortLocked publishes it sorted; Delete removes from it in place).
func (ps *PolicyStore) priorityTiedRuleCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	tied := 0
	for i := 0; i < len(ps.rules); {
		j := i + 1
		for j < len(ps.rules) && ps.rules[j].Priority == ps.rules[i].Priority {
			j++
		}
		if j-i > 1 {
			tied += j - i
		}
		i = j
	}
	return tied
}

// policyPriorityTie is one priority held by more than one rule, with the rule
// names in stored (evaluation) order.
type policyPriorityTie struct {
	Priority int
	Names    []string
}

// policyPriorityTies returns every priority held by more than one rule, in
// ascending priority, each with its rules' names in input order. The input
// need not be sorted (an import payload is not).
func policyPriorityTies(rules []PolicyRule) []policyPriorityTie {
	byPriority := make(map[int][]string, len(rules))
	for i := range rules {
		name := rules[i].Name
		if name == "" {
			name = rules[i].ID
		}
		byPriority[rules[i].Priority] = append(byPriority[rules[i].Priority], name)
	}
	var ties []policyPriorityTie
	for p, names := range byPriority {
		if len(names) > 1 {
			ties = append(ties, policyPriorityTie{Priority: p, Names: names})
		}
	}
	slices.SortFunc(ties, func(a, b policyPriorityTie) int { return cmp.Compare(a.Priority, b.Priority) })
	return ties
}

// tiedRuleCount is the number of rules across ties.
func tiedRuleCount(ties []policyPriorityTie) int {
	n := 0
	for i := range ties {
		n += len(ties[i].Names)
	}
	return n
}

// describePolicyPriorityTies renders up to maxGroups ties as
// `priority 5: "a", "b"; priority 9: "c", "d"`, naming every colliding rule of
// each rendered group and summarising the rest.
func describePolicyPriorityTies(ties []policyPriorityTie, maxGroups int) string {
	var b strings.Builder
	for i := range ties {
		if i == maxGroups {
			fmt.Fprintf(&b, "; and %d more shared priorit(ies)", len(ties)-maxGroups)
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		quoted := make([]string, len(ties[i].Names))
		for j, n := range ties[i].Names {
			quoted[j] = fmt.Sprintf("%q", sanitizeLog(n))
		}
		fmt.Fprintf(&b, "priority %d: %s", ties[i].Priority, strings.Join(quoted, ", "))
	}
	return b.String()
}

// newPriorityTieError refuses a candidate rulebase that holds a priority
// shared by rules which did not already share that exact priority in running
// (POL-006, draft commit). A tie inherited unchanged from running — a legacy
// rulebase loaded before ties were refused — does not block a commit: it was
// admitted by a faithful restore and is reported by the diagnostics row, and
// refusing it here would strand every draft on such a node, since no move can
// separate tied rules.
func newPriorityTieError(cand, running []PolicyRule) error {
	runningPriority := make(map[string]int, len(running))
	for i := range running {
		if running[i].ID != "" {
			runningPriority[running[i].ID] = running[i].Priority
		}
	}
	inherited := func(r *PolicyRule) bool {
		p, ok := runningPriority[r.ID]
		return r.ID != "" && ok && p == r.Priority
	}
	first := make(map[int]int, len(cand)) // priority → index of the first rule holding it
	for i := range cand {
		j, seen := first[cand[i].Priority]
		if !seen {
			first[cand[i].Priority] = i
			continue
		}
		if inherited(&cand[i]) && inherited(&cand[j]) {
			continue
		}
		return fmt.Errorf("candidate rules %q and %q share priority %d; give each rule a unique priority before committing",
			sanitizeLog(cand[j].Name), sanitizeLog(cand[i].Name), cand[i].Priority)
	}
	return nil
}
