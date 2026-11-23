package main

import (
	"cmp"
	"fmt"
	"slices"
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
// the differential proof (the previous sort survives only as its test oracle;
// there is no upgrade-time comparison in production).

// policyRulePriorityCmp orders rules by priority alone. Rules that share a
// priority compare equal, so a stable sort keeps them in input order.
func policyRulePriorityCmp(a, b *PolicyRule) int { return cmp.Compare(a.Priority, b.Priority) }

// orderPolicyRulesForPublication sorts next by priority in place, keeping
// rules that share a priority in their input (stored) order. Runs under the
// PolicyStore writer lock (sortLocked).
//
// Cost: an already-sorted input — every steady-state publication — is one
// O(n) scan and no sort at all. slices.SortStableFunc is generic and does not
// allocate, unlike sort.Slice, whose reflect-based swapper allocated on every
// publication.
func orderPolicyRulesForPublication(next []*PolicyRule) {
	if slices.IsSortedFunc(next, policyRulePriorityCmp) {
		return
	}
	slices.SortStableFunc(next, policyRulePriorityCmp)
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
